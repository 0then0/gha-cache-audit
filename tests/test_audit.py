import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from gha_cache_audit import workflow
from gha_cache_audit.analysis import analyze, matches
from gha_cache_audit.cli import main
from gha_cache_audit.expressions import dependencies
from gha_cache_audit.workflow import matrix_rows, parse

FIXTURES = Path(__file__).parent / "fixtures"


def main_output(*args):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = main(list(args))
    return status, output.getvalue()


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workflows = self.root / ".github/workflows"
        self.workflows.mkdir(parents=True)
        (self.root / "package-lock.json").write_text("{}")

    def write(self, text):
        path = self.workflows / "test.yml"
        path.write_text(text)
        return path

    def fixture(self, name):
        return (FIXTURES / f"{name}.yml").read_text()

    def scan(self, text, confidence="high"):
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertEqual(diagnostics, [])
        return [
            f
            for c in caches
            for f in analyze(c, self.root)
            if confidence == "medium" or f.confidence == "high"
        ]

    def test_safe_fixture(self):
        self.assertFalse(self.scan(self.fixture("safe")))

    def test_matrix_positive_and_negative(self):
        text = self.fixture("matrix")
        findings = self.scan(text)
        self.assertEqual([f.rule_id for f in findings], ["GHA-CACHE-001"])
        self.assertEqual(findings[0].missing, ["matrix.node"])
        self.assertEqual(findings[0].line, 15)
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ matrix.node }}-"))
        )

    def test_os_positive_and_negative(self):
        text = self.fixture("os")
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-002"])
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ runner.os }}-"))
        )
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ matrix.os }}-"))
        )
        self.assertFalse(
            self.scan(
                text.replace(
                    "[ubuntu-latest, macos-latest]", "[ubuntu-22.04, ubuntu-24.04]"
                )
            )
        )

    def test_os_requires_a_cross_platform_key_collision(self):
        text = (
            self.fixture("os")
            .replace(
                "        os: [ubuntu-latest, macos-latest]",
                "        include:\n"
                "          - {os: ubuntu-latest, shard: a}\n"
                "          - {os: ubuntu-24.04, shard: a}\n"
                "          - {os: macos-latest, shard: b}",
            )
            .replace("key: deps-", "key: deps-${{ matrix.shard }}-")
        )
        self.assertFalse(self.scan(text))
        self.assertEqual(
            [f.rule_id for f in self.scan(text.replace("shard: b", "shard: a"))],
            ["GHA-CACHE-002"],
        )

    def test_fixed_os_only_medium_and_revision_key_is_safe(self):
        text = self.fixture("lockfile").replace("yarn.lock", "package-lock.json")
        self.assertFalse(self.scan(text))
        self.assertEqual(
            [f.rule_id for f in self.scan(text, "medium")], ["GHA-CACHE-002"]
        )
        self.assertFalse(
            self.scan(
                text.replace("key: deps-", "key: deps-${{ github.sha }}-"), "medium"
            )
        )
        self.assertFalse(
            self.scan(
                text.replace(
                    "key: deps-",
                    "key: deps-${{ hashFiles('.github/workflows/test.yml') }}-",
                ),
                "medium",
            )
        )

    def test_windows_archive_confidence(self):
        text = self.fixture("os").replace("macos-latest", "windows-latest")
        self.assertEqual(self.scan(text, "medium")[0].confidence, "medium")
        self.assertEqual(
            self.scan(
                text.replace(
                    "path: node_modules",
                    "enableCrossOsArchive: true\n          path: node_modules",
                )
            )[0].confidence,
            "high",
        )

    def test_lockfile_positive_and_negative(self):
        text = self.fixture("lockfile")
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-003"])
        self.assertFalse(self.scan(text.replace("yarn.lock", "package-lock.json")))
        self.assertFalse(self.scan(text.replace("yarn.lock", "**/package-lock.json")))
        self.assertTrue(
            self.scan(
                text.replace(
                    "'yarn.lock'", "'**/package-lock.json', '!package-lock.json'"
                )
            )
        )

    def test_hashfiles_globs_include_descendants_of_matched_directories(self):
        self.assertTrue(matches("foo/package-lock.json", "foo"))
        self.assertTrue(matches("foo/package-lock.json/child", "**/package-lock.json"))
        self.assertTrue(matches("foo/package-lock.json", "**/package-lock.json"))

        web = self.root / "web"
        web.mkdir()
        (web / "package-lock.json").write_text("{}")
        text = (
            self.fixture("lockfile")
            .replace("node_modules", "web/node_modules")
            .replace("hashFiles('yarn.lock')", "hashFiles('web')")
        )
        self.assertFalse(self.scan(text))

    def test_python_requirements_only_invalidates_cache_when_installed(self):
        (self.root / "pyproject.toml").write_text("[project]\nname='example'\n")
        (self.root / "requirements.txt").write_text("example==1.0\n")
        workflow_text = (
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/cache@v4\n        with:\n"
            "          path: .venv\n          key: deps-${{ hashFiles('pyproject.toml') }}\n"
            "      - run: pip install .\n"
        )
        self.assertFalse(self.scan(workflow_text))
        self.assertFalse(
            self.scan(
                workflow_text.replace(
                    "pip install .", "echo pip install -r requirements.txt"
                )
            )
        )
        self.assertFalse(
            self.scan(
                workflow_text.replace(
                    "pip install .", "# pip install -r requirements.txt"
                )
            )
        )
        self.assertFalse(
            self.scan(
                workflow_text.replace(
                    "pip install .", "pip install -r requirements.txt-dev"
                ).replace("pyproject.toml", "requirements.txt-dev")
            )
        )
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    workflow_text.replace(
                        "pip install .", r"pip install -r .\requirements.txt"
                    )
                )
            ],
            ["GHA-CACHE-003"],
        )
        disabled_install = workflow_text.replace(
            "      - run: pip install .",
            "      - if: false\n        run: pip install -r requirements.txt",
        )
        self.assertFalse(self.scan(disabled_install))
        self.assertFalse(
            self.scan(
                workflow_text.replace(
                    "pip install .", "pip install -r requirements.txt#dev"
                )
            )
        )
        self.assertFalse(
            self.scan(
                workflow_text.replace(
                    "pip install .", "pip install . && echo -r requirements.txt"
                )
            )
        )
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    workflow_text.replace(
                        "pip install .", "pip install -r requirements.txt"
                    )
                )
            ],
            ["GHA-CACHE-003"],
        )
        multiline = workflow_text.replace(
            "      - run: pip install .",
            "      - run: |\n          pip install \\\n            -r requirements.txt",
        )
        self.assertEqual([f.rule_id for f in self.scan(multiline)], ["GHA-CACHE-003"])
        for command in (
            "uv pip install -r requirements.txt",
            "python -m pip install --requirement=./requirements.txt",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    [
                        f.rule_id
                        for f in self.scan(
                            workflow_text.replace("pip install .", command)
                        )
                    ],
                    ["GHA-CACHE-003"],
                )
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    workflow_text.replace(
                        "pip install .", "pip install -r ./requirements.txt"
                    )
                )
            ],
            ["GHA-CACHE-003"],
        )
        (self.root / "web").mkdir()
        (self.root / "web/requirements.txt").write_text("web-only==1\n")
        nested_cache = workflow_text.replace("path: .venv", "path: web/.venv").replace(
            "pip install .", "pip install -r requirements.txt"
        )
        self.assertFalse(self.scan(nested_cache))
        nested_install = nested_cache.replace(
            "      - run: pip install -r requirements.txt",
            "      - run: pip install -r requirements.txt\n        working-directory: web",
        )
        self.assertEqual(
            [f.rule_id for f in self.scan(nested_install)], ["GHA-CACHE-003"]
        )

    def test_lockfile_ignored_by_npm(self):
        text = self.fixture("lockfile").replace(
            "    steps:", "    steps:\n      - run: npm install --package-lock=false"
        )
        self.assertFalse(self.scan(text))
        self.assertFalse(
            self.scan(text.replace("--package-lock=false", "--no-package-lock"))
        )
        self.assertEqual(
            [f.rule_id for f in self.scan(text.replace("--package-lock=false", ""))],
            ["GHA-CACHE-003"],
        )
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    text.replace(
                        "- run: npm install --package-lock=false",
                        "- run: |\n          npm install --package-lock=false\n          npm ci",
                    )
                )
            ],
            ["GHA-CACHE-003"],
        )
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    text.replace(
                        "- run: npm install --package-lock=false",
                        "- run: |\n          npm install --package-lock=false\n          echo ok && npm ci",
                    )
                )
            ],
            ["GHA-CACHE-003"],
        )
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    text.replace("- run: npm install", "- run: echo npm install")
                )
            ],
            ["GHA-CACHE-003"],
        )
        (self.root / ".npmrc").write_text("package-lock=false\n")
        self.assertFalse(self.scan(text.replace(" --package-lock=false", "")))
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    text.replace("--package-lock=false", "--package-lock=true")
                )
            ],
            ["GHA-CACHE-003"],
        )

    def test_npmrc_symlink_cannot_read_outside_repository(self):
        outside = self.root.parent / f"outside-npmrc-{self.root.name}"
        outside.write_text("package-lock=false\n")
        self.addCleanup(outside.unlink, missing_ok=True)
        try:
            (self.root / ".npmrc").symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks are unavailable: {exc}")
        text = self.fixture("lockfile").replace(
            "    steps:", "    steps:\n      - run: npm install"
        )
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-003"])

    def test_build_positive_and_negative(self):
        (self.root / "src").mkdir()
        (self.root / "src/index.ts").write_text("export const n = 1")
        text = self.fixture("build")
        findings = self.scan(text, "medium")
        self.assertEqual([f.rule_id for f in findings], ["GHA-CACHE-004"])
        self.assertEqual(findings[0].confidence, "medium")
        self.assertFalse(
            self.scan(
                text.replace("'package-lock.json'", "'package-lock.json', 'src/**'"),
                "medium",
            )
        )
        self.assertFalse(
            self.scan(text.replace("path: dist", "path: .next/cache"), "medium")
        )
        self.assertFalse(
            self.scan(text.replace("npm run build", "echo build"), "medium")
        )

    def test_build_configuration_invalidation(self):
        (self.root / "src").mkdir()
        (self.root / "src/index.ts").write_text("export const n = 1")
        (self.root / "vite.config.ts").write_text("export default {}")
        text = self.fixture("build").replace(
            "'package-lock.json'", "'package-lock.json', 'src/**'"
        )
        findings = self.scan(text, "medium")
        self.assertEqual([f.rule_id for f in findings], ["GHA-CACHE-004"])
        self.assertEqual(findings[0].missing, ["vite.config.ts"])
        self.assertFalse(
            self.scan(text.replace("'src/**'", "'src/**', 'vite.config.ts'"), "medium")
        )

    def test_build_partial_source_hash_is_incomplete(self):
        (self.root / "src").mkdir()
        (self.root / "src/a.ts").write_text("export const a = 1")
        (self.root / "src/b.ts").write_text("export const b = 1")
        text = self.fixture("build").replace("'package-lock.json'", "'src/a.ts'")
        findings = self.scan(text, "medium")
        self.assertEqual([f.rule_id for f in findings], ["GHA-CACHE-004"])
        self.assertEqual(findings[0].missing, ["src/**"])
        self.assertFalse(
            self.scan(text.replace("'src/a.ts'", "'src/a.ts', 'src/b.ts'"), "medium")
        )

    def test_build_source_globs_follow_hashfiles(self):
        (self.root / "src/nested").mkdir(parents=True)
        (self.root / "src/a.ts").write_text("a")
        (self.root / "src/nested/b.ts").write_text("b")
        text = self.fixture("build").replace("'package-lock.json'", "'src/*.ts'")
        self.assertEqual(
            [f.rule_id for f in self.scan(text, "medium")], ["GHA-CACHE-004"]
        )
        self.assertFalse(
            self.scan(text.replace("'src/*.ts'", "'src/**/*.ts'"), "medium")
        )
        (self.root / "src/nested/b.ts").unlink()
        self.assertFalse(
            self.scan(text.replace("'src/*.ts'", "'src/**/*.ts'"), "medium")
        )
        self.assertFalse(self.scan(text.replace("'src/*.ts'", "'src'"), "medium"))
        self.assertFalse(self.scan(text.replace("'src/*.ts'", "'src/'"), "medium"))

    def test_root_relative_hashfiles_pattern_is_supported(self):
        text = self.fixture("lockfile").replace("'yarn.lock'", "'/package-lock.json'")
        self.write(text)
        status, output = self.cli("--format", "json")
        report = json.loads(output)
        self.assertEqual(status, 0)
        self.assertFalse(report["findings"])
        self.assertFalse(report["diagnostics"])

    def test_absolute_hashfiles_pattern_outside_workspace_is_incomplete(self):
        text = self.fixture("lockfile").replace(
            "'yarn.lock'", "'C:/outside/package-lock.json'"
        )
        self.write(text)
        status, output = self.cli("--format", "json")
        report = json.loads(output)
        self.assertEqual(status, 2)
        self.assertFalse(report["findings"])
        self.assertTrue(
            any("hashFiles patterns" in d["message"] for d in report["diagnostics"])
        )

    def test_hashfiles_case_matching_must_cover_every_matrix_platform(self):
        (self.root / "package-lock.json").write_text("{}")
        text = (
            "jobs:\n  test:\n    runs-on: ${{ matrix.os }}\n"
            "    strategy:\n      matrix:\n        os: [ubuntu-latest, windows-latest]\n"
            "    steps:\n      - uses: actions/cache@v4\n        with:\n"
            "          path: node_modules\n"
            "          key: deps-${{ runner.os }}-${{ hashFiles('PACKAGE-LOCK.JSON') }}\n"
        )
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertFalse(diagnostics)
        self.assertEqual(
            [f.rule_id for cache in caches for f in analyze(cache, self.root)],
            ["GHA-CACHE-003"],
        )

    def test_hashfiles_case_matching_recognizes_windows_self_hosted_labels(self):
        text = (
            "jobs:\n  test:\n    runs-on: [self-hosted, windows]\n"
            "    steps:\n      - uses: actions/cache@v4\n        with:\n"
            "          path: node_modules\n"
            "          key: deps-${{ runner.os }}-${{ hashFiles('PACKAGE-LOCK.JSON') }}\n"
        )
        self.assertFalse(self.scan(text))

    def test_runs_on_group_name_does_not_determine_platform(self):
        text = (
            "jobs:\n  test:\n    runs-on:\n"
            "      group: windows\n      labels: ubuntu-latest\n"
            "    steps:\n      - uses: actions/cache@v4\n        with:\n"
            "          path: node_modules\n"
            "          key: deps-${{ runner.os }}-${{ hashFiles('PACKAGE-LOCK.JSON') }}\n"
        )
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-003"])

    def test_runs_on_object_matrix_labels_are_checked_per_platform(self):
        text = (
            "jobs:\n  test:\n    runs-on:\n"
            "      group: self-hosted\n      labels: ${{ matrix.os }}\n"
            "    strategy:\n      matrix:\n        os: [ubuntu-latest, windows-latest]\n"
            "    steps:\n      - uses: actions/cache@v4\n        with:\n"
            "          path: node_modules\n"
            "          key: deps-${{ runner.os }}-${{ hashFiles('PACKAGE-LOCK.JSON') }}\n"
        )
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-003"])

    def test_cache_path_cannot_read_outside_repository(self):
        outside_name = f"outside-{self.root.name}"
        outside = self.root.parent / outside_name
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        self.addCleanup((outside / "package-lock.json").unlink, missing_ok=True)
        (outside / "package-lock.json").write_text("{}")
        text = self.fixture("matrix").replace(
            "node_modules", f"../{outside_name}/node_modules"
        )
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertFalse(caches)
        self.assertTrue(
            any("outside the repository root" in d.message for d in diagnostics)
        )

    def test_cache_path_symlink_cannot_escape_repository(self):
        outside_name = f"outside-{self.root.name}"
        outside = self.root.parent / outside_name
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        link = self.root / "node_modules"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlinks are unavailable: {exc}")
        caches, diagnostics = parse(self.write(self.fixture("matrix")), self.root)
        self.assertFalse(caches)
        self.assertTrue(
            any("outside the repository root" in d.message for d in diagnostics)
        )

    def test_workflow_symlink_cannot_escape_repository(self):
        outside = self.root.parent / f"outside-workflow-{self.root.name}.yml"
        outside.write_text(self.fixture("matrix"))
        self.addCleanup(outside.unlink, missing_ok=True)
        link = self.workflows / "external.yml"
        try:
            link.symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks are unavailable: {exc}")
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 2)
        self.assertIn("outside the repository root", output)
        self.assertNotIn("GHA-CACHE-001", output)
        status, output = main_output(str(link), "--format", "json")
        self.assertEqual(status, 2)
        self.assertIn("outside the repository root", output)

    def test_workflow_directory_symlink_cannot_escape_repository(self):
        outside = self.root.parent / f"outside-workflows-{self.root.name}"
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        external = outside / "test.yml"
        external.write_text(self.fixture("matrix"))
        self.addCleanup(external.unlink, missing_ok=True)
        # The conventional path is accepted by both discovery modes.
        link = self.root / ".github/workflows"
        link.rmdir()
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlinks are unavailable: {exc}")
        status, output = main_output(
            str(self.root), "--workflow-dir", str(link), "--format", "json"
        )
        self.assertEqual(status, 2)
        self.assertIn("outside the repository root", output)
        status, output = main_output(str(self.root), "--format", "json")
        self.assertEqual(status, 2)
        self.assertIn("outside the repository root", output)

    def test_explicit_workflow_directory_rejects_external_workflow_symlink(self):
        outside = self.root.parent / f"outside-child-{self.root.name}.yml"
        outside.write_text(self.fixture("matrix"))
        self.addCleanup(outside.unlink, missing_ok=True)
        directory = self.root / "custom-workflows"
        directory.mkdir()
        try:
            (directory / "external.yml").symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks are unavailable: {exc}")
        status, output = main_output(
            str(self.root), "--workflow-dir", str(directory), "--format", "json"
        )
        self.assertEqual(status, 2)
        self.assertIn("outside the repository root", output)

    def test_parent_symlink_and_dotdot_cannot_escape_repository(self):
        outside = self.root.parent / f"outside-parent-{self.root.name}"
        (outside / "nested").mkdir(parents=True)
        self.addCleanup(outside.rmdir)
        self.addCleanup((outside / "nested").rmdir)
        external = outside / "secret.yml"
        external.write_text(self.fixture("matrix"))
        self.addCleanup(external.unlink, missing_ok=True)
        link = self.workflows / "linkdir"
        try:
            link.symlink_to(outside / "nested", target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlinks are unavailable: {exc}")
        status, output = main_output(
            str(self.workflows / "linkdir/../secret.yml"), "--format", "json"
        )
        self.assertEqual(status, 2)
        self.assertIn("outside the repository root", output)

    def test_equivalent_workflow_file_paths_have_same_findings(self):
        path = self.write(self.fixture("lockfile"))
        ordinary_status, ordinary_output = main_output(str(path), "--format", "json")
        dotted_status, dotted_output = main_output(
            str(self.workflows / "../workflows/test.yml"), "--format", "json"
        )
        self.assertEqual(dotted_status, ordinary_status)
        self.assertEqual(
            json.loads(dotted_output)["findings"],
            json.loads(ordinary_output)["findings"],
        )

    def test_custom_workflow_file_uses_repository_root(self):
        (self.root / ".git").mkdir()
        directory = self.root / "ci"
        directory.mkdir()
        path = directory / "test.yml"
        path.write_text(self.fixture("lockfile"))
        status, output = main_output(str(path), "--format", "json")
        report = json.loads(output)
        self.assertEqual(status, 1)
        self.assertEqual([f["rule_id"] for f in report["findings"]], ["GHA-CACHE-003"])

    def test_custom_workflow_file_accepts_explicit_root_without_git(self):
        directory = self.root / "ci"
        directory.mkdir()
        path = directory / "test.yml"
        path.write_text(self.fixture("lockfile"))
        status, output = main_output(
            str(path), "--root", str(self.root), "--format", "json"
        )
        report = json.loads(output)
        self.assertEqual(status, 1)
        self.assertEqual([f["rule_id"] for f in report["findings"]], ["GHA-CACHE-003"])

    def test_nested_custom_workflow_without_git_requires_explicit_root(self):
        project = self.root / "project"
        directory = project / "ci"
        directory.mkdir(parents=True)
        path = directory / "test.yml"
        path.write_text(self.fixture("lockfile"))
        with patch("gha_cache_audit.cli.Path.cwd", return_value=self.root):
            status, output = main_output(str(path), "--format", "json")
        self.assertEqual(status, 2)
        self.assertIn("cannot infer repository root", output)
        self.assertIn("--root", output)

    def test_workflow_directory_uses_explicit_root_without_git_metadata(self):
        directory = self.root / "ci"
        directory.mkdir()
        (directory / "test.yml").write_text(self.fixture("lockfile"))
        status, output = main_output(
            str(self.root), "--workflow-dir", "ci", "--format", "json"
        )
        report = json.loads(output)
        self.assertEqual(status, 1)
        self.assertEqual([f["rule_id"] for f in report["findings"]], ["GHA-CACHE-003"])

    def test_explicit_workflow_directory_is_scanned(self):
        directory = self.root / "custom-workflows"
        directory.mkdir()
        (directory / "package.json").write_text("{}\n")
        (directory / "README.md").write_text("Workflow fixtures\n")
        (directory / "safe.yml").write_text(self.fixture("safe"))
        status, output = main_output(
            str(self.root), "--workflow-dir", str(directory), "--format", "json"
        )
        self.assertEqual(status, 0)
        self.assertEqual(len(json.loads(output)["caches"]), 1)

    def test_default_config_symlink_cannot_escape_repository(self):
        outside = self.root.parent / f"outside-config-{self.root.name}.toml"
        outside.write_text(
            '[[suppressions]]\nrule="GHA-CACHE-001"\nreason="external"\n'
        )
        self.addCleanup(outside.unlink, missing_ok=True)
        try:
            (self.root / ".gha-cache-audit.toml").symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks are unavailable: {exc}")
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 2)
        self.assertIn("default configuration resolves outside", output)

    def test_root_without_workflows_does_not_parse_unrelated_yaml(self):
        self.workflows.rmdir()
        self.workflows.parent.rmdir()
        (self.root / "compose.yml").write_text("services: {}\n")
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 2)
        self.assertIn("no workflow YAML files found", output)
        self.assertNotIn("expected a workflow mapping", output)

    def test_source_symlink_cannot_escape_repository(self):
        outside = self.root.parent / f"outside-source-{self.root.name}"
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        external_source = outside / "private.ts"
        external_source.write_text("export const secret = 1")
        self.addCleanup(external_source.unlink, missing_ok=True)
        source = self.root / "src"
        try:
            source.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlinks are unavailable: {exc}")
        findings = self.scan(self.fixture("build"), "medium")
        self.assertFalse(any(f.rule_id == "GHA-CACHE-004" for f in findings))
        self.assertFalse(any("private.ts" in f.missing for f in findings))

    def test_unknown_self_hosted_os_allows_case_insensitive_hashfiles_match(self):
        text = (
            self.fixture("lockfile")
            .replace("ubuntu-latest", "self-hosted")
            .replace("yarn.lock", "PACKAGE-LOCK.JSON")
        )
        self.assertFalse(self.scan(text))
        findings = self.scan(text, "medium")
        self.assertEqual([finding.rule_id for finding in findings], ["GHA-CACHE-003"])
        self.assertEqual(findings[0].confidence, "medium")

    def test_windows_hashfiles_matching_ignores_case(self):
        (self.root / "src").mkdir()
        (self.root / "src/a.ts").write_text("a")
        text = self.fixture("build").replace("'package-lock.json'", "'SRC/*.TS'")
        self.assertEqual(
            [f.rule_id for f in self.scan(text, "medium")], ["GHA-CACHE-004"]
        )
        self.assertFalse(
            self.scan(text.replace("ubuntu-latest", "windows-latest"), "medium")
        )

    def test_hashfiles_pattern_order_and_call_boundaries(self):
        (self.root / "src").mkdir()
        (self.root / "src/a.ts").write_text("a")
        text = self.fixture("build").replace("'package-lock.json'", "'src/a.ts'")
        excluded = text.replace("'src/a.ts'", "'src/a.ts', '!src/a.ts'")
        self.assertEqual(
            [f.rule_id for f in self.scan(excluded, "medium")],
            ["GHA-CACHE-004"],
        )
        self.assertEqual(
            [
                f.rule_id
                for f in self.scan(
                    text.replace("'src/a.ts'", "'src/**', '!src'"), "medium"
                )
            ],
            ["GHA-CACHE-004"],
        )
        self.assertFalse(
            self.scan(
                text.replace("'src/a.ts'", "'src/a.ts', '!src/a.ts', 'src/a.ts'"),
                "medium",
            )
        )
        self.assertFalse(
            self.scan(
                text.replace(
                    "hashFiles('src/a.ts')",
                    "hashFiles('src/a.ts') }}-${{ hashFiles('src/a.ts', '!src/a.ts')",
                ),
                "medium",
            )
        )

    def test_incremental_build_configuration(self):
        (self.root / "next.config.js").write_text("module.exports = {}")
        text = self.fixture("build").replace("path: dist", "path: .next/cache")
        self.assertEqual(
            [f.rule_id for f in self.scan(text, "medium")], ["GHA-CACHE-004"]
        )
        self.assertFalse(
            self.scan(text.replace("'package-lock.json'", "'next.config.js'"), "medium")
        )

    def test_restore_positive_and_negative(self):
        text = self.fixture("restore").replace(
            "key: deps-", "key: deps-${{ runner.os }}-"
        )
        self.assertEqual(
            [f.rule_id for f in self.scan(text, "medium")], ["GHA-CACHE-005"]
        )
        self.assertFalse(
            self.scan(
                text.replace(
                    "restore-keys: deps-",
                    "restore-keys: deps-${{ runner.os }}-${{ matrix.node }}-",
                ),
                "medium",
            )
        )

    def test_os_restore_prefix_is_checked_separately(self):
        text = self.fixture("os").replace(
            "key: deps-", "restore-keys: deps-\n          key: deps-${{ runner.os }}-"
        )
        self.assertEqual(
            [f.rule_id for f in self.scan(text, "medium")], ["GHA-CACHE-005"]
        )
        self.assertFalse(
            self.scan(
                text.replace(
                    "restore-keys: deps-", "restore-keys: deps-${{ runner.os }}-"
                ),
                "medium",
            )
        )
        self.assertFalse(
            self.scan(text.replace("macos-latest", "ubuntu-24.04"), "medium")
        )

    def test_builtins_inventory(self):
        caches, diagnostics = parse(self.write(self.fixture("builtin")), self.root)
        self.assertFalse(diagnostics)
        self.assertEqual(len(caches), 2)
        self.assertTrue(all(c.implicit for c in caches))
        self.assertFalse([f for c in caches for f in analyze(c, self.root)])

    def test_env_alias_and_brackets(self):
        text = self.fixture("matrix").replace(
            "    steps:", "    env:\n      NODE: ${{ matrix.node }}\n    steps:"
        )
        text = text.replace(
            "node-version: ${{ matrix.node }}", "node-version: ${{ env.NODE }}"
        )
        self.assertEqual(self.scan(text)[0].missing, ["matrix.node"])
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ matrix['node'] }}-"))
        )
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ env.NODE }}-"))
        )

    def test_explicit_env_artifact_input(self):
        text = self.fixture("matrix").replace("node_modules", ".cache/compiler")
        text = text.replace("    steps:", "    env:\n      COMPILER: clang\n    steps:")
        overrides = [{"path": ".cache/compiler", "depends-on": ["env.COMPILER"]}]
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertFalse(diagnostics)
        findings = analyze(caches[0], self.root, overrides)
        self.assertEqual(
            [(f.rule_id, f.missing) for f in findings],
            [("GHA-CACHE-002", ["env.compiler"])],
        )
        (self.root / ".gha-cache-audit.toml").write_text(
            '[[artifacts]]\npath=".cache/compiler"\ndepends-on=["env.COMPILER"]\n'
        )
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output)["findings"][0]["missing"], ["env.compiler"])
        safe = text.replace("key: deps-", "key: deps-${{ env.COMPILER }}-")
        caches, diagnostics = parse(self.write(safe), self.root)
        self.assertFalse(diagnostics)
        self.assertFalse(analyze(caches[0], self.root, overrides))
        dynamic = text.replace("COMPILER: clang", "COMPILER: ${{ matrix.node }}")
        caches, diagnostics = parse(self.write(dynamic), self.root)
        self.assertFalse(diagnostics)
        self.assertEqual(
            analyze(caches[0], self.root, overrides)[0].missing, ["matrix.node"]
        )

    def test_setup_output_alias(self):
        text = self.fixture("matrix").replace(
            "      - uses: actions/setup-node",
            "      - id: node\n        uses: actions/setup-node",
        )
        self.assertFalse(
            self.scan(
                text.replace(
                    "key: deps-", "key: deps-${{ steps.node.outputs.node-version }}-"
                )
            )
        )

    def test_setup_after_restore(self):
        text = self.fixture("matrix")
        setup = "      - uses: actions/setup-node@v6\n        with:\n          node-version: ${{ matrix.node }}\n"
        self.assertEqual(
            self.scan(text.replace(setup, "") + setup)[0].rule_id, "GHA-CACHE-001"
        )

    def test_revision_keys_still_need_matrix_partitioning(self):
        text = self.fixture("matrix").replace(
            "hashFiles('package-lock.json')", "github.sha"
        )
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-001"])

    def test_conditional_cache_skipped(self):
        text = self.fixture("matrix").replace(
            "      - uses: actions/cache@v4",
            "      - if: matrix.node == 22\n        uses: actions/cache@v4",
        )
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertFalse([f for c in caches for f in analyze(c, self.root)])
        self.assertTrue(any("conditional cache step" in d.message for d in diagnostics))
        self.assertEqual(self.cli()[0], 2)
        status, output = self.cli("--format", "sarif")
        self.assertEqual(status, 2)
        self.assertFalse(
            json.loads(output)["runs"][0]["invocations"][0]["executionSuccessful"]
        )
        always = text.replace("matrix.node == 22", "always()")
        self.assertEqual([f.rule_id for f in self.scan(always)], ["GHA-CACHE-001"])
        never = text.replace("matrix.node == 22", "false")
        caches, diagnostics = parse(self.write(never), self.root)
        self.assertFalse(caches)
        self.assertFalse(diagnostics)

    def test_runner_os_separates_correlated_runtime_rows(self):
        text = (
            self.fixture("matrix")
            .replace("runs-on: ubuntu-latest", "runs-on: ${{ matrix.os }}")
            .replace(
                "        node: [22, 24]",
                "        include:\n          - node: 22\n            os: ubuntu-latest\n          - node: 24\n            os: macos-latest",
            )
        )
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ runner.os }}-"))
        )
        # Same OS with different runner image versions must still collide.
        self.assertTrue(
            self.scan(
                text.replace("macos-latest", "ubuntu-24.04").replace(
                    "key: deps-", "key: deps-${{ runner.os }}-"
                )
            )
        )

    def test_yaml_dates_are_strings_in_json(self):
        workflow = self.write(
            self.fixture("matrix").replace(
                "    steps:", "    env:\n      RELEASE_DATE: 2026-09-23\n    steps:"
            )
        )
        caches, diagnostics = parse(workflow, self.root)
        self.assertFalse(diagnostics)
        self.assertEqual(caches[0].aliases["env.release_date"], "2026-09-23")
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 1)
        self.assertNotIn("aliases", json.loads(output)["caches"][0])

    def test_unknown_key_skipped(self):
        workflow = self.write(
            self.fixture("matrix").replace(
                "key: deps-", "key: deps-${{ steps.custom.outputs.key }}-"
            )
        )
        caches, diagnostics = parse(workflow, self.root)
        self.assertFalse(caches)
        self.assertTrue(
            any("unsupported expressions" in d.message for d in diagnostics)
        )

    def test_architecture_is_scoped_to_runtime(self):
        text = self.fixture("matrix").replace(
            "        node: [22, 24]", "        node: [22]\n        arch: [x64, arm64]"
        )
        text += "      - uses: actions/setup-python@v5\n        with:\n          python-version: 3.13\n          architecture: ${{ matrix.arch }}\n"
        self.assertFalse(self.scan(text))
        text = text.replace(
            "node-version: ${{ matrix.node }}",
            "node-version: ${{ matrix.node }}\n          architecture: ${{ matrix.arch }}",
        )
        self.assertEqual(self.scan(text)[0].missing, ["matrix.arch"])

    def test_custom_multiple_inputs(self):
        caches, _ = parse(
            self.write(
                self.fixture("matrix").replace("node_modules", ".cache/compiler")
            ),
            self.root,
        )
        overrides = [
            {"path": ".cache/compiler", "depends-on": ["a.lock", "b.lock", "runner.os"]}
        ]
        findings = analyze(caches[0], self.root, overrides)
        self.assertEqual(
            {f.rule_id for f in findings}, {"GHA-CACHE-002", "GHA-CACHE-003"}
        )
        self.assertEqual(
            next(f.missing for f in findings if f.rule_id == "GHA-CACHE-003"),
            ["a.lock", "b.lock"],
        )

    def test_single_dimension_and_unused_axis(self):
        self.assertFalse(self.scan(self.fixture("matrix").replace("[22, 24]", "[22]")))
        self.assertFalse(
            self.scan(
                self.fixture("matrix").replace(
                    "node-version: ${{ matrix.node }}", "node-version: 22"
                )
            )
        )

    def test_runtime_matrix_values_render_to_same_input(self):
        text = self.fixture("matrix").replace("[22, 24]", "[22, '22']")
        self.assertFalse(self.scan(text))
        self.assertFalse(self.scan(text.replace("[22, '22']", "[true, 'true']")))
        self.assertEqual(
            [f.rule_id for f in self.scan(text.replace("[22, '22']", "[22, 24]"))],
            ["GHA-CACHE-001"],
        )

    def test_include_correlation(self):
        text = self.fixture("matrix").replace(
            "        node: [22, 24]",
            "        include:\n          - node: 22\n            label: old\n          - node: 24\n            label: new",
        )
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ matrix.label }}-"))
        )
        self.assertEqual(self.scan(text)[0].rule_id, "GHA-CACHE-001")

    def test_exclude(self):
        text = self.fixture("matrix").replace(
            "        node: [22, 24]",
            "        node: [22, 24]\n        exclude:\n          - node: 24",
        )
        self.assertFalse(self.scan(text))

    def test_python_uv(self):
        (self.root / "package-lock.json").unlink()
        (self.root / "uv.lock").write_text("version = 1")
        text = (
            self.fixture("matrix")
            .replace("node", "python")
            .replace("python_modules", ".venv")
            .replace("package-lock.json", "uv.lock")
        )
        self.assertEqual(self.scan(text)[0].missing, ["matrix.python"])
        self.assertFalse(
            self.scan(text.replace("key: deps-", "key: deps-${{ matrix.python }}-"))
        )

    def test_download_stores_are_not_installed_trees(self):
        for path in ("~/.npm", "~/.cache/pip", "~/.cache/uv", ".pnpm-store"):
            with self.subTest(path=path):
                self.assertFalse(
                    self.scan(self.fixture("matrix").replace("node_modules", path))
                )

    def test_multiple_caches(self):
        text = self.fixture("matrix")
        block = text[text.index("      - uses: actions/cache") :]
        findings = self.scan(text + block)
        self.assertEqual(len(findings), 2)
        self.assertNotEqual(findings[0].line, findings[1].line)

    def test_ambiguous_lockfiles_and_monorepo(self):
        text = self.fixture("lockfile")
        (self.root / "yarn.lock").write_text("")
        self.assertFalse(self.scan(text))
        (self.root / "web").mkdir()
        (self.root / "web/package-lock.json").write_text("{}")
        nested = text.replace("node_modules", "web/node_modules")
        self.assertEqual(self.scan(nested)[0].missing, ["web/package-lock.json"])
        self.assertFalse(
            self.scan(nested.replace("yarn.lock", "web/package-lock.json"))
        )

    def test_malformed_and_reusable(self):
        for text in (
            "jobs: [",
            "jobs: {}\njobs: {}",
            "- item",
            "jobs: {}\nenv: {x: !!binary aGVsbG8=}",
            "jobs: {}\nenv: {x: .nan}",
            self.fixture("reusable"),
        ):
            with self.subTest(text=text):
                _, diagnostics = parse(self.write(text), self.root)
                self.assertTrue(diagnostics)

    def test_dynamic_matrix_and_setup_ambiguity(self):
        text = self.fixture("matrix").replace(
            "matrix:\n        node: [22, 24]", "matrix: ${{ fromJSON(inputs.matrix) }}"
        )
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertTrue(diagnostics)
        self.assertFalse([f for c in caches for f in analyze(c, self.root)])

        text = self.fixture("matrix").replace(
            "      - uses: actions/setup-node",
            "      - if: false\n"
            "        uses: actions/setup-node@v6\n"
            "        with:\n"
            "          node-version: 20\n"
            "      - uses: actions/setup-node",
            1,
        )
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertFalse(diagnostics)
        findings = [
            finding for cache in caches for finding in analyze(cache, self.root)
        ]
        self.assertEqual(
            [finding.rule_id for finding in findings if finding.confidence == "high"],
            ["GHA-CACHE-001"],
        )
        text = self.fixture("matrix").replace(
            "      - uses: actions/setup-node",
            "      - if: success()\n        uses: actions/setup-node",
        )
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertTrue(diagnostics)
        self.assertFalse([f for c in caches for f in analyze(c, self.root)])

    def test_jobs_without_cache_do_not_block_analysis(self):
        for job in (
            "    if: github.ref == 'refs/heads/main'\n",
            "    strategy:\n      matrix: ${{ fromJSON(inputs.matrix) }}\n",
        ):
            with self.subTest(job=job):
                self.write(
                    "jobs:\n  lint:\n"
                    + job
                    + "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
                )
                status, output = self.cli("--format", "json")
                self.assertEqual(status, 0)
                self.assertEqual(json.loads(output)["diagnostics"], [])

    def test_yaml_aliases_are_checked_once_and_cycles_rejected(self):
        aliases = "a0: &a0 [0]\n" + "".join(
            f"a{i}: &a{i} [*a{i - 1}, *a{i - 1}]\n" for i in range(1, 25)
        )
        original_validate = workflow.validate_data
        visits = 0

        def bounded_validate(*args, **kwargs):
            nonlocal visits
            visits += 1
            if visits > 200:
                raise AssertionError("YAML alias validation repeated a subtree")
            return original_validate(*args, **kwargs)

        with patch.object(workflow, "validate_data", bounded_validate):
            _, diagnostics = parse(self.write(aliases + "jobs: {}\n"), self.root)
        self.assertEqual(diagnostics, [])
        self.assertLessEqual(visits, 200)
        _, diagnostics = parse(
            self.write("env: &cycle [*cycle]\njobs: {}\n"), self.root
        )
        self.assertTrue(
            any("cyclic" in d.message or "recursive" in d.message for d in diagnostics)
        )
        deep = (
            "base: &base "
            + "[" * 50
            + "0"
            + "]" * 50
            + "\ndeep: "
            + "[" * 60
            + "*base"
            + "]" * 60
            + "\njobs: {}\n"
        )
        _, diagnostics = parse(self.write(deep), self.root)
        self.assertTrue(any("deeply nested" in d.message for d in diagnostics))

    def test_long_env_alias_chain_is_diagnostic(self):
        aliases = "".join(f"  A{i}: ${{{{ env.A{i + 1} }}}}\n" for i in range(1200))
        self.write(
            "env:\n"
            + aliases
            + "  A1200: final\n"
            + "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            + "      - uses: actions/cache@v4\n        with:\n"
            + "          path: node_modules\n          key: ${{ env.A0 }}\n"
        )
        status, output = self.cli("--format", "json")
        report = json.loads(output)
        self.assertEqual(status, 2)
        self.assertTrue(
            any(
                "unsupported expressions" in d["message"] for d in report["diagnostics"]
            )
        )
        text = self.fixture("matrix").replace("matrix.node", "env.A0")
        self.write("env:\n" + aliases + "  A1200: final\n" + text)
        status, output = self.cli("--format", "json")
        report = json.loads(output)
        self.assertEqual(status, 2)
        self.assertTrue(
            any(
                "unsupported runtime setup input" in d["message"]
                for d in report["diagnostics"]
            )
        )

    def test_shared_env_alias_tree_is_diagnostic(self):
        aliases = "".join(
            f"  A{i}: ${{{{ env.A{i + 1} }}}}-${{{{ env.A{i + 1} }}}}\n"
            for i in range(22)
        )
        self.write(
            "env:\n"
            + aliases
            + "  A22: final\n"
            + "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            + "      - uses: actions/cache@v4\n        with:\n"
            + "          path: node_modules\n          key: ${{ env.A0 }}\n"
        )
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 2)
        self.assertTrue(
            any(
                "unsupported expressions" in d["message"]
                for d in json.loads(output)["diagnostics"]
            )
        )

    def test_repeated_large_env_alias_is_diagnostic(self):
        value = "x" * 10_000
        references = "${{ env.A }}" * 250
        self.write(
            f"env:\n  A: {value}\n"
            + "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            + "      - uses: actions/cache@v4\n        with:\n"
            + f"          path: node_modules\n          key: {references}\n"
        )
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 2)
        self.assertTrue(
            any(
                "unsupported expressions" in d["message"]
                for d in json.loads(output)["diagnostics"]
            )
        )

    def test_shared_yaml_collection_in_scalar_fields_is_diagnostic(self):
        aliases = "a0: &a0 [x]\n" + "".join(
            f"a{i}: &a{i} [*a{i - 1}, *a{i - 1}]\n" for i in range(1, 25)
        )
        base = self.fixture("matrix")
        variants = {
            "env alias": (
                "env:\n  BIG: *a24\n"
                + base.replace("hashFiles('package-lock.json')", "env.BIG")
            ),
            "key": base.replace(
                "key: deps-${{ hashFiles('package-lock.json') }}", "key: *a24"
            ),
            "path": base.replace("path: node_modules", "path: *a24"),
            "runtime": base.replace(
                "node-version: ${{ matrix.node }}", "node-version: *a24"
            ),
            "uses": base.replace("uses: actions/setup-node@v6", "uses: *a24"),
            "step id": base.replace(
                "      - uses: actions/setup-node@v6",
                "      - id: *a24\n        uses: actions/setup-node@v6",
            ),
            "runner": base.replace("runs-on: ubuntu-latest", "runs-on: *a24"),
        }
        for field, workflow_text in variants.items():
            with self.subTest(field=field):
                self.write(aliases + workflow_text)
                status, output = self.cli("--format", "json")
                self.assertEqual(status, 2)
                self.assertTrue(
                    any(
                        "must be a scalar" in d["message"]
                        for d in json.loads(output)["diagnostics"]
                    )
                )

    def cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main([str(self.root), *args])
        return status, output.getvalue()

    def test_cli_formats_and_confidence(self):
        self.write(self.fixture("matrix"))
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output)["findings"][0]["rule_id"], "GHA-CACHE-001")
        status, output = self.cli("--format", "sarif")
        report = json.loads(output)
        self.assertEqual(status, 1)
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["runs"][0]["results"][0]["ruleId"], "GHA-CACHE-001")
        self.assertEqual(
            report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "region"
            ]["startLine"],
            15,
        )
        self.write(self.fixture("restore"))
        self.assertEqual(self.cli()[0], 0)
        self.assertEqual(self.cli("--min-confidence", "medium")[0], 1)

    def test_json_inventory_excludes_repeated_job_internals(self):
        script = "echo " + "x" * 4000
        text = self.fixture("matrix").replace(
            "    steps:", f"    steps:\n      - run: {script}"
        )
        cache_block = text[text.index("      - uses: actions/cache") :]
        self.write(text + cache_block)
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 1)
        inventory = json.loads(output)["caches"]
        self.assertEqual(len(inventory), 2)
        self.assertTrue(
            all("commands" not in item and "aliases" not in item for item in inventory)
        )
        self.assertNotIn(script, output)

    def test_json_matrix_evidence_is_bounded_for_yaml_aliases(self):
        long_value = "x" * 10_000
        matrix_values = ", ".join(
            ["&large " + long_value] + ["*large"] * 254 + ["small"]
        )
        text = self.fixture("matrix").replace(
            "node: [22, 24]", f"node: [{matrix_values}]"
        )
        self.write(text)

        status, output = self.cli("--format", "json")

        self.assertEqual(status, 1)
        report = json.loads(output)
        finding = next(f for f in report["findings"] if f["rule_id"] == "GHA-CACHE-001")
        matrix = finding["evidence"]["matrix"]["node"]
        self.assertEqual(matrix["distinct_values"], 2)
        self.assertEqual(len(matrix["examples"]), 2)
        self.assertTrue(matrix["truncated"])
        self.assertLessEqual(max(map(len, matrix["examples"])), 120)
        self.assertEqual(finding["evidence"]["runtime_inputs"], ["matrix.node"])
        self.assertLess(len(output), 25_000)

    def test_cli_errors_are_structured(self):
        self.write("jobs: [")
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 2)
        self.assertTrue(json.loads(output)["diagnostics"])

    def test_suppressions_and_custom_artifacts(self):
        self.write(self.fixture("matrix"))
        config = self.root / ".gha-cache-audit.toml"
        config.write_text(
            '[[suppressions]]\nrule="GHA-CACHE-001"\nreason="intentional"\n'
        )
        self.assertEqual(self.cli()[0], 0)
        config.write_text('[[suppressions]]\nrule="GHA-CACHE-001"\n')
        self.assertEqual(self.cli()[0], 2)
        self.write(self.fixture("matrix").replace("node_modules", ".cache/compiler"))
        config.write_text(
            '[[artifacts]]\npath=".cache/compiler"\ndepends-on=["matrix.node", "compiler.lock"]\n'
        )
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 1)
        self.assertEqual(
            {f["rule_id"] for f in json.loads(output)["findings"]},
            {"GHA-CACHE-001", "GHA-CACHE-003"},
        )

    def test_invalid_suppression_rule_types_are_structured_errors(self):
        self.write(self.fixture("safe"))
        config = self.root / ".gha-cache-audit.toml"
        for rule in ("[]", "{}"):
            with self.subTest(rule=rule):
                config.write_text(
                    f'[[suppressions]]\nrule = {rule}\nreason = "invalid rule type"\n'
                )
                status, output = self.cli("--format", "json")
                self.assertEqual(status, 2)
                self.assertTrue(json.loads(output)["diagnostics"])


class ExpressionTests(unittest.TestCase):
    def test_literals_not_references(self):
        self.assertFalse(dependencies("plain matrix.node ${{ 'matrix.python' }}").refs)
        self.assertFalse(
            dependencies("${{ format('matrix.node-{0}', runner.os) }}").opaque
        )

    def test_quotes_and_delimiters(self):
        result = dependencies(
            "${{ format('a}}b''c-{0}', matrix.node) }}-${{ hashFiles('pnpm-lock.yaml', 'web/**') }}"
        )
        self.assertEqual(result.refs, {"matrix.node"})
        self.assertEqual(result.files, [("pnpm-lock.yaml", "web/**")])

    def test_cycles_and_unknown(self):
        self.assertTrue(
            dependencies(
                "${{ env.A }}", {"env.a": "${{ env.B }}", "env.b": "${{ env.A }}"}
            ).opaque
        )
        self.assertTrue(dependencies("${{ matrix[env.NAME] }}").opaque)
        self.assertTrue(dependencies("${{ unknown.foo }}").opaque)
        self.assertTrue(dependencies("${{ unfinished").opaque)

    def test_matrix_limit(self):
        self.assertTrue(matrix_rows({"n": list(range(257))})[1])
        self.assertTrue(matrix_rows({"include": [{"n": n} for n in range(257)]})[1])
        self.assertTrue(
            matrix_rows({"n": [1], "exclude": [{"n": n} for n in range(257)]})[1]
        )
        self.assertEqual(
            matrix_rows({"include": [{"n": 1}, {"n": 2}]}),
            ([{"n": 1}, {"n": 2}], False),
        )


class ActionTests(unittest.TestCase):
    def test_python_module_invocations_ignore_checkout(self):
        action = yaml.safe_load((FIXTURES.parent.parent / "action.yml").read_text())
        step = action["runs"]["steps"][0]
        script = step["run"]
        self.assertIn("workflow-dir", action["inputs"])
        self.assertEqual(
            step["env"]["AUDITOR_WORKFLOW_DIR"], "${{ inputs.workflow-dir }}"
        )
        self.assertIn('--workflow-dir "$AUDITOR_WORKFLOW_DIR"', script)
        self.assertIn('-- "$AUDITOR_TARGET"', script)
        for command in (
            "python -I -m venv",
            '"$audit_python" -I -m pip',
            '"$audit_python" -I -m gha_cache_audit',
            '"$audit_python" -I -c',
        ):
            self.assertIn(command, script)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("venv", "pip", "gha_cache_audit", "secrets"):
                (root / f"{name}.py").write_text(
                    'raise RuntimeError("checkout module executed")\n'
                )
            environment = root / "isolated"
            created = subprocess.run(
                [sys.executable, "-I", "-m", "venv", str(environment)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            venv_python = environment / "bin/python"
            if not venv_python.is_file():
                venv_python = environment / "Scripts/python.exe"
            for python, args in (
                (venv_python, ("-m", "pip", "--version")),
                (sys.executable, ("-m", "gha_cache_audit", "--version")),
                (venv_python, ("-c", "import secrets; print(secrets.token_hex(4))")),
            ):
                with self.subTest(args=args):
                    result = subprocess.run(
                        [python, "-I", *args],
                        cwd=root,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
