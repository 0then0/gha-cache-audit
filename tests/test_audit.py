import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from gha_cache_audit.analysis import analyze
from gha_cache_audit.cli import main
from gha_cache_audit.expressions import dependencies
from gha_cache_audit.workflow import matrix_rows, parse

FIXTURES = Path(__file__).parent / "fixtures"


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

    def scan(self, text):
        caches, diagnostics = parse(self.write(text), self.root)
        self.assertEqual(diagnostics, [])
        return [f for c in caches for f in analyze(c, self.root)]

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

    def test_windows_archive_confidence(self):
        text = self.fixture("os").replace("macos-latest", "windows-latest")
        self.assertEqual(self.scan(text)[0].confidence, "medium")
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

    def test_build_positive_and_negative(self):
        (self.root / "src").mkdir()
        (self.root / "src/index.ts").write_text("export const n = 1")
        text = self.fixture("build")
        findings = self.scan(text)
        self.assertEqual([f.rule_id for f in findings], ["GHA-CACHE-004"])
        self.assertEqual(findings[0].confidence, "medium")
        self.assertFalse(
            self.scan(
                text.replace("'package-lock.json'", "'package-lock.json', 'src/**'")
            )
        )
        self.assertFalse(self.scan(text.replace("path: dist", "path: .next/cache")))
        self.assertFalse(self.scan(text.replace("npm run build", "echo build")))

    def test_restore_positive_and_negative(self):
        text = self.fixture("restore")
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-005"])
        self.assertFalse(
            self.scan(
                text.replace(
                    "restore-keys: deps-", "restore-keys: deps-${{ matrix.node }}-"
                )
            )
        )

    def test_os_restore_prefix_is_checked_separately(self):
        text = self.fixture("os").replace(
            "key: deps-", "restore-keys: deps-\n          key: deps-${{ runner.os }}-"
        )
        self.assertEqual([f.rule_id for f in self.scan(text)], ["GHA-CACHE-005"])
        self.assertFalse(
            self.scan(
                text.replace(
                    "restore-keys: deps-", "restore-keys: deps-${{ runner.os }}-"
                )
            )
        )
        self.assertFalse(self.scan(text.replace("macos-latest", "ubuntu-24.04")))

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
        self.assertFalse(self.scan(text))

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
        self.write(
            self.fixture("matrix").replace(
                "    steps:", "    env:\n      RELEASE_DATE: 2026-09-23\n    steps:"
            )
        )
        status, output = self.cli("--format", "json")
        self.assertEqual(status, 1)
        self.assertEqual(
            json.loads(output)["caches"][0]["aliases"]["env.release_date"], "2026-09-23"
        )

    def test_unknown_key_skipped(self):
        self.assertFalse(
            self.scan(
                self.fixture("matrix").replace(
                    "key: deps-", "key: deps-${{ steps.custom.outputs.key }}-"
                )
            )
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
            "      - if: success()\n        uses: actions/setup-node",
        )
        self.assertFalse(self.scan(text))

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
        self.assertEqual(
            report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "region"
            ]["startLine"],
            15,
        )
        self.write(self.fixture("restore"))
        self.assertEqual(self.cli()[0], 0)
        self.assertEqual(self.cli("--min-confidence", "medium")[0], 1)

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
        self.assertEqual(result.files, {"pnpm-lock.yaml", "web/**"})

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
        self.assertEqual(
            matrix_rows({"include": [{"n": 1}, {"n": 2}]}),
            ([{"n": 1}, {"n": 2}], False),
        )


if __name__ == "__main__":
    unittest.main()
