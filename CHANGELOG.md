# Changelog

This project follows [Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Monthly Dependabot updates for Python packages and GitHub Actions.
- Repository icon, Shields.io badges, issue forms, and project policies.

### Changed

- Shortened the README and moved detailed guidance into `docs/guide.md`.

## [0.1.6] - 2026-10-31

### Fixed

- Report incomplete analysis for glob, home-directory, and expression cache
  paths that prevent artifact inference, while retaining checks on other paths.
  Known package download stores remain intentional exclusions.
- Preserve download-store exclusions for patterns within them and treat braces
  and extglob-like directory names as literals, matching `@actions/glob`.
- Diagnose unknown restore-prefix dependencies without guessing their values or
  dropping primary-key findings and checks on known prefixes.
- Include diagnostic locations in SARIF notifications and make incomplete text
  summaries explicit. Cache counts describe discovered definitions, not proof
  of complete analysis. Diagnostics retain exit status `2` even with findings.

## [0.1.5] - 2026-09-27

### Changed

- Updated the PyPI description and organized the user and contributor guides.

Earlier release details are available in the [GitHub Releases](https://github.com/0then0/gha-cache-audit/releases) page.
