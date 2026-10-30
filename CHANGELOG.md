# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-30

The runner became the back half of a pipeline. A template now has to pass a
static gate before it is allowed to send anything.

### Added

- **Static lint engine** with six rules (`PG-001` … `PG-006`): metadata
  contract, identity/CVE consistency, dangerous capabilities, destructive
  payloads, weak matchers and cross-file duplicates.
- **YAML path → line mapping** built from the `yaml.compose` node tree, so every
  finding points at `file:line` and every rule reports an actionable hint.
- **Gate** (`gate.py`): templates with a non-waived finding at or above
  `--block-on` are refused by the runner; `--allow-unsafe` is the explicit
  override.
- **Nuclei dialect support**: `http:`/`requests:`, `raw:`, `payloads:`
  (up to 50 combinations), `info.classification`, and protocol blocks. Legacy
  v1 flat `match_*` templates still load through the same model.
- **SARIF 2.1.0** output for GitHub code scanning, with waiver suppressions, plus
  `--format json` for pipelines.
- **Unified Markdown report**: lint findings, gate decisions, planned requests
  (dry-run) and per-request evidence in one file.
- **`.pocverify.yaml`** with glob waivers that require a reason; unused waivers
  are reported and `--strict-waivers` fails on them.
- **`--dry-run`** prints exactly what would be sent (headers masked) and sends
  nothing.
- **Scope enforcement**: same-origin absolute URLs only, cross-origin redirects
  not followed, raw `Host` replaced by the target.
- **Test suite**: 188 pytest cases, offline, including a local `http.server`
  target; CI matrix on Linux and Windows.
- English and Chinese READMEs, rule reference, architecture and threat model.

### Changed

- The project is now an installable package (`src/pocverify`) with a
  `pocverify` console script; v1 top-level modules were replaced by the package.
- The bundled PoC files use the v2 schema (`id`, `info:`, `matchers:`).
- The bundled mock target moved to `mock/dvwa_mock.py`.
- Scoring is per template (`critical` −25, `high` −10, `medium` −4, `low` −1);
  the report shows the worst template and the average.

### Removed

- `requests` as a runtime dependency: the runner uses `urllib` from the standard
  library. Runtime dependencies are now `PyYAML` and `rich`.

### Deprecated

- `python main.py --target ... --poc-dir ...` still works through a shim that
  maps to `pocverify run --no-lint --allow-unsafe` and prints a migration note.

## [1.0.0] - 2026-10-15

- YAML-driven PoC runner for authorized labs: GET/POST, timeout, retries,
  `--delay`, response size cap, status/keyword/regex matching, Markdown report.
- Local DVWA-shaped mock target for offline demonstration.
