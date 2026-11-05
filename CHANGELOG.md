# Changelog

All notable changes to `mlab`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.3.0 - 2026-11-05

Domain scan v2.

### Changed

- **`scan domain` and `results domain` print the v2 report** (`GET /api/v1/scan/domain/report`, `schema: "domain-report/2"`) instead of the v1 results: score and grade, findings sorted by severity, then registration, DNS, mail, web, certificates and attack surface.
- **`--json` now outputs the raw v2 report.** Scripts that parse the v1 shape (`results.subdomains`, `results.dns`…) need `--legacy`.
- `search <domain>` reads the v2 report too. Like before, it never launches a scan.

### Added

- `--legacy` on `scan domain` and `results domain`: the v1 payload from `GET /api/v1/scan/domain/results`. The server keeps it frozen and no longer extends it.
- The latest certificates show in the v2 render, in the same table as `mlab ssl`.

### Fixed

- A scan that ends `failed` now exits `1` with an error. The status route answers `success` for failed scans too, so the report's own status is what gets checked. With `--json`, the report is still printed before the error.
- A `partial` or still-running report shows a warning instead of passing for a complete one.
