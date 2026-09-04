# mlab-cli

`mlab` is the official command-line client for the [mlab.sh](https://mlab.sh)
threat-intelligence platform and its companion services: the CVE and dependency
scanner at [vuln.mlab.sh](https://vuln.mlab.sh) and the threat-actor database at
[actors.mlab.sh](https://actors.mlab.sh).

It lets you scan domains, look up IPs, analyse files, inspect SSL certificates,
check cryptocurrency addresses, and search the CVE database — all from a single
keyboard-driven tool with pretty terminal output or raw JSON for scripting.

```
$ mlab scan domain example.com
$ mlab cve detail CVE-2024-3094
$ mlab limits
```

## Installation

### Homebrew (macOS & Linux)

```bash
brew tap mlab-sh/mlab-cli https://github.com/mlab-sh/mlab-cli
brew install mlab
```

### From a release archive

Download the right tarball for your platform from the
[releases page](https://github.com/mlab-sh/mlab-cli/releases) and drop the
binary into a directory on your `PATH`:

```bash
tar xzf mlab-darwin-arm64.tar.gz
sudo mv mlab /usr/local/bin/
```

Pre-built archives are published for:

- `mlab-darwin-arm64` — macOS Apple Silicon
- `mlab-darwin-amd64` — macOS Intel
- `mlab-linux-amd64` — Linux x86_64 (glibc)
- `mlab-linux-arm64` — Linux aarch64 (glibc)

### From source

```bash
git clone https://github.com/mlab-sh/mlab-cli
cd mlab-cli
cargo install --path .
```

Requires Rust 1.74+.

## Authentication

The mlab.sh endpoints require an API key. Generate one from your account at
<https://mlab.sh> and run:

```bash
mlab login
```

`login` verifies the key against the API before storing it, so a typo fails
immediately instead of at the next command. For CI, pass it directly:

```bash
mlab login --key "$MLAB_KEY"
```

The key is written to `~/.mlab/conf.yml` with `0600` permissions. Verify it with
`mlab whoami`, and remove it with `mlab logout`.

A key can also come from the environment or a flag, which take precedence over
the file:

| Source | Example |
|---|---|
| Flag | `mlab --api-key mlab_xxx whoami` |
| Environment | `MLAB_API_KEY=mlab_xxx mlab whoami` |
| Config file | `~/.mlab/conf.yml` |

`MLAB_HOSTNAME`, `MLAB_CVE_HOSTNAME` and `MLAB_ACTORS_HOSTNAME` work the same way
for the three hosts.

`vuln.mlab.sh` uses a **separate** credential: a personal CI token created from
the web account page, supplied as `--vuln-token`, `MLAB_VULN_TOKEN`, or
`vuln_token` in the config file. Most of that host answers unauthenticated — the
token only lifts the per-IP scan rate limit, so CI runners behind shared egress
IPs get their own quota.

The CVE endpoints on `vuln.mlab.sh` are public and require no authentication.

## Commands

### `mlab scan` — launch a scan

| Sub-command | Endpoint | Description |
|---|---|---|
| `scan domain <domain>` | `POST /api/v1/scan/domain` | Launch a full domain scan, poll until completion, render the report |
| `scan ip <ip>` | `GET /api/v1/scan/ip` | Geo, ASN and threat intel for an IPv4/IPv6 address |
| `scan file <path>` | `POST /upload/file` (site root, not under `/api/v1`) | Upload a file (≤ 10 MB) and print the `sha256` to poll |
| `scan crypto <address>` | `GET /api/v1/scan/crypto` | Threat intel for a blockchain address (chain auto-detected; override with `--chain eth/btc/...`) |

Common flags:

- `--json` — emit raw JSON (good for piping into `jq`); accepted by every command
- `--no-follow` (domain only) — fire the scan and exit immediately

`scan domain` follows the scan for at most 15 minutes and stops as soon as the
API reports a failure, rather than polling a dead scan forever. Safe requests are
retried on transport blips and 5xx, and a `429` with a short `Retry-After` is
honoured; a scan launch is never replayed, so a retry cannot spend your quota
twice.

### `mlab scan` — lookups

| Sub-command | Endpoint | Description |
|---|---|---|
| `scan url <url>` | `GET /api/v1/scan/url` | URL structure, host reputation, lookalike detection. `--resolve` follows redirects (off by default: it fetches the target) |
| `scan hash <h...>` | `GET`/`POST /api/v1/scan/hash` | Reputation for SHA-1/SHA-256/MD5. More than one digest switches to the bulk endpoint |
| `scan email <addr>` | `GET /api/v1/scan/email` | Mailbox type, disposable/role detection, sending-domain posture |
| `scan phone <num>` | `GET /api/v1/scan/phone` | Validity, region, line type, operator |
| `scan mac <mac>` | `GET /api/v1/scan/mac` | Vendor/OUI, randomization, virtualization |
| `scan bash <file>` | `POST /api/v1/scan/file/bash` | Shell-script analysis: suspicious patterns and extracted indicators |
| `scan crypto <a...>` | `GET`/`POST /api/v1/scan/crypto` | More than one address switches to the bulk endpoint |

### `mlab ioc` — pull indicators out of text

```bash
cat incident-report.txt | mlab ioc
mlab ioc report.txt --country fr --risk deep
mlab ioc - --json | jq '.iocs.ipv4[].value'
```

Reads stdin by default, which is the point: pipe an email, a log or a report at
it and get the indicators back grouped by kind. `--risk fast` scores locally,
`--risk deep` adds network checks.

### `mlab network` — capture a page's requests

```bash
mlab network https://example.com
```

Loads the URL in an instrumented browser and lists every request it makes, with
status, resource type, size and failures.

### `mlab status` — check progress

```bash
mlab status domain example.com
mlab status domain example.com --json
```

### `mlab results` — fetch finished results

```bash
mlab results domain example.com
mlab results file <sha256>
mlab results file <sha256> --tool strings   # one tool's raw output
```

`scan file --follow` uploads, waits for the analysis and prints the report in one
go, the way `scan domain` does.

### `mlab ssl` — SSL certificate details

```bash
mlab ssl example.com
mlab ssl example.com --json
```

Expiry is computed against the current date: expired certificates are flagged in
red, ones lapsing within 30 days in yellow. The endpoint returns what a previous
scan collected, so run `mlab scan domain` first on a domain you have never
scanned. The domain report shows the same certificates inline.

### `mlab limits` — quota inspection

```bash
mlab limits                # show all (domain, ip, file, crypto)
mlab limits domain         # one scan type
mlab limits ip --raw       # raw remaining count, easy to script
```

### `mlab actor` — threat actor intelligence (actors.mlab.sh)

```bash
mlab actor list --origin Russia --sector Government
mlab actor get apt28
mlab actor by-cve CVE-2023-23397
mlab actor stix apt28 > apt28.stix.json
mlab actor export --format jsonl > actors.jsonl
```

Public and read-only — no credential. `list` filters on `origin`, `motivation`,
`sector` and `updated_since`, and pages with `--limit`/`--offset` (`--country` is
accepted as an alias for `--origin`, which is the name the API actually reads).
`by-cve` validates the identifier locally, so a typo costs no request.

The dataset comes from ETDA Threat Group Cards and MITRE ATT&CK under
CC BY-NC-SA 4.0, and every rendered view carries that attribution.

### `mlab sbom scan` — dependency scanning for CI

```bash
mlab sbom scan package-lock.json
mlab sbom scan Cargo.lock --fail-on high
mlab sbom scan --url https://raw.githubusercontent.com/o/r/main/go.sum
cat requirements.txt | mlab sbom scan - --format pip
```

The lockfile is sent as-is and the format is detected server-side, so the CLI
never has to learn a manifest format. `--fail-on critical|high|medium|low` exits
`7` when a finding reaches that severity, which is the whole point in CI:

```yaml
- run: mlab sbom scan package-lock.json --fail-on high
```

Severity comes from the advisory's CVSS v3 vector, scored with the same formula
the web UI uses, so the CLI fails on exactly what the site paints red.

**An incomplete scan never passes the gate.** The API distinguishes "this package
has no known vulnerabilities" from "this package could not be scanned", and
reports upstream outages explicitly. When any of that happens, `--fail-on` exits
non-zero with the reason instead of reporting a clean build — a scan that did not
look is not a scan that found nothing.

`--json` keeps the raw payload on stdout *and* still applies the gate.

### `mlab vuln query` — one package coordinate

```bash
mlab vuln query pkg:cargo/time --version 0.1.0
mlab vuln query npm/lodash --version 4.17.11
```

OSV-compatible lookup. An empty result is a real answer ("no known
vulnerabilities"); an upstream outage is an error, never silence.

### `mlab cve` — CVE search (vuln.mlab.sh)

```bash
mlab cve search openssl --severity HIGH
mlab cve search "remote code execution" --date-start 2026-01-01 --exact
mlab cve search apache --vendor redhat --min-cvss 7.5 --kev-only
mlab cve search xss --cwe CWE-79 --page 1 --limit 50
mlab cve detail CVE-2024-3094
mlab cve latest
```

`search` accepts every filter the API supports: `--severity`, `--date-start`,
`--date-end`, `--vendor`, `--cwe`, `--min-cvss`, `--kev-only`, `--exact`, plus
`--page` (0-based) and `--limit` (max 100). Results are paginated server-side and
the CLI tells you when more pages exist. `latest` takes no filters — the endpoint
returns a fixed window.

All `cve` commands accept `--json`. The detail view shows CVSS score & vector,
EPSS probability, CISA KEV status, weaknesses (CWE) and references.

Beyond search, the same host exposes:

```bash
mlab cve dump --date-start 2026-01-01 --min-cvss 7 > cves.json
mlab cve export openssl --severity HIGH --format csv > openssl.csv
mlab cve export "" --kev-only --format rss
mlab cve stats
mlab cve sources
mlab cve advisories --cve CVE-2024-3094
mlab cve vendor microsoft --year 2026
```

`dump` is the heaviest anonymous route and is rate limited per IP: a `429` with a
short `Retry-After` is waited out, a long one is reported as a quota error.
`export` writes to stdout — CSV lives at `/export/csv` and the feed at `/rss`,
both at the site root (the paths the Node SDK documents under `/api/v1` do not
exist).

## Global flags

| Flag | Description |
|---|---|
| `--hostname <url>` | Override the mlab.sh API host (default `https://mlab.sh`) |
| `--cve-hostname <url>` | Override the CVE API host (default `https://vuln.mlab.sh`) |
| `--api-key <key>` | Use this key instead of the stored one |
| `--vuln-token <token>` | vuln.mlab.sh CI token — raises the scan quota |
| `--actors-hostname <url>` | Override the threat-actor API host |
| `--quiet`, `-q` | Suppress spinners and progress output |

Useful for self-hosted deployments or staging environments.

## Progress output

Long-running commands show a spinner with an elapsed timer, and a step counter
where the work is countable (`mlab limits` polls four quotas, a followed file
scan reports `3/8 tools`). A followed domain scan tracks the API's own state:
`queued` → `scanning` → `done`.

Three rules govern it:

- **Progress goes to stderr, results go to stdout.** `mlab scan domain x --json |
  jq` is a clean stream; nothing animated ever lands in it.
- **Nothing is drawn unless stderr is a terminal.** Pipes, redirects, CI logs and
  test harnesses get plain output with no escape sequences.
- **Nothing is drawn for fast work.** A spinner only appears once a call has run
  past 300 ms, so quick lookups do not flash.

Turn it off with `--quiet`/`-q`, or `MLAB_NO_PROGRESS=1`. It also switches itself
off when `CI` is set. `--quiet` silences progress only — errors still print.

```bash
mlab -q scan domain example.com --json > report.json
MLAB_NO_PROGRESS=1 mlab limits
```

## Exit codes

The API reports quota, maintenance and malformed input all as HTTP 400 with the
reason in the body; the CLI classifies that into a code you can branch on.

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic failure (network, unreadable response) |
| `2` | Authentication — missing, rejected or unrecognized key |
| `3` | Quota exhausted or rate limited |
| `4` | Invalid input (bad domain, unreadable file, unsupported type) |
| `5` | Platform in maintenance |
| `6` | Nothing found (no scan for that domain, unknown hash) |
| `7` | A `--fail-on` gate matched: the scan worked and found something bad enough |

```bash
mlab scan domain example.com || case $? in
  3) echo "out of quota" ;;
  5) echo "maintenance, retry later" ;;
esac
```

## Configuration file

`~/.mlab/conf.yml`, written with `0600` permissions:

```yaml
hostname: https://mlab.sh
cve_hostname: https://vuln.mlab.sh
actors_hostname: https://actors.mlab.sh
api_key: <your key>
vuln_token: <optional vuln.mlab.sh CI token>
```

You can edit it by hand; `mlab login` rewrites it and `mlab logout` clears the
key while keeping the hosts.

## Examples

Scan a domain and dump the JSON report into a file:

```bash
mlab scan domain example.com --json > example.json
```

List the 5 highest-scoring CVEs published last week:

```bash
mlab cve latest --json | jq '.cves | sort_by(-.cvss_score) | .[:5] | .[].id'
```

Quick check that you have crypto quota left:

```bash
mlab limits crypto --raw
```

## Tests

```bash
cargo test
```

Unit tests live next to the code they cover; `tests/cli.rs` drives the real
binary against a throwaway HTTP server on an ephemeral loopback port, with an
isolated `$HOME`, so the suite needs no API key and never reaches the network.

## Releases

Tagged commits (`v*`) trigger a GitHub Actions build that produces:

- Static-TLS binaries for the four supported targets, packaged as `.tar.gz`
- A GitHub Release with auto-generated notes and the tarballs attached
- An auto-bumped [`Formula/mlab.rb`](Formula/mlab.rb) committed back to `main`,
  so `brew upgrade mlab` picks the new version up on the next refresh

To cut a release:

```bash
# bump version in Cargo.toml, commit, then:
git tag v0.2.0
git push origin v0.2.0
```

You can also trigger the workflow manually from the Actions tab.

## License

Apache-2.0 — see [LICENSE](LICENSE).
