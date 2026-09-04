# mlab-cli

`mlab` is the official command-line client for the [mlab.sh](https://mlab.sh)
threat-intelligence platform and its companion CVE API at
[vuln.mlab.sh](https://vuln.mlab.sh).

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

`MLAB_HOSTNAME` and `MLAB_CVE_HOSTNAME` work the same way for the two hosts.

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

### `mlab status` — check progress

```bash
mlab status domain example.com
mlab status domain example.com --json
```

### `mlab results` — fetch finished results

```bash
mlab results domain example.com
mlab results file <sha256>
```

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

## Global flags

| Flag | Description |
|---|---|
| `--hostname <url>` | Override the mlab.sh API host (default `https://mlab.sh`) |
| `--cve-hostname <url>` | Override the CVE API host (default `https://vuln.mlab.sh`) |
| `--api-key <key>` | Use this key instead of the stored one |

Useful for self-hosted deployments or staging environments.

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
api_key: <your key>
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
