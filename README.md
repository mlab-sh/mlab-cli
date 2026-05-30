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

The key is stored in `~/.mlab/conf.yml`. You can verify it with:

```bash
mlab whoami
```

The CVE endpoints on `vuln.mlab.sh` are public and require no authentication.

## Commands

### `mlab scan` — launch a scan

| Sub-command | Endpoint | Description |
|---|---|---|
| `scan domain <domain>` | `POST /api/v1/scan/domain` | Launch a full domain scan, poll until completion, render the report |
| `scan ip <ip>` | `GET /api/v1/scan/ip` | Geo, ASN and threat intel for an IPv4/IPv6 address |
| `scan file <path>` | `POST /api/v1/upload/file` | Upload a file (≤ 10 MB) for analysis |
| `scan crypto <address>` | `GET /api/v1/scan/crypto` | Threat intel for a blockchain address (`--chain eth/btc/...`) |

Common flags:

- `--json` — emit raw JSON (good for piping into `jq`)
- `--no-follow` (domain only) — fire the scan and exit immediately

### `mlab status` — check progress

```bash
mlab status domain example.com
```

### `mlab results` — fetch finished results

```bash
mlab results domain example.com
mlab results file <sha256>
```

### `mlab ssl` — SSL certificate details

```bash
mlab ssl example.com
```

### `mlab limits` — quota inspection

```bash
mlab limits                # show all (domain, ip, file, crypto)
mlab limits domain         # one scan type
mlab limits ip --raw       # raw number, easy to script
```

### `mlab cve` — CVE search (vuln.mlab.sh)

```bash
mlab cve search openssl --severity HIGH
mlab cve search "remote code execution" --date-start 2025-01-01 --exact
mlab cve detail CVE-2024-3094
mlab cve latest
```

All `cve` commands accept `--json`. The detail view shows CVSS score & vector,
EPSS probability, CISA KEV status, weaknesses (CWE) and references.

## Global flags

| Flag | Description |
|---|---|
| `--hostname <url>` | Override the mlab.sh API host (default `https://mlab.sh`) |
| `--cve-hostname <url>` | Override the CVE API host (default `https://vuln.mlab.sh`) |

Useful for self-hosted deployments or staging environments.

## Configuration file

`~/.mlab/conf.yml`:

```yaml
hostname: https://mlab.sh
api_key: <your key>
```

You can edit it by hand; `mlab login` will rewrite it.

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
