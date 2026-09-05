# `mlab scan`

The metered commands. Each one spends quota you can inspect with
[`limits`](Limits), and each answers on `mlab.sh`, so each needs an API key.

The cheap sub-commands that live under the same verb — `url`, `hash`, `email`,
`phone`, `mac`, `bash` — are on [Lookups](Lookups).

| Sub-command | Endpoint | What it does |
| --- | --- | --- |
| `scan domain <domain>` | `POST /api/v1/scan/domain` | Launch a full domain scan, follow it, render the report |
| `scan ip <ip>` | `GET /api/v1/scan/ip` | Geo, ASN and threat intel for an IPv4 or IPv6 address |
| `scan file <path>` | `POST /upload/file` | Upload a file (≤ 10 MB) and print the sha256 to poll |
| `scan crypto <address…>` | `GET`/`POST /api/v1/scan/crypto` | Threat intel for one or more blockchain addresses |

## `scan domain`

```bash
mlab scan domain example.com
mlab scan domain example.com --no-follow
mlab scan domain example.com --json > report.json
```

Launches the scan, then follows it to completion and prints the report — the
whole thing in one command. Progress goes to stderr, so `--json` still gives a
clean stream on stdout.

```
⠹ Scanning example.com — scanning  1m12s
```

`--no-follow` fires the scan and exits, telling you what to run next:

```
ok: Scan launched for example.com
    Track it with: mlab status domain example.com
```

### How it follows

- **A budget, not a loop.** It gives up after `--max-wait` seconds (default
  900, so fifteen minutes) and says what the last status was.
- **Backing off.** Polls start at 2 s and grow by half each time to a ceiling of
  15 s, so a quick scan is caught almost immediately and a slow one is not asked
  two hundred times.
- **A failure stops it.** A terminal failure reported by the API ends the
  command; without that the loop would spin until the timeout on a scan that
  is already dead.
- **A blip does not.** Transient polling errors are tolerated for a few
  consecutive attempts before the command gives up on them.

The launch itself is never retried. A replay would spend a second scan of quota
for one command, so a failed launch is reported rather than quietly repeated.

## `scan ip`

```bash
mlab scan ip 8.8.8.8
mlab scan ip 2001:4860:4860::8888 --json
```

A single request, no polling. Geolocation, ASN and reputation.

## `scan file`

```bash
mlab scan file suspicious.bin
mlab scan file suspicious.bin --follow
```

Uploads the file and prints the sha256 the analysis is keyed on:

```
  ✔ File uploaded
  sha256:  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Without `--follow` that is where it stops — fetch the report later with
[`results file`](Results). With `--follow` it waits for the analysis and prints
the report in one go, the way `scan domain` does, reporting the tools as they
finish:

```
⠹ Analysing — 3/8 tools  0m24s
```

The upload posts to `/upload/file` at the site root rather than under
`/api/v1` — the one platform route outside the prefix. A file that does not
exist fails locally, before anything is sent, with exit code `4`.

The size ceiling is 10 MB.

## `scan crypto`

```bash
mlab scan crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
mlab scan crypto 0x742d35Cc6634C0532925a3b844Bc454e4438f44e --chain eth
mlab scan crypto addr1 addr2 addr3
```

The chain is detected from the address; `--chain` overrides it when the address
shape is ambiguous. More than one address switches to the bulk endpoint —
one request instead of *n*, and one line of quota per address either way.

## Flags

| Flag | Applies to | Description |
| --- | --- | --- |
| `--json` | all | Raw JSON on stdout |
| `--no-follow` | `domain` | Launch and exit |
| `--follow` | `file` | Wait for the analysis and print the report |
| `--chain` | `crypto` | Force the blockchain instead of detecting it |
| `--max-wait` | `domain`, `file --follow` | Seconds to follow before giving up (default 900) |

`-o csv` is refused here: a scan report is a nested document, and flattening it
into rows would produce something no spreadsheet can use. See
[Output](Output).

## Before you spend quota

```bash
mlab --dry-run scan domain example.com
mlab limits domain
```

`--dry-run` prints the request and stops. [`limits`](Limits) says what is left.
