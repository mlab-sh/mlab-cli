# Hosts

`mlab` is one binary in front of three separate services. They differ in what
they hold, how they authenticate, and what happens when you have no credential
at all — which explains most of the CLI's behaviour, including why half of it
works out of the box.

| Host | Default | Credential | Commands |
| --- | --- | --- | --- |
| `mlab.sh` | `https://mlab.sh` | API key, **required** | [`scan`](Scan), [`lookups`](Lookups), [`status`](Status), [`results`](Results), [`ssl`](Ssl), [`ioc`](Ioc), [`network`](Network), [`limits`](Limits), `whoami` |
| `vuln.mlab.sh` | `https://vuln.mlab.sh` | none, plus an **optional** CI token | [`cve`](Cve), [`sbom`](Sbom), [`vuln`](Vuln) |
| `actors.mlab.sh` | `https://actors.mlab.sh` | none | [`actor`](Actor) |

Each host has its own override, as a flag or an environment variable:

| Host | Flag | Environment | Config key |
| --- | --- | --- | --- |
| Platform | `--hostname` | `MLAB_HOSTNAME` | `hostname` |
| CVE / SBOM | `--cve-hostname` | `MLAB_CVE_HOSTNAME` | `cve_hostname` |
| Actors | `--actors-hostname` | `MLAB_ACTORS_HOSTNAME` | `actors_hostname` |

Useful against a staging deployment, and the reason the integration suite can
run the real binary against a throwaway HTTP server on loopback with no
credentials and no network.

## `mlab.sh` — the platform

The metered one. Every route lives under `/api/v1`, every request carries the
API key, and the scan routes spend quota you can inspect with
[`limits`](Limits).

One route is deliberately outside the prefix: file upload posts to `/upload/file`
at the site root, not `/api/v1/upload/file`. The client keeps the root URL
separate from the API base for exactly that reason.

This host answers `400` for almost everything that goes wrong — quota
exhausted, platform in maintenance, malformed domain — with the reason in the
body rather than the status. The CLI classifies that once, centrally, into an
[exit code](Exit-Codes); no command has to parse an error string itself.

## `vuln.mlab.sh` — CVEs and dependencies

Public. `mlab cve detail CVE-2024-3094` works on a machine that has never run
`mlab login`, and so does a lockfile scan.

The optional credential is a **different** one from the platform key: a personal
CI token from the web account page, passed as `--vuln-token`, `MLAB_VULN_TOKEN`
or `vuln_token` in the config file, and sent as a bearer token. It buys nothing
but quota — it lifts the per-IP scan rate limit, which matters when a fleet of
CI runners shares one egress address.

Not everything here sits under `/api/v1`. `dump`, the CSV export and the RSS
feed live at the site root, so the [`cve`](Cve) page names the path each
sub-command actually calls.

`dump` is the heaviest anonymous route and is rate limited per IP: a `429`
carrying a short `Retry-After` is waited out, a long one is reported as a quota
error rather than silently sleeping for minutes.

## `actors.mlab.sh` — the threat actor database

Public and read-only. No credential is ever sent, and none is accepted.

The dataset comes from ETDA Threat Group Cards and MITRE ATT&CK under
CC BY-NC-SA 4.0, and every rendered view carries that attribution.

## Retries

Safe requests — the `GET`s — are retried on transport failures and on 5xx, with
an exponential backoff starting at 300 ms. A `429` carrying a short
`Retry-After` is honoured.

Writes are not retried. A scan launch and a lockfile upload are sent exactly
once, because a replay would spend quota twice for one command; a failed launch
is reported, never quietly repeated.

## Seeing the request

`--dry-run` prints the first request a command would send and stops, on any
host:

```console
$ mlab --dry-run scan crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
GET https://mlab.sh/api/v1/scan/crypto?address=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

$ mlab --dry-run cve search openssl --severity HIGH
GET https://vuln.mlab.sh/api/v1/cve?q=openssl&severity=HIGH
```

That is the fastest way to find out what a flag really does, and it costs no
quota.
