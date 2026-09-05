# Authentication

Two credentials, for two different [hosts](Hosts), with different rules.

| | API key | vuln CI token |
| --- | --- | --- |
| Host | `mlab.sh` | `vuln.mlab.sh` |
| Required | yes, for every platform command | no |
| Where from | your account at <https://mlab.sh> | the web account page |
| Sent as | `Authorization: token …` | `Authorization: Bearer …` |
| What it buys | access | quota — it lifts the per-IP scan rate limit |

`actors.mlab.sh` takes no credential at all, and the CVE endpoints on
`vuln.mlab.sh` are public.

## The API key

```bash
mlab login
```

The prompt asks for the key, verifies it against the API, and only then writes
it. Storing a key that does not work just moves the failure to whatever you run
next, so a typo fails here instead:

```
ok: Authenticated as Acme Security — key saved to /home/you/.mlab/conf.yml
```

Non-interactively, for CI:

```bash
mlab login --key "$MLAB_KEY"
```

Check it later with `whoami`, and remove it with `logout` — which clears the
key and keeps the hostname, because a hostname is a preference, not a
credential. See [login](Login).

### Why `whoami` is not just a status code

The API answers `200` with a generic greeting when the key is unknown, so the
status alone cannot separate an authenticated call from a rejected one. Both
`login` and `whoami` look for an organization in the body (or the explicit
`api_key` marker) and treat its absence as a rejection. A key that "works"
against a naive check is caught here.

## Precedence

Flag, then environment, then file. The first one set wins:

| Source | Example |
| --- | --- |
| Flag | `mlab --api-key mlab_xxx whoami` |
| Environment | `MLAB_API_KEY=mlab_xxx mlab whoami` |
| Config file | `api_key:` in `~/.mlab/conf.yml` |

The same three-step precedence applies to every host override and to the vuln
token:

| Setting | Flag | Environment | Config key |
| --- | --- | --- | --- |
| API key | `--api-key` | `MLAB_API_KEY` | `api_key` |
| vuln token | `--vuln-token` | `MLAB_VULN_TOKEN` | `vuln_token` |
| Platform host | `--hostname` | `MLAB_HOSTNAME` | `hostname` |
| CVE host | `--cve-hostname` | `MLAB_CVE_HOSTNAME` | `cve_hostname` |
| Actors host | `--actors-hostname` | `MLAB_ACTORS_HOSTNAME` | `actors_hostname` |
| Profile | `--profile` | `MLAB_PROFILE` | — |

**Prefer the environment variable to the flag.** A command line is readable by
every other process on the machine, and it lands in your shell history; an
environment variable does neither.

## The vuln CI token

Most of `vuln.mlab.sh` answers unauthenticated, so this is an optimisation, not
a requirement. What it changes is the rate limit: without it the scan quota is
counted per IP, which a fleet of CI runners behind one NAT will exhaust between
them. With it, the token gets its own.

```yaml
# ~/.mlab/conf.yml
vuln_token: <token>
```

```bash
MLAB_VULN_TOKEN=... mlab sbom scan package-lock.json --fail-on high
```

## In CI

Put the key in the job's secret store and let the environment carry it. Nothing
needs to be written to disk:

```yaml
- run: mlab sbom scan package-lock.json --fail-on high
  env:
    MLAB_VULN_TOKEN: ${{ secrets.MLAB_VULN_TOKEN }}
```

A dependency scan needs no platform key at all — only the optional token above.

## What ends up on disk

Only `~/.mlab/conf.yml`, written with mode `0600`. Credentials in it are masked
when printed:

```console
$ mlab config list
api_key   mlab…mnop
```

`--reveal` prints them in full, and nothing else does. A config dump pasted into
an issue therefore does not leak a key. See [Configuration](Configuration).
