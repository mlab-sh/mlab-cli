# mlab

**The official command-line client for the mlab.sh threat-intelligence
platform.**

`mlab` talks to three hosts: the platform itself at `mlab.sh`, the CVE and
dependency scanner at `vuln.mlab.sh`, and the threat-actor database at
`actors.mlab.sh`. One binary, one config file at `$HOME/.mlab/conf.yml`, one
credential model — see [Hosts](Hosts) for which command reaches which.

Everything renders for a terminal by default and as raw JSON on demand, so the
same command serves an investigation and a pipeline.

---

## The commands

| Command | What it does |
| --- | --- |
| [`search`](Search) | Work out what you pasted and route it to the lookup that owns it. Start here. |
| [`scan`](Scan) | Launch a metered scan: a domain, an IP, a file, a crypto address. |
| [`scan url` … `bash`](Lookups) | The cheap lookups: URL, hash, email, phone, MAC, shell script. |
| [`status`](Status) | Where a running domain scan has got to. |
| [`results`](Results) | Fetch a finished domain or file report. |
| [`ssl`](Ssl) | The certificates a previous scan collected for a domain. |
| [`ioc`](Ioc) | Pull indicators out of an email, a log or a report. |
| [`network`](Network) | Every request a page makes, captured in an instrumented browser. |
| [`cve`](Cve) | Search, detail, export and dump the CVE catalogue. |
| [`sbom scan`](Sbom) | Scan a lockfile and fail a CI build on what it finds. |
| [`vuln query`](Vuln) | One package coordinate, OSV-compatible. |
| [`actor`](Actor) | Threat actors: list, detail, by-CVE, STIX, bulk export. |
| [`limits`](Limits) | What is left of each scan quota. |
| [`login`](Login) | Store a key, check it, or forget it. |
| [`open`](Search) | Jump to the matching web report. |
| [`config`](Config) | Read and edit the config file and its profiles. |
| [`completions`, `man`](Completions) | Shell completions and a roff man page. |

## Key concepts

- **[Hosts](Hosts)** — three APIs with three different credential rules.
  Knowing which one a command uses explains most of its behaviour, including
  why some commands work with no key at all.
- **[Authentication](Authentication)** — the API key, the separate
  `vuln.mlab.sh` CI token, and the precedence between flag, environment and
  file.
- **[Configuration](Configuration)** — `~/.mlab/conf.yml`, profiles, and what
  the tool writes to disk.
- **[Output](Output)** — the terminal render, `-o json`, `-o csv` where it is
  honest, and the rules that keep progress out of a pipe.
- **[Exit codes](Exit-Codes)** — the API reports quota, maintenance and bad
  input all as HTTP 400; the CLI turns that into a code you can branch on.
- **[Releasing](Releasing)** — how a version becomes a Homebrew formula, a
  `.deb`, an `.rpm` and a set of tarballs.

## Getting started

```bash
brew tap mlab-sh/mlab-cli https://github.com/mlab-sh/mlab-cli
brew install mlab
mlab login
mlab whoami
```

There are `.deb` and `.rpm` packages and tarballs for every target on the
[releases page](https://github.com/mlab-sh/mlab-cli/releases) too. See
[Install](Install).

Nothing needs a credential to try: the CVE catalogue and the actor database are
public.

```bash
mlab cve detail CVE-2024-3094
mlab actor get apt28
```

## Scope

The CLI is a client. It does not cache, it does not keep a local database, and
apart from the config file it writes nothing to disk that you did not redirect
there yourself. The one command that reaches a target rather than an API is
[`network`](Network), and even that runs server-side.
