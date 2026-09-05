# mlab-cli

![](./.github/banner.png)

`mlab` is the official command-line client for the [mlab.sh](https://mlab.sh)
threat-intelligence platform and its companion services: the CVE and dependency
scanner at [vuln.mlab.sh](https://vuln.mlab.sh) and the threat-actor database at
[actors.mlab.sh](https://actors.mlab.sh).

It scans domains, looks up IPs, analyses files, inspects SSL certificates,
checks cryptocurrency addresses and searches the CVE catalogue — from one
keyboard-driven tool, with terminal output or raw JSON for scripting.

```
$ mlab scan domain example.com
$ mlab cve detail CVE-2024-3094
$ mlab limits
```

## Install

```bash
brew tap mlab-sh/mlab-cli https://github.com/mlab-sh/mlab-cli
brew install mlab
```

Tarballs for the four supported targets, plus `.deb` and `.rpm` packages for
both Linux architectures, are on the
[releases page](https://github.com/mlab-sh/mlab-cli/releases). Nothing is
signed, so every release carries a `SHA256SUMS` covering its assets. From
source: `cargo install --path .`, Rust 1.74+.

Full instructions, including the glibc floor and checksum verification, are in
[Install](https://github.com/mlab-sh/mlab-cli/wiki/Install).

## Start here

```bash
mlab login          # verifies the key before storing it in ~/.mlab/conf.yml
mlab whoami
mlab search 8.8.8.8
```

The CVE catalogue and the actor database are public, so there is plenty to try
before you have a key:

```bash
mlab cve detail CVE-2024-3094
mlab actor get apt28
```

## Commands

| Command | What it does |
| --- | --- |
| [`search`](https://github.com/mlab-sh/mlab-cli/wiki/Search) | Work out what you pasted and route it to the lookup that owns it |
| [`scan`](https://github.com/mlab-sh/mlab-cli/wiki/Scan) | Launch a metered scan: a domain, an IP, a file, a crypto address |
| [`scan url` … `bash`](https://github.com/mlab-sh/mlab-cli/wiki/Lookups) | The cheap lookups: URL, hash, email, phone, MAC, shell script |
| [`status`](https://github.com/mlab-sh/mlab-cli/wiki/Status) | Where a running domain scan has got to |
| [`results`](https://github.com/mlab-sh/mlab-cli/wiki/Results) | Fetch a finished domain or file report |
| [`ssl`](https://github.com/mlab-sh/mlab-cli/wiki/Ssl) | The certificates a previous scan collected for a domain |
| [`ioc`](https://github.com/mlab-sh/mlab-cli/wiki/Ioc) | Pull indicators out of an email, a log or a report |
| [`network`](https://github.com/mlab-sh/mlab-cli/wiki/Network) | Every request a page makes, captured in an instrumented browser |
| [`cve`](https://github.com/mlab-sh/mlab-cli/wiki/Cve) | Search, detail, export and dump the CVE catalogue |
| [`sbom scan`](https://github.com/mlab-sh/mlab-cli/wiki/Sbom) | Scan a lockfile and fail a CI build on what it finds |
| [`vuln query`](https://github.com/mlab-sh/mlab-cli/wiki/Vuln) | One package coordinate, OSV-compatible |
| [`actor`](https://github.com/mlab-sh/mlab-cli/wiki/Actor) | Threat actors: list, detail, by-CVE, STIX, bulk export |
| [`limits`](https://github.com/mlab-sh/mlab-cli/wiki/Limits) | What is left of each scan quota |
| [`login`](https://github.com/mlab-sh/mlab-cli/wiki/Login) | Store a key, check it, or forget it |
| [`open`](https://github.com/mlab-sh/mlab-cli/wiki/Search) | Jump to the matching web report |
| [`config`](https://github.com/mlab-sh/mlab-cli/wiki/Config) | Read and edit the config file and its profiles |
| [`completions`, `man`](https://github.com/mlab-sh/mlab-cli/wiki/Completions) | Shell completions and a roff man page |
| [`module`](https://github.com/mlab-sh/mlab-cli/wiki/Modules) | Install the optional `mlab-*` modules |

## Modules

The integrations that only matter to some people live in their own repositories
and are installed on demand, so nobody downloads an async runtime and a
WebSocket stack for a feature they never run:

```bash
mlab module available
mlab module install unifi
mlab unifi --help
```

`mlab unifi …` then behaves exactly like running `mlab-unifi …` directly. The
catalogue is [`modules.json`](modules.json) in this repository — an allowlist,
since installing a module downloads and runs code. See
[Modules](https://github.com/mlab-sh/mlab-cli/wiki/Modules) for the install
pipeline, the checksum check and how to publish one.

## Documentation

The [wiki](https://github.com/mlab-sh/mlab-cli/wiki) has a page per command and
per concept:
[Hosts](https://github.com/mlab-sh/mlab-cli/wiki/Hosts) (three APIs, three
credential rules),
[Authentication](https://github.com/mlab-sh/mlab-cli/wiki/Authentication),
[Configuration](https://github.com/mlab-sh/mlab-cli/wiki/Configuration)
(the config file, profiles, global flags),
[Output](https://github.com/mlab-sh/mlab-cli/wiki/Output) (`-o json`, `-o csv`,
`--dry-run`, progress) and
[Exit codes](https://github.com/mlab-sh/mlab-cli/wiki/Exit-Codes).

Those pages live in [`wiki/`](wiki) in this repository and are mirrored to the
GitHub wiki on every push to `main`. The repository is the source of truth: a
page edited in the wiki web UI is overwritten on the next sync.

## Tests

```bash
cargo test
```

Unit tests live next to the code they cover; `tests/cli.rs` drives the real
binary against a throwaway HTTP server on an ephemeral loopback port, with an
isolated `$HOME`, so the suite needs no API key and never reaches the network.

## Releases

The **Release** workflow is a manual trigger from the Actions tab. The version
is whatever `Cargo.toml` says, so a release is a version bump, a commit and a
click — the tag, the archive names, the packages and the formula cannot
disagree with the binary they contain. A test gate (`cargo fmt --check`,
`cargo clippy -D warnings`, `cargo test --locked`) runs first; nothing is built
if any of the three fails.

The full story is in
[Releasing](https://github.com/mlab-sh/mlab-cli/wiki/Releasing).

## License

Apache-2.0 — see [LICENSE](LICENSE).
