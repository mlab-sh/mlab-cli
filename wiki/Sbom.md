# `mlab sbom scan`

Scan a dependency lockfile for known vulnerabilities, and fail a CI build on
what it finds.

```bash
mlab sbom scan package-lock.json
mlab sbom scan Cargo.lock --fail-on high
mlab sbom scan Cargo.lock web/package-lock.json api/go.sum --fail-on high
mlab sbom scan --url https://raw.githubusercontent.com/o/r/main/go.sum
cat requirements.txt | mlab sbom scan - --format pip
```

Answers on `vuln.mlab.sh`, which is public: no platform key needed. A
[vuln token](Authentication) is optional and buys larger scans, not access.

Lockfiles and SBOMs the server reads: `package-lock.json`, `npm-shrinkwrap.json`,
`yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `requirements.txt` (`==` pins),
`poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `composer.lock`,
`Gemfile.lock`, `go.sum`, `pom.xml`, `gradle.lockfile`, `packages.lock.json`,
`pubspec.lock`, `mix.lock`, `mise.lock`, CycloneDX (JSON or XML) and SPDX (JSON
or tag-value). An SBOM component without a purl is matched by its CPE.

## Limits

| | Packages per scan | Request size | Cooldown between scans |
| --- | --- | --- | --- |
| Anonymous (per IP) | 512 | 4 MiB | 10 s |
| Free account, with a token | 1024 | 8 MiB | 5 s |
| Paid plan, with a token | 4096 | 32 MiB | none |

The tier and its limits are printed with each scan. Scanning several lockfiles
in a row runs into the cooldown by design: the server refuses with a 429 and
says how long to wait, and the CLI waits and sends the same file again (a
refusal spent nothing). A wait longer than 30 s is reported instead, with the
server's explanation and what the next tier unlocks; so is a file over the size
limit.

## Three ways in

| Form | What happens |
| --- | --- |
| `mlab sbom scan <path>` | The file is sent as the request body |
| `mlab sbom scan -` | Same, reading stdin |
| `mlab sbom scan --url <url>` | The server fetches and parses the lockfile itself |

The lockfile goes up **as-is** and the format is detected server-side, so the
CLI never has to learn a manifest format — and never falls behind one. `--format`
forces it when detection needs help, which is mostly when the content arrived on
stdin with no filename to go on.

Giving neither a path nor `--url` is an error, not a silent scan of nothing.

## Several lockfiles at once

Paths can be repeated, and so can `--url`; both can be mixed. Each manifest is
scanned and rendered in turn, and `--fail-on` is evaluated **once, at the end**,
across all of them — so one failing lockfile never hides what the others would
have found. With `--json`, a single manifest keeps its usual object; several
come out as a JSON array, one object per manifest. `-o csv` emits a single
table covering every file.

## `--fail-on`

```bash
mlab sbom scan package-lock.json --fail-on high
```

Exits `7` when a finding reaches that severity — `critical`, `high`, `medium`
or `low`. That is the whole point in CI:

```yaml
- run: mlab sbom scan package-lock.json --fail-on high
```

Severity comes from the advisory's CVSS v3 vector, scored with the same formula
the web UI uses, so the CLI fails on exactly what the site paints red. An
unknown severity name is refused up front, before the scan runs.

Exit `7` is not an error code — see [Exit codes](Exit-Codes). It means the scan
worked and found something bad enough.

## An incomplete scan never passes the gate

The API distinguishes things the CLI keeps distinct:

1. this package has no known vulnerabilities;
2. this package **could not be scanned**;
3. an upstream advisory source is down;
4. the manifest had more packages than your tier scans, and the rest were cut.

Only the first is a clean result. When any of the others happens, `--fail-on`
exits non-zero with the reason (for a cut manifest, the server's own sentence)
rather than reporting a clean build:

```
scan incomplete, so --fail-on high cannot be evaluated:
  3 package(s) could not be scanned — that is not the same as finding nothing.
```

A scan that did not look is not a scan that found nothing, and a build that
goes green because the scanner was broken is the failure mode this rule exists
to prevent.

Entries the server could not turn into a package at all (a git or path
dependency, an unpinned requirement, the Flutter SDK listed in every
`pubspec.lock`, an SBOM component with neither purl nor CPE) are printed as a
warning and are not counted as clean, but they do not fail the gate: some can
never be scanned, and a gate that always fails ends up switched off.

## `--json`

```bash
mlab sbom scan package-lock.json --fail-on high --json > findings.json
```

Keeps the raw payload on stdout **and** still applies the gate. A CI job that
asked for machine-readable output would otherwise silently stop failing, which
is the worst of both.

## `-o csv`

```bash
mlab sbom scan Cargo.lock -o csv > findings.csv
```

```
package,version,ecosystem,advisory,cve,cvss,severity,fixed,summary
time,0.1.44,crates.io,RUSTSEC-2020-0071,CVE-2020-26235,6.2,MEDIUM,0.2.23,Potential segfault…
```

The same columns, in the same order, as the web scan page's export — so a
spreadsheet built on one works on the other.

## Related

[pre-commit](Pre-commit) runs this command as a git hook on every commit that
touches a lockfile.

[`vuln query`](Vuln) asks the same database about a single package coordinate
rather than a whole lockfile.
