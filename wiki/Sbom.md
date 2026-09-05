# `mlab sbom scan`

Scan a dependency lockfile for known vulnerabilities, and fail a CI build on
what it finds.

```bash
mlab sbom scan package-lock.json
mlab sbom scan Cargo.lock --fail-on high
mlab sbom scan --url https://raw.githubusercontent.com/o/r/main/go.sum
cat requirements.txt | mlab sbom scan - --format pip
```

Answers on `vuln.mlab.sh`, which is public: no platform key needed. A
[vuln token](Authentication) is optional and buys quota, not access.

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

The API distinguishes three things the CLI keeps distinct:

1. this package has no known vulnerabilities;
2. this package **could not be scanned**;
3. an upstream advisory source is down.

Only the first is a clean result. When either of the others happens,
`--fail-on` exits non-zero with the reason rather than reporting a clean build:

```
scan incomplete, so --fail-on high cannot be evaluated:
  3 package(s) could not be scanned — that is not the same as finding nothing.
```

A scan that did not look is not a scan that found nothing, and a build that
goes green because the scanner was broken is the failure mode this rule exists
to prevent.

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

[`vuln query`](Vuln) asks the same database about a single package coordinate
rather than a whole lockfile.
