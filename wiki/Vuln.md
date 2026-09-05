# `mlab vuln query`

One package coordinate, OSV-compatible.

```bash
mlab vuln query pkg:cargo/time --version 0.1.0
mlab vuln query npm/lodash --version 4.17.11
mlab vuln query crates.io/time
```

The coordinate is either a purl (`pkg:cargo/time`) or an `ecosystem/name` pair.
`--version` narrows to the advisories that actually affect that release; without
it you get everything known for the package.

Answers on `vuln.mlab.sh`, which is public — no key required. The optional
[vuln token](Authentication) raises the rate limit, nothing else.

## An empty result is an answer

```
No known vulnerabilities.
```

That is a real finding, not a failure, and it exits `0`. An upstream outage is
an error and exits non-zero. The two are never collapsed into the same silence:
"we did not look" must not read as "there is nothing there".

The same rule governs [`sbom scan`](Sbom) at lockfile scale, where it is what
keeps a broken scanner from turning a build green.

## When to use it instead of `sbom scan`

`vuln query` is the interactive one — you are looking at a single dependency
and want to know about it now:

```bash
mlab vuln query pkg:npm/lodash --version 4.17.11 --json | jq '.vulns[].id'
```

[`sbom scan`](Sbom) is the CI one: a whole lockfile, in one request, with a
severity gate. Reaching for `vuln query` in a loop over your dependencies is
slower, spends more quota and has no gate.

## Output

`--json` gives the OSV-shaped payload. `-o csv` is refused — one coordinate's
advisories are a nested document, not a table. See [Output](Output).
