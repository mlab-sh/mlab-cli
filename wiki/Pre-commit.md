# pre-commit

Run [`sbom scan`](Sbom) on every commit that touches a lockfile, and refuse the
commit when a finding reaches the severity you set. The hook lives in this
repository, so `rev:` is a CLI release tag: the hook and the binary it runs
cannot disagree.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/mlab-sh/mlab-cli
    rev: v1.1.1
    hooks:
      - id: mlab-sbom-scan
```

```bash
pre-commit install
```

Nothing else. No key is needed: `vuln.mlab.sh` is public (see [Hosts](Hosts)).

## Two hooks, one scan

| Hook | Where `mlab` comes from | First run |
| --- | --- | --- |
| `mlab-sbom-scan` | pre-commit builds it from this repository at `rev` | ~2 minutes, then cached |
| `mlab-sbom-scan-system` | the `mlab` already on your `PATH` | instant |

`mlab-sbom-scan` needs nothing installed beforehand: pre-commit uses your
`cargo` if there is one, and bootstraps a Rust toolchain into its own cache if
not. The build is slow once because the release profile uses full LTO.

`mlab-sbom-scan-system` is for machines that already have the CLI from
[Homebrew or a package](Install). The version is then whatever you installed,
not `rev`.

## When it runs

Only when a staged file matches one of these names, in any directory:

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json` |
| crates.io | `Cargo.lock` |
| Packagist | `composer.lock` |
| RubyGems | `Gemfile.lock` |
| Go | `go.sum` |
| CycloneDX | `bom.json`, `*.cdx.json` |

A commit that touches none of them skips the hook entirely: no process, no
request. When several match, they go to one `mlab sbom scan` invocation and
`--fail-on` is judged once across all of them, so one bad lockfile never hides
what the others found.

### What is left out, and why

The pattern names only what the server parses correctly. Matching a file it
cannot read would block the commit on exit `4`, or pass it on a wrong parse:

- `poetry.lock` and `uv.lock` are currently read as `Cargo.lock`, so every
  Python package is looked up on crates.io and comes back clean. Left out until
  that is fixed server-side.
- `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock` and `mise.lock` are not parsed
  yet.
- `requirements*.txt` is parsed only when every line is pinned with `==`. A file
  of ranges fails with "no dependencies parsed". If yours are fully pinned, opt
  in:

```yaml
      - id: mlab-sbom-scan
        files: '(^|/)(Cargo\.lock|package-lock\.json|requirements[^/]*\.txt)$'
```

## Choosing the threshold

The default is `--fail-on high`. Override it with `args`:

```yaml
      - id: mlab-sbom-scan
        args: [--fail-on, critical]
```

`critical`, `high`, `medium` or `low`, scored from the CVSS v3 vector exactly as
the web UI does. An advisory without a vector (an "unmaintained" notice, say) shows
as `unknown` and does not trip `--fail-on high`.

## What blocks a commit

| Exit | Meaning | What to do |
| --- | --- | --- |
| `0` | Nothing at or above the threshold | — |
| `7` | A finding reached the threshold | Upgrade to the *Fixed in* version |
| `3` | Rate limited | Wait a few seconds and commit again, or set a [vuln token](Authentication) |
| `1` | Network failure | See below |
| other | See [Exit codes](Exit-Codes) | |

An incomplete scan never passes: if a package could not be scanned or an
advisory source is down, the hook fails with the reason rather than letting the
commit through looking clean. The same holds offline. When you have to commit
anyway, skip the hook for that one commit:

```bash
git commit --no-verify
```

That is the point of a pre-commit hook being a local guard rather than a
control: the gate that cannot be skipped is the same command in CI.

```yaml
- run: mlab sbom scan package-lock.json --fail-on high
```

## Rate limits

Without a token the scan quota is counted per IP. Set `MLAB_VULN_TOKEN` in your
shell profile to get your own, which matters when many developers commit from
behind one office NAT:

```bash
export MLAB_VULN_TOKEN=...
```

See [Authentication](Authentication). Never put the token in
`.pre-commit-config.yaml`: that file is committed.

## Pinning

A tag can be moved. To pin the exact commit behind it, let pre-commit rewrite
`rev` to a SHA with the tag as a comment:

```bash
pre-commit autoupdate --freeze
```

## Trying it without installing

```bash
pre-commit try-repo https://github.com/mlab-sh/mlab-cli mlab-sbom-scan --all-files
```
