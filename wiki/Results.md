# `mlab results`

Fetch a report a scan already produced. Nothing here launches anything, so
nothing here spends scan quota.

```bash
mlab results domain example.com
mlab results file <sha256>
mlab results file <sha256> --tool strings
```

`--json` is accepted before or after the sub-command — `mlab results --json
domain example.com` and `mlab results domain example.com --json` are the same
command, matching how `scan … --json` reads.

## `results domain`

```bash
mlab results domain example.com
mlab results domain example.com --json > report.json
```

The full report from `GET /api/v1/scan/domain/results`: DNS, hosting, exposed
services, certificates, and whatever else the scan collected.

If no scan exists for that domain the command exits `6` — nothing found — which
is a different thing from a scan that ran and found nothing. Launch one with
[`scan domain`](Scan).

## `results file`

```bash
mlab results file e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The analysis for an uploaded file, keyed on the sha256 that
[`scan file`](Scan) printed. The summary lists each tool and its verdict, plus
how many have finished:

```
  📄 File Scan Results  [✔ done]
```

While the analysis is still running, the same command shows the tools that have
reported so far — it is a snapshot, not a wait. `mlab scan file <path> --follow`
is the version that waits.

### `--tool`

```bash
mlab results file <sha256> --tool strings
```

One tool's raw output, fetched on demand from
`GET /api/v1/scan/file/output`. The summary deliberately omits it: a full
`strings` dump is not something to print by accident, and pulling it is a second
request that most readings do not need.

## Output

`-o csv` is refused for both sub-commands. A scan report is a nested document,
and flattening it into rows would produce something a spreadsheet opens and
nobody can use — [Output](Output) explains the rule.

`--json` prints exactly what the API returned, which is the only form that
keeps every field. The human render truncates long values and summarises nested
detail.
