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
mlab results domain example.com --legacy
```

The v2 report from `GET /api/v1/scan/domain/report` (`schema:
"domain-report/2"`): the whole scan, the same one the web page shows. The
terminal render reads top to bottom:

1. **Score** out of 100 and its grade (not graded while the scan is running).
2. **Findings**, worst first, with their section — the first 25, `--json` for
   all of them.
3. **Registration** (registrar, age, expiry), **DNS** (NS, MX, DNSSEC, CAA,
   SaaS seen in TXT), **Mail** (grade, SPF, DMARC, DKIM, BIMI, TLS-RPT),
   **Web** (HTTP, TLS, missing headers, CVEs on the detected software),
   **Certificates** (CT history and the latest ones), **Attack surface**
   (subdomains, suspicious names, hosts visited, technologies, takeover
   candidates, registered lookalikes).

A section the scan predates is simply left out. `--json` prints the v2 report
exactly as the API returned it.

The report's own `status` decides how the command ends:

| Status | Outcome |
| --- | --- |
| `completed` | rendered, exit `0` |
| `partial` | rendered with a warning: some checks did not finish, exit `0` |
| `in_progress` | rendered with a warning, not graded, exit `0` |
| `failed` | rendered (or printed with `--json`), then an error, exit `1` |

### `--legacy`

The v1 payload from `GET /api/v1/scan/domain/results`: subdomains, DNS resolve
and TXT, CT certificates and the two well-known files. The server keeps it
**frozen** for existing integrations and no longer extends it, so use it only to
keep a script that parses the v1 shape working. It is the output `mlab` 1.2 and
earlier printed by default.

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
