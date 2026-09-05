# `mlab cve`

The CVE catalogue on `vuln.mlab.sh`. **Public** — every sub-command here works
on a machine that has never run `mlab login`.

```bash
mlab cve detail CVE-2024-3094
mlab cve search openssl --severity HIGH
mlab cve latest
```

| Sub-command | Path | What it does |
| --- | --- | --- |
| `search <query>` | `/api/v1/cve` | Keyword search with the full filter set |
| `detail <id>` | `/api/v1/cve/<id>` | One CVE in full |
| `latest` | `/api/v1/cve/latest` | A fixed window of recent publications |
| `export <query>` | `/export/csv`, `/rss` | The same search, as CSV or a feed |
| `dump` | `/api/v1/cve/dump` | Bulk extract, rate limited per IP |
| `stats` | `/api/v1/stats` | Database statistics |
| `sources` | `/api/v1/sources` | The advisory sources being ingested |
| `advisories` | `/api/v1/advisories` | National advisories, optionally for one CVE |
| `vendor <name>` | `/api/v1/vendor/<name>/months` | Per-month counts for a vendor |

Not everything sits under `/api/v1`: the CSV export and the RSS feed live at the
site root. The paths a Node SDK documents under `/api/v1` for those two do not
exist.

## `search`

```bash
mlab cve search openssl --severity HIGH
mlab cve search "remote code execution" --date-start 2026-01-01 --exact
mlab cve search apache --vendor redhat --min-cvss 7.5 --kev-only
mlab cve search xss --cwe CWE-79 --page 1 --limit 50
```

| Filter | Description |
| --- | --- |
| `--severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `--date-start`, `--date-end` | Published within a window, `YYYY-MM-DD` |
| `--vendor` | Narrow to a vendor (merged into the keyword server-side) |
| `--cwe` | Weakness, e.g. `CWE-79` |
| `--min-cvss` | Only CVEs scoring at least this (0–10) |
| `--kev-only` | Only entries in the CISA KEV catalogue |
| `--exact` | Exact-match rather than fuzzy |
| `--page` | Result page, **0-based** |
| `--limit` | Results per page, max 100 |

Paging is server-side and the CLI tells you when more pages exist, so a search
that looks short is never silently truncated.

```
  CVE-2024-3094 [CRITICAL] CVSS 10.0 2024-03-29 🚨KEV
    Malicious code was discovered in the upstream tarballs of xz…
```

## `detail`

```bash
mlab cve detail CVE-2024-3094
mlab cve detail CVE-2024-3094 --json
```

CVSS score and vector, EPSS probability, CISA KEV status, weaknesses (CWE) and
references — the whole record.

## `latest`

```bash
mlab cve latest
mlab cve latest -o csv
```

Recent publications. It takes no filters: the endpoint returns a fixed window,
and pretending otherwise would mean filtering client-side and reporting a count
that means nothing.

## `export`

```bash
mlab cve export openssl --severity HIGH --format csv > openssl.csv
mlab cve export "" --kev-only --format rss
```

The same filter set as `search`, written to stdout as CSV or as an RSS feed.
The query may be empty, which is how you export a filter rather than a search —
every KEV entry, say.

This is a different thing from `search -o csv`: `export` is the server's own
export, `-o csv` is the CLI rendering search results.

## `dump`

```bash
mlab cve dump --date-start 2026-01-01 --min-cvss 7 > cves.json
```

The bulk extract, with its own smaller filter set: `--date-start`,
`--date-end`, `--min-cvss`.

It is the heaviest anonymous route on the host and is rate limited per IP. A
`429` carrying a short `Retry-After` is waited out; a long one is reported as a
quota error (exit `3`) rather than the CLI silently sleeping for minutes.

If you are hitting that limit from CI, a [vuln token](Authentication) gives the
runner its own quota instead of sharing the egress IP's.

## The rest

```bash
mlab cve stats
mlab cve sources
mlab cve advisories --cve CVE-2024-3094
mlab cve advisories --country fr --limit 20
mlab cve vendor microsoft --year 2026
```

`stats` and `sources` describe the database itself — how much is in it and
where it came from. `advisories` returns national advisories, filtered by CVE
or by country. `vendor` charts per-month counts for one vendor and one year.

## Output

`--json` everywhere. `-o csv` on `search` and `latest` only; the other
sub-commands refuse it rather than inventing rows, and say so:

```console
$ mlab cve stats -o csv
error: this cve sub-command has no CSV form — use --output json.
```

See [Output](Output).
