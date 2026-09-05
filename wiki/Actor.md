# `mlab actor`

Threat-actor intelligence from `actors.mlab.sh`. **Public and read-only** — no
credential is sent and none is accepted.

```bash
mlab actor list --origin Russia --sector Government
mlab actor get apt28
mlab actor by-cve CVE-2023-23397
mlab actor stix apt28 > apt28.stix.json
mlab actor export --format jsonl > actors.jsonl
```

| Sub-command | Path | What it does |
| --- | --- | --- |
| `list` | `/api/v1/actors` | Filtered, paged listing |
| `get <slug>` | `/api/v1/actors/<slug>` | One actor in full |
| `by-cve <cve>` | `/api/v1/cves/<cve>/actors` | Who is documented exploiting it |
| `stix <slug>` | `/actors/<slug>.stix.json` | STIX 2.1 bundle |
| `export` | `/export/actors.{csv,jsonl}` | Every actor, in bulk |

## `list`

```bash
mlab actor list --origin Russia
mlab actor list --sector Government --motivation "Information theft and espionage"
mlab actor list --updated-since 2026-01-01T00:00:00Z
mlab actor list --limit 100 --offset 200
```

| Filter | Description |
| --- | --- |
| `--origin` | Suspected country of origin |
| `--motivation` | e.g. `Information theft and espionage` |
| `--sector` | Targeted sector |
| `--updated-since` | Only actors changed since this ISO timestamp |
| `--limit` | Page size, max 500 |
| `--offset` | Page offset |

`--country` is accepted as an alias for `--origin`. `origin` is the name the
API actually reads, and the one the docs use; `--country` is there because it
is what everyone types first.

`-o csv` gives one row per actor: `slug`, `name`, `origin`, `motivation`,
`sectors`, `countries`.

## `get`

```bash
mlab actor get apt28
mlab actor get apt28 --json
```

The full card for one actor by slug: names and aliases, origin, motivations,
sectors and countries targeted, tools, and the CVEs it is documented using.

## `by-cve`

```bash
mlab actor by-cve CVE-2023-23397
```

Which actors are documented exploiting a given CVE — the join that turns a
vulnerability you are patching into a question about who is likely to use it.

**The identifier is validated locally**, so a typo costs no request:

```console
$ mlab actor by-cve CVE-23397
error: 'CVE-23397' is not a CVE identifier — expected CVE-YYYY-NNNN.
```

Case does not matter; `cve-2023-23397` is fine.

## `stix` and `export`

```bash
mlab actor stix apt28 > apt28.stix.json
mlab actor export --format jsonl > actors.jsonl
mlab actor export --format csv > actors.csv
```

`stix` emits a STIX 2.1 bundle for one actor, for loading into a platform that
speaks it. `export` is the whole dataset — `csv` (the default) or `jsonl`, one
object per line, which is the form to stream into a database.

Both write to stdout, so redirect them.

## Attribution

The dataset comes from **ETDA Threat Group Cards** and **MITRE ATT&CK**, under
CC BY-NC-SA 4.0. Every rendered view carries that attribution, and it applies
to anything you build on the exports too — the licence is non-commercial and
share-alike.
