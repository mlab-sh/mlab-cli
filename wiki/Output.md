# Output

Three formats. A terminal render by default, raw JSON with `-o json`, and CSV
with `-o csv` where a command has a genuine tabular shape.

```bash
mlab cve search openssl                       # human
mlab cve search openssl -o json | jq '.cves[].id'
mlab cve search openssl -o csv > openssl.csv
```

`--json` on a sub-command predates `--output` and still works; it is a
shorthand for the same thing, and it wins wherever both are given.

## The human render

Aligned key/value blocks, dimmed labels, a section rule, one blank line around
each block. Severity and status are coloured by meaning rather than
decoratively: a critical CVE is red, a KEV entry carries a badge, an expired
certificate is red and one lapsing within 30 days is yellow.

```
  🛡  CVE-2024-3094 🚨KEV
  ──────────────────────────────────────
  CVSS           10.0  CRITICAL
  Published      2024-03-29
```

It is the default because it is the format for reading. It is also the only one
that loses information: long descriptions are truncated and wrapped, and
nested detail is summarised rather than printed whole.

## JSON

`-o json` (or a command's own `--json`) prints what the API returned,
pretty-printed, with no colour and no truncation. It is the format to script
against and the only one that never drops a field.

```bash
mlab scan domain example.com --json > report.json
mlab cve latest --json | jq '.cves | sort_by(-.cvss_score) | .[:5] | .[].id'
mlab ioc report.txt --json | jq '.iocs.ipv4[].value'
```

## CSV

`-o csv` is offered by the commands with real rows:

| Command | Rows |
| --- | --- |
| [`limits`](Limits) | one per scan type |
| [`ssl`](Ssl) | one per certificate |
| [`cve search`](Cve), [`cve latest`](Cve) | one per CVE |
| [`actor list`](Actor) | one per actor |
| [`sbom scan`](Sbom) | one per finding |

Anywhere else it is **refused**, with a message naming the command, rather than
quietly falling back to the table:

```console
$ mlab scan domain example.com -o csv
error: scan has no CSV form — use --output json.
```

A domain report is a nested document. Flattening it into rows would produce
something a spreadsheet opens and nobody can use, which is worse than an error.
The refusal happens before the request, so it costs no quota.

Fields are escaped per RFC 4180 — quoted only when they contain a comma, a
quote or a newline, with embedded quotes doubled. `sbom scan --output csv`
emits the same columns, in the same order, as the web scan page's export.

## Progress

Long-running commands show a spinner with an elapsed timer, and a step counter
where the work is countable: [`limits`](Limits) polls four quotas, a followed
file scan reports `3/8 tools`, a followed domain scan tracks the API's own state
from `queued` to `scanning` to `done`.

Three rules keep it out of your data:

1. **Progress goes to stderr, results go to stdout.** `mlab scan domain x --json
   | jq` is a clean stream; nothing animated ever lands in it.
2. **Nothing is animated unless stderr is a terminal.** Pipes, redirects, CI
   logs and test harnesses get plain output with no escape sequences.
3. **Nothing is drawn for fast work.** The spinner appears only once a call has
   run past 300 ms, so a quick lookup does not flash.

Turn it off with `-q`/`--quiet` or `MLAB_NO_PROGRESS=1` — both silence the
status lines as well as the animation.

Setting `CI` turns off only the *animation*. Build logs still get the messages,
because a warning nobody sees is not a warning.

```bash
mlab -q scan domain example.com --json > report.json
MLAB_NO_PROGRESS=1 mlab limits
```

`--quiet` silences progress only. Errors always print.

## Errors

Errors go to stderr with a red `error:` prefix, and carry a hint when the cause
is a known one:

```
error: quota exhausted for domain scans
hint: See what is left with `mlab limits`.
```

The exit code says which kind it was — see [Exit codes](Exit-Codes).
