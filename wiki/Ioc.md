# `mlab ioc`

Pull indicators of compromise out of text.

```bash
cat incident-report.txt | mlab ioc
mlab ioc report.txt --country fr --risk deep
mlab ioc - --json | jq '.iocs.ipv4[].value'
```

It reads stdin by default, which is the point: pipe an email, a log line, a
ticket or a whole report at it and get back what is in there, grouped by kind —
IPv4 and IPv6, domains, URLs, hashes, emails, wallets.

```
  🧾 Indicators  report.txt
```

The argument is a file path, or `-` for stdin. Empty input fails locally with
exit `4` rather than posting nothing to the API.

## `--risk`

| Value | What it does |
| --- | --- |
| `fast` | Scores what was extracted, locally, from the shape of each indicator |
| `deep` | Adds network checks against the platform's data |

`deep` is the slow one — it leaves the process and reaches out per indicator, so
a long report takes a while. The spinner says which mode is running so a slow
command is never a mysterious one.

Omit the flag entirely and you get extraction without scoring, which is the
fastest way to answer "what is even in this file".

## `--country`

```bash
mlab ioc sms.txt --country fr
```

Loads a country pack of smishing keywords, so the local-language lures in an
SMS campaign are recognised as well as the indicators. `fr`, `uk` and the other
supported codes; without it, extraction is language-neutral.

## Scripting it

The JSON is grouped by indicator type, which makes a one-liner out of most of
what you would otherwise write by hand:

```bash
mlab ioc report.txt --json | jq -r '.iocs.ipv4[].value' | sort -u
mlab ioc report.txt --json | jq -r '.iocs.domain[].value' > domains.txt
```

Feeding those back into a lookup closes the loop:

```bash
mlab ioc report.txt --json | jq -r '.iocs.ipv4[].value' \
  | while read ip; do mlab scan ip "$ip" --json; done
```

Each of those spends IP-lookup quota — check it with [`limits`](Limits) before
turning a hundred-indicator report loose.

## Output

`--json` is the useful form here and the reason the command exists. `-o csv` is
refused: the result is several lists of different shapes, not one table. See
[Output](Output).
