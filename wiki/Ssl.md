# `mlab ssl`

The certificates a previous scan collected for a domain.

```bash
mlab ssl example.com
mlab ssl example.com --json
mlab ssl example.com -o csv > certs.csv
```

```
  🔒 Found 3 certificate(s) for example.com

  COMMON NAME                    NOT BEFORE     NOT AFTER                 ISSUER
  example.com                    2026-01-14     2026-04-14                R11
  *.example.com                  2025-11-02     2026-02-01 (expired)      R10

  ● = valid   ● = expires within 30 days   ● = expired
```

## It reads, it does not connect

The endpoint returns what a previous scan stored, so the command answers
instantly and costs no scan quota — but a domain nobody has ever scanned has
nothing to return. Run [`scan domain`](Scan) first:

```bash
mlab scan domain example.com
mlab ssl example.com
```

The domain report shows the same certificates inline, so `ssl` is the view you
want when the certificates are the whole question.

## Expiry

Computed against the current date, at three levels:

| Colour | Meaning |
| --- | --- |
| green | valid |
| yellow | expires within 30 days |
| red | expired |

That is the reason this command exists as its own view rather than a section of
the report: a wall of dates tells you nothing, and a red line tells you what to
renew this week.

## CSV

```bash
mlab ssl example.com -o csv
```

```
common_name,not_before,not_after,issuer,serial
example.com,2026-01-14,2026-04-14,R11,03:9a:…
```

One row per certificate, dates trimmed to the day and the issuer shortened to
its common name. `--json` keeps the full issuer DN and every field the API
returned.
