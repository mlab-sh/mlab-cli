# `mlab status`

Where a running domain scan has got to.

```bash
mlab status domain example.com
mlab status domain example.com --json
```

```
  🌐 example.com  ⏳ scanning
```

Once it is finished the command says what to run next:

```
  🌐 example.com  ✔ done
  Fetch it with: mlab results domain example.com
```

| Badge | API status |
| --- | --- |
| `⏳ queued` | `pending` |
| `⏳ scanning` | `scanning` |
| `✔ done` | `success` |
| `✖ failed` | `failed`, `fail`, `error` |

An unrecognised status is printed as-is rather than mapped to a badge that
might be wrong.

## When you need it

You do not, for a scan you launched normally: `mlab scan domain example.com`
follows the scan itself and prints the report when it lands. `status` is for
the other cases —

- a scan launched with `--no-follow`;
- a scan launched in another shell, or by someone else on the same account;
- a `scan domain` that hit its `--max-wait` budget and gave up while the scan
  itself kept running.

It reads `GET /api/v1/scan/domain/status` and costs no scan quota.

## Scripting it

```bash
until [ "$(mlab status domain example.com --json | jq -r .status)" = success ]; do
  sleep 30
done
mlab results domain example.com --json > report.json
```

Though for that particular shape, `mlab scan domain example.com --json` already
does the waiting, with backoff and a timeout. See [scan](Scan).

`-o csv` is refused: one status is not a table. See [Output](Output).
