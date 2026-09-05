# Exit codes

The platform answers HTTP `400` for almost everything that goes wrong — quota
exhausted, maintenance window, malformed domain — with the reason in the body
rather than in the status. Printing `HTTP 400` and the raw JSON would push that
classification onto every caller, so the CLI does it once and hands you a code
to branch on.

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Generic failure — network, TLS, unreadable response |
| `2` | Authentication — missing, rejected or unrecognised key |
| `3` | Quota exhausted or rate limited |
| `4` | Invalid input — bad domain, unreadable file, unsupported type |
| `5` | Platform in maintenance |
| `6` | Nothing found — no scan for that domain, unknown hash |
| `7` | A `--fail-on` gate matched: the scan worked, and found something bad enough |

```bash
mlab scan domain example.com || case $? in
  3) echo "out of quota" ;;
  5) echo "maintenance, retry later" ;;
esac
```

## 7 is not an error

Codes 1 to 6 mean the command did not get its answer. `7` means it did: the
[dependency scan](Sbom) ran, and what it found reached the severity you set
with `--fail-on`. That is the whole point in CI.

```yaml
- run: mlab sbom scan package-lock.json --fail-on high
```

`--json` keeps the raw payload on stdout *and* still applies the gate, so a
pipeline can both record the findings and fail on them.

## An incomplete scan never passes the gate

The API distinguishes "this package has no known vulnerabilities" from "this
package could not be scanned", and reports upstream outages explicitly. When
either happens, `--fail-on` exits non-zero with the reason rather than
reporting a clean build.

A scan that did not look is not a scan that found nothing. The same rule
governs [`vuln query`](Vuln): an empty result is a real answer, an upstream
outage is an error, never silence.

## Hints

Three of the codes carry a hint on stderr, because the next command is
predictable:

| Code | Hint |
| --- | --- |
| `2` | Check your key with `mlab whoami`, or set a new one with `mlab login`. |
| `3` | See what is left with `mlab limits`. |
| `5` | The platform is in maintenance — retry in a few minutes. |

## What the message says

The reason comes from the response body — the `error` or `message` field —
rather than the status line. The status is only printed when the server gave
nothing better:

```
error: the API answered HTTP 502
```

Everything goes to stderr, so a failing command still leaves stdout clean for
whatever was going to parse it.
