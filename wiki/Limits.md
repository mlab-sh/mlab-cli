# `mlab limits`

What is left of each scan quota.

```bash
mlab limits            # all four
mlab limits domain     # one
mlab limits ip --raw   # just the number
```

```
  🌐 Domain scans  ████████████████████ 98 / 100 remaining
  🔍 IP lookups    ████████████████···· 412 / 500 remaining
  📄 File scans    █████████··········· 12 / 25 remaining
  🪙 Crypto lookups ████████████████████ 50 / 50 remaining
```

Four quotas: `domain`, `ip`, `file` and `crypto` — one per metered thing
[`scan`](Scan) can do. Naming one shows only that one; naming nothing polls all
four, and the spinner counts them off as they land.

## `--raw`

```bash
mlab limits ip --raw
```

Prints the remaining count and nothing else, so it drops straight into a
condition:

```bash
if [ "$(mlab limits domain --raw)" -lt 5 ]; then
  echo "nearly out of domain scans" >&2
fi
```

## What counts against them

Only the metered commands. The [lookups](Lookups) that share the `scan` verb —
`url`, `hash`, `email`, `phone`, `mac`, `bash` — and everything on
`vuln.mlab.sh` and `actors.mlab.sh` are outside this accounting entirely; see
[Hosts](Hosts).

A bulk call spends one unit per item, not one per request. `mlab scan crypto a
b c` is one request and three crypto lookups.

An unknown type is refused before anything is sent:

```console
$ mlab limits dns
Unknown limit type: dns. Use: domain, ip, file, or crypto.
```

## When quota runs out

Commands fail with exit `3` and a hint pointing back here:

```
error: quota exhausted for domain scans
  See what is left with `mlab limits`.
```

`--dry-run` is the way to check what a command would do without spending
anything — see [Hosts](Hosts).

## Output

```bash
mlab limits -o csv
```

```
scan_type,remaining,total
domain,98,100
ip,412,500
```

A quota that could not be read shows as `error` in both columns rather than as
a zero, because a zero here reads as "exhausted" and would be a lie.

`--json` gives the API's own shape, one object per quota.
