# `mlab network`

Capture every request a page makes.

```bash
mlab network https://example.com
mlab network https://example.com --json
```

```
  🌐 Network Capture  https://example.com
```

The URL is loaded in an instrumented browser upstream, and the command lists
what that load pulled in: each request with its status, resource type, size and
whatever failed.

## What it is for

The third-party inventory of a page, without opening devtools and without
loading the page on your own machine. What a marketing site actually calls at
runtime, which CDN a script really comes from, what a checkout page reaches for
before you have entered anything.

It pairs with [`scan url`](Lookups), which analyses the URL and its host
statically. `network` answers the different question of what happens when
someone opens it.

## It is the slowest command in the CLI

A real browser loads the page upstream, so this takes seconds where a lookup
takes milliseconds. The spinner says `Loading … in a browser` for exactly that
reason. `--timeout` raises the HTTP ceiling if a heavy page needs it.

## It does load the page

Server-side, not from your machine — but it *is* a real load, with whatever that
implies for a hostile URL: it fetches the target, executes its scripts, and
follows what they ask for.

That is the whole function of the command, so the point is not to be careful
with it but to know what you are asking for. [`scan url`](Lookups) without
`--resolve` is the version that does not touch the target.

## Output

`--json` gives the request list in full — the form to script against:

```bash
mlab network https://example.com --json | jq -r '.requests[].url' | sort -u
mlab network https://example.com --json \
  | jq -r '.requests[] | select(.status >= 400) | "\(.status) \(.url)"'
```

`-o csv` is refused. See [Output](Output).
