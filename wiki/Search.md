# `mlab search` and `mlab open`

One entry point for "I have a value and I do not want to think about which
command owns it".

```bash
mlab search 8.8.8.8
mlab search abuse@example.com
mlab search CVE-2024-3094
mlab search 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
```

```
Detected IP address — routing to it
  🔍 IP Lookup  8.8.8.8
```

It says what it detected before it acts, so a wrong guess is visible rather
than mysterious.

## What routes where

| Detected | Goes to |
| --- | --- |
| CVE identifier | [`cve detail`](Cve) |
| IP address | [`scan ip`](Scan) |
| MAC address | [`scan mac`](Lookups) |
| email address | [`scan email`](Lookups) |
| file hash | [`scan hash`](Lookups) |
| crypto address | [`scan crypto`](Scan) |
| URL | [`scan url`](Lookups) (without `--resolve`) |
| phone number | [`scan phone`](Lookups) |
| domain | [`results domain`](Results) — the **read** side |

## Detection is local

Nothing is sent until the kind is settled, so an unrecognised value costs no
request and no quota:

```console
$ mlab search "not a thing"
error: could not tell what 'not a thing' is.
```

The order the checks run in is what makes the ambiguous cases come out right:
an IP is tested before a domain, because `8.8.8.8` reads as four labels and a
TLD; a 32-character hex string is a digest, not a name; and anything carrying a
scheme or a path is the whole URL rather than a bare host.

## Searching a domain does not scan it

`mlab search example.com` fetches the **existing** report. A scan spends quota
and takes minutes, so starting one stays an explicit
[`mlab scan domain`](Scan) — a command that costs real money should never be
something you triggered by pasting.

If there is no report yet, the command exits `6` and you decide whether to
spend the scan.

## `mlab open`

```bash
mlab open example.com
mlab open CVE-2024-3094 --print
```

The same detection, pointed at the web report instead of the API. It launches
your browser; `--print` writes the URL to stdout and stops, which is what you
want inside a script or over SSH:

```console
$ mlab open CVE-2024-3094 --print
https://vuln.mlab.sh/cve/CVE-2024-3094
```

The URL is built from the configured hosts, so `--hostname` and a
[profile](Configuration) pointing at a staging deployment produce links into
that deployment rather than production.

## Output

`--json` on `search` behaves exactly as it does on whichever command it routed
to. `-o csv` is refused for both. See [Output](Output).
