# Lookups

The cheap half of [`scan`](Scan). These sub-commands ask a question and get an
answer in one request — no polling, no follow, no report to fetch later. They
still live on `mlab.sh` and still need an API key.

| Sub-command | Endpoint | What it tells you |
| --- | --- | --- |
| `scan url <url>` | `GET /api/v1/scan/url` | URL structure, host reputation, lookalike detection |
| `scan hash <h…>` | `GET`/`POST /api/v1/scan/hash` | Reputation for SHA-1, SHA-256 and MD5 digests |
| `scan email <addr>` | `GET /api/v1/scan/email` | Mailbox type, disposable and role detection, sending-domain posture |
| `scan phone <num>` | `GET /api/v1/scan/phone` | Validity, region, line type, operator |
| `scan mac <mac>` | `GET /api/v1/scan/mac` | Vendor and OUI, randomization, virtualization |
| `scan bash <file>` | `POST /api/v1/scan/file/bash` | Shell-script analysis: suspicious patterns and extracted indicators |

Every one of them takes `--json`.

## `scan url`

```bash
mlab scan url https://exarnple.com/login
mlab scan url https://short.link/abc --resolve
```

Structure, host reputation and lookalike detection — the last of which is the
point for a phishing triage: `exarnple.com` reads as `example.com` at a glance
and does not at all to a comparison function.

`--resolve` follows redirects. **It is off by default because it fetches the
target**, which a link in a phishing email may well be counting on. Turn it on
deliberately, not by habit.

## `scan hash`

```bash
mlab scan hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
mlab scan hash <sha256> <md5> <sha1>
```

One digest is a `GET`; more than one switches to the bulk endpoint, which is
one request rather than *n*. Mixed digest types in one call are fine.

## `scan email`

```bash
mlab scan email abuse@example.com
```

Whether the address is deliverable-shaped, whether the mailbox is disposable or
a role account (`abuse@`, `postmaster@`), and what the sending domain's posture
looks like — the SPF/DKIM/DMARC story behind it.

## `scan phone`

```bash
mlab scan phone +33612345678
```

Validity, region, line type and operator. Give it E.164 form (`+`, country
code, number) when you have it; anything else is parsed on a best-effort basis.

## `scan mac`

```bash
mlab scan mac 00:1A:2B:3C:4D:5E
mlab scan mac 001a.2b3c.4d5e
```

Vendor from the OUI, plus the two flags that matter when a MAC turns up
somewhere unexpected: whether it is locally administered (a randomized privacy
address, not a real vendor assignment) and whether it belongs to a
virtualization range.

Any common notation is accepted — colons, hyphens, Cisco dotted-quad, or bare
hex.

## `scan bash`

```bash
mlab scan bash install.sh
cat install.sh | mlab scan bash -
```

Static analysis of a shell script: the suspicious patterns it contains, and the
indicators it references. The thing to run against the `curl … | sh` installer
before you are the pipe.

`-` reads stdin, so it composes with whatever produced the script.

## Which one do I want?

If you do not know, do not choose:

```bash
mlab search 00:1A:2B:3C:4D:5E
```

[`search`](Search) works out what a value is and routes it to the lookup that
owns it. Detection is local, so a value it does not recognise costs no request.
