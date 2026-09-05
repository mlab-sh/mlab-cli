# `mlab login`, `logout`, `whoami`

The three commands that manage the platform credential. See
[Authentication](Authentication) for where a key can come from and which host
wants which one.

## `login`

```bash
mlab login
mlab login --key "$MLAB_KEY"
```

Prompts for the key, verifies it against the API, and only then writes it to
`~/.mlab/conf.yml` with mode `0600`:

```
mlab.sh — Login

API Key: 
ok: Authenticated as Acme Security — key saved to /home/you/.mlab/conf.yml
```

**Verification happens before the write.** Storing a key that does not work
only moves the failure to whatever you run next, so a bad key fails here and
leaves the existing configuration untouched:

```
error: that key was not accepted by the API — nothing was saved.
```

`--key` skips the prompt, which is what a provisioning script wants. In CI,
prefer setting `MLAB_API_KEY` and not calling `login` at all — nothing has to be
written to disk for the rest of the CLI to work.

`login` also records the hostname it verified against, so
`mlab --hostname https://staging.mlab.sh login` sets up a staging profile in one
step.

## `whoami`

```bash
mlab whoami
mlab whoami --json
```

```
  ✔ Authenticated
  Organization:  Acme Security
  Plan:          team
```

The command to run first when something else misbehaves: it separates a network
problem from a credential problem before you spend quota finding out.

### Why it does not just check the status code

The API answers `200` with a generic greeting when the key is unknown, so the
status alone cannot tell an authenticated call from a rejected one. `whoami`
looks for an organization in the body — or the explicit `api_key` marker — and
treats its absence as a rejection, exiting `2`:

```
error: API key not recognized.
  Check your key with `mlab whoami`, or set a new one with `mlab login`.
```

A key that would pass a naive check is caught here.

## `logout`

```bash
mlab logout
```

Clears the key from the config file and keeps everything else:

```
ok: API key removed from /home/you/.mlab/conf.yml
```

The hostnames survive, because a hostname is a preference, not a credential —
logging out of a self-hosted deployment should not silently point you back at
`mlab.sh`. Running it twice is not an error:

```
Not logged in — nothing to do.
```

`logout` touches only the credential the config file holds. A key in
`MLAB_API_KEY` or on the command line is not the CLI's to remove.
