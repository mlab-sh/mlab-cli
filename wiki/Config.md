# `mlab config`

Read and edit `~/.mlab/conf.yml` without opening an editor. See
[Configuration](Configuration) for what the file holds and how profiles resolve.

```bash
mlab config path
mlab config list
mlab config get api_key
mlab config set hostname https://staging.mlab.sh
```

## `path`

```console
$ mlab config path
/home/you/.mlab/conf.yml
```

The one command that works before anything is configured. Useful in a script
that wants to back the file up, or check its permissions.

## `list`

```console
$ mlab config list
hostname         https://mlab.sh
cve_hostname     https://vuln.mlab.sh
actors_hostname  https://actors.mlab.sh
api_key          mlab…mnop
vuln_token       —
```

The **effective** configuration — after the selected profile has been overlaid,
so `mlab --profile work config list` shows what a `--profile work` command would
actually use, not what the file literally says.

An unset value shows as `—`, which is a different thing from an empty string.

## `get`

```bash
mlab config get hostname
mlab config get api_key --reveal
```

One value, unadorned, for scripting.

## `set`

```bash
mlab config set hostname https://staging.mlab.sh
mlab config set vuln_token "$TOKEN"
mlab --profile work config set api_key mlab_xxx
```

Writes one key. With `--profile`, it writes into that profile's block rather
than the top level, creating it if it does not exist.

The writable keys are `hostname`, `cve_hostname`, `actors_hostname`, `api_key`
and `vuln_token`.

## Masking

`list` and `get` mask credentials by default — first four characters, last
four:

```
api_key   mlab…mnop
```

A secret of eight characters or fewer is hidden entirely rather than mostly
revealed by its prefix. `--reveal` prints the real value, and nothing else
does.

That default exists because a config dump is the kind of thing people paste
into issues and CI logs, and a key that leaks that way is a key that has to be
rotated. Hostnames are never masked: they are settings, not secrets.

## Related

[`login`](Login) writes the key after verifying it; `logout` clears it and
keeps everything else. Editing the file by hand is fine too.
