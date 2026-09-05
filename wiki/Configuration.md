# Configuration

One file, `~/.mlab/conf.yml`, written with mode `0600`. It is the lowest layer
of the precedence described in [Authentication](Authentication): a flag beats an
environment variable beats this file.

```yaml
hostname: https://mlab.sh
cve_hostname: https://vuln.mlab.sh
actors_hostname: https://actors.mlab.sh
api_key: <your key>
vuln_token: <optional vuln.mlab.sh CI token>
```

You can edit it by hand. `mlab login` rewrites the key, `mlab logout` clears it
and keeps the hosts, and [`mlab config`](Config) reads and writes single values
without opening an editor:

```bash
mlab config path
mlab config list
mlab config set hostname https://staging.mlab.sh
```

The file is not created until something needs to write it. Everything works
from the environment alone, which is what a CI runner usually wants.

## Profiles

One machine, several organisations. A profile is a named block that overrides
only the fields it sets:

```yaml
api_key: personal-key
hostname: https://mlab.sh
profiles:
  work:
    api_key: work-key
    hostname: https://mlab.example.internal
  audit:
    api_key: audit-key
```

```bash
mlab --profile work whoami
MLAB_PROFILE=work mlab limits
```

`audit` above sets no hostname, so it uses `https://mlab.sh` from the top
level. Overriding is per-field, not per-block: a profile never has to restate
settings it does not change.

Writing into a profile works the same way:

```bash
mlab --profile work config set api_key mlab_xxx
```

### A missing profile is an error

```console
$ mlab --profile prod whoami
error: no profile named 'prod' in /home/you/.mlab/conf.yml (known: audit, work)
```

Never a silent fall-through to the default credentials. Quietly running a
production command against a personal key is a worse failure than an error
message, so it is not offered.

## Masking

`config list` and `config get` mask credentials by default, keeping the first
four characters and the last four:

```console
$ mlab config list
api_key   mlab…mnop
```

A secret shorter than that is hidden entirely, rather than mostly revealed by a
prefix. `--reveal` prints the real value, and nothing else does — so a config
dump pasted into an issue or a bug report does not leak a key.

Hostnames are never masked: they are settings, not secrets, and hiding them
would defeat the purpose of printing the configuration.

## Global flags

Everything here is accepted before or after the sub-command.

| Flag | Description |
| --- | --- |
| `--hostname <url>` | Override the platform host (default `https://mlab.sh`) |
| `--cve-hostname <url>` | Override the CVE host (default `https://vuln.mlab.sh`) |
| `--actors-hostname <url>` | Override the actor host (default `https://actors.mlab.sh`) |
| `--api-key <key>` | Use this key instead of the stored one |
| `--vuln-token <token>` | `vuln.mlab.sh` CI token — raises the scan quota |
| `--profile <name>` | Configuration profile to use |
| `--output`, `-o` | `table` (default), `json` or `csv` |
| `--quiet`, `-q` | Suppress spinners and progress output |
| `--dry-run` | Print the request that would be sent, and stop |
| `--timeout <secs>` | HTTP request timeout (default 60) |
| `--max-wait <secs>` | How long to follow a running scan (default 900) |

See [Output](Output) for `-o`, `-q` and the progress rules, and [Hosts](Hosts)
for what `--dry-run` prints.
