# Modules

`mlab` ships the core commands. Everything else — the integrations that only
matter to some people, and that carry their own dependencies — lives in separate
repositories as a `mlab-<name>` binary, installed on demand:

```bash
mlab module available
mlab module install unifi
mlab unifi --help
```

After that, `mlab unifi …` behaves exactly like running `mlab-unifi …` by hand.
The core does not wrap it, parse for it, or re-render its output.

## Why not one binary

A module is a full CLI with its own dependency tree. UniFi support alone pulls
in an async runtime and a WebSocket stack that no other command uses. Linking
that into `mlab` would make every user download it, and every module after it
would make the core a little slower to build and a little larger to ship, for a
feature most people never run.

Keeping them separate also decouples the release cycles: a module ships a fix
without a core release, and the core ships without re-testing every integration.

## The catalogue

The list of installable modules is
[`modules.json`](https://github.com/mlab-sh/mlab-cli/blob/main/modules.json) at
the root of the `mlab-cli` repository, read over `raw.githubusercontent.com`.
Publishing a module is a commit to that file — no core release, no server.

```json
{
  "name": "unifi",
  "binary": "mlab-unifi",
  "repo": "https://github.com/mlab-sh/mlab-unifi",
  "description": "Audit UniFi consoles over the local and Site Manager APIs",
  "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin",
              "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
}
```

`targets` are the triples with a published release asset; a host outside that
list can still build from source. An optional `asset` field overrides the
filename template, which defaults to `{binary}-{version}-{target}.tar.gz` — the
layout every mlab release workflow emits.

A fetched copy is cached at `~/.mlab/catalog.json` for six hours, and a copy of
the file is compiled into the binary. A network outage therefore degrades to a
slightly older list rather than breaking `mlab`.

**The catalogue is an allowlist, and that is the point.** Installing a module
downloads and runs code. There is deliberately no `mlab module install <url>`:
the only things installable are the ones listed in a file that lives under
review in this repository.

## Installing

```bash
mlab module install unifi              # latest release
mlab module install unifi --version 1.0.0
mlab module install unifi --force      # reinstall
mlab module install unifi --from-source
```

The default path downloads a release binary:

1. Resolve the latest tag from the GitHub API, unless `--version` says otherwise.
2. Fetch `SHA256SUMS` from that release and find the line for this host's asset.
3. Download the tarball and check its SHA-256 against that line.
4. Extract just the binary into `~/.mlab/bin/`, through a temporary file so an
   interrupted install leaves the previous version in place.

A mismatch aborts before anything is written. Note what that check is and is
not: `SHA256SUMS` comes from the same release as the archive, so it proves the
download arrived intact and unswapped — it is not a signature, and it says
nothing about whether the release itself is trustworthy.

The extraction never uses a path from the archive. The destination is computed
from the module name, so a crafted entry name cannot write outside
`~/.mlab/bin`.

### `--from-source`

Clones into `~/.mlab/sources/<name>` and runs `cargo build --release`. Needs
`git` and `cargo` on the `PATH`, and takes minutes rather than seconds. Use it
for a target with no published build, or to run a module from `main`.

`mlab module update` rebuilds a source install from the latest commit rather
than replacing it with a release binary — silently swapping the two would undo
the reason someone chose it.

## Where things live

| Path | Contents |
| --- | --- |
| `~/.mlab/bin/mlab-<name>` | The installed binary |
| `~/.mlab/modules.json` | What is installed, at which version, from where |
| `~/.mlab/catalog.json` | Cached catalogue |
| `~/.mlab/sources/<name>` | Clone, for `--from-source` only |

`~/.mlab/bin` does not need to be on your `PATH`: `mlab` looks there itself.

## Resolution order

For `mlab unifi …`, the core looks for `mlab-unifi` in `~/.mlab/bin` first, then
on the `PATH`. The second rule means a module installed another way is picked up
for free:

```bash
brew install mlab-sh/mlab-unifi/mlab-unifi
mlab unifi --help          # works, with no `mlab module install`
```

`mlab module list` only reports what `mlab module install` put there, so a
Homebrew-installed module works as a sub-command without appearing in the list —
Homebrew owns its updates, not `mlab`.

## What gets passed through

Everything after the module name goes to the module untouched, including
`--help` and `--json`. The core's global flags are parsed *before* the module
name and are not forwarded as flags, because the module has its own parser and
its own idea of what `--output` means:

```bash
mlab --profile work unifi devices     # --profile is the core's
mlab unifi devices --json             # --json is the module's
```

`--profile` is the exception worth knowing about: it is forwarded as
`MLAB_PROFILE`, the same environment variable the core reads, so a module that
supports profiles picks up the one you asked for. `MLAB_CORE_VERSION` is set
too, for a module that wants to check what invoked it.

On Unix the module *replaces* the `mlab` process rather than running underneath
it. Exit codes, `Ctrl-C`, job control and the module's own TTY detection all
behave exactly as if you had run the module binary directly — there is no
wrapper left in the middle to get them wrong.

## Managing what is installed

```bash
mlab module list          # installed, with versions
mlab module available     # the catalogue, marking what you have
mlab module update        # every module, to its latest release
mlab module update unifi  # just this one
mlab module remove unifi
mlab module remove unifi --purge   # also delete the ~/.mlab/sources clone
mlab module which unifi   # print the binary path
```

`list` and `available` both take `--json`.

Installed modules are appended to `mlab --help` under a `Modules:` heading, so
the help reflects what this machine can actually run. Shell completions do not:
they are generated from the static command tree, so a module's own sub-commands
are not completed by `mlab`.

## Names

A module name is a bare lowercase word (`[a-z0-9][a-z0-9-]*`). Anything with a
path separator in it is rejected outright, which is what stops
`mlab ../../bin/sh` from ever resolving.

A module can never shadow a built-in command: clap owns those names and the
module dispatch never fires for them, so `mlab module install scan` is refused
rather than installing something that would silently never run.

## When a command is not found

```
$ mlab unifi devices
error: `unifi` is a module and it is not installed — run `mlab module install unifi`.

$ mlab scna example.com
error: unrecognised command `scna` — did you mean `scan`?
```

Routing unknown commands to modules costs clap its own "did you mean", so the
suggestion is rebuilt by hand against the built-ins *and* the catalogue. The
distance is optimal string alignment rather than plain Levenshtein: `scna` for
`scan` is the typo people actually make, and Levenshtein scores a transposition
the same as two unrelated substitutions.

Exit codes follow the usual table: `4` for an unrecognised command, `6` for a
module or release that does not exist. See [Exit codes](Exit-Codes).

## Publishing a module

1. Ship a `mlab-<name>` binary in tarballs named
   `mlab-<name>-<version>-<target>.tar.gz`, with a `SHA256SUMS` covering them,
   on GitHub releases. The release workflow in `mlab-unifi` is the reference.
2. Add an entry to `modules.json` in `mlab-cli` and merge it.

There is no step three: the next `mlab module available` on any machine lists it.
