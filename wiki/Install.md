# Install

`mlab` is a single Rust binary with no runtime dependencies. macOS and Linux,
x86_64 and arm64, from a package manager or as a tarball.

## Homebrew (macOS and Linux)

```bash
brew tap mlab-sh/mlab-cli https://github.com/mlab-sh/mlab-cli.git
brew install mlab
```

## Debian and Ubuntu

Download the `.deb` for your architecture from the
[releases page](https://github.com/mlab-sh/mlab-cli/releases), then let apt
resolve it:

```bash
sudo apt install ./mlab_1.0.1_amd64.deb
```

## Fedora, RHEL and rebuilds

The same with the `.rpm`:

```bash
sudo dnf install ./mlab-1.0.1-1.x86_64.rpm
```

The payload is gzip rather than the zstd default, so rpm 4.14 (RHEL 8 and its
rebuilds) reads it too.

## Prebuilt binary

Tarballs for every target are on the same page. Each one unpacks to a directory
holding the binary, the README and the licence:

```bash
tar -xzf mlab-1.0.1-aarch64-apple-darwin.tar.gz
install -m 0755 mlab-1.0.1-aarch64-apple-darwin/mlab ~/.local/bin/
```

The Linux builds are linked against glibc 2.35, so they run on Debian 12,
Ubuntu 22.04 and anything newer.

## Checking what you downloaded

Nothing is signed, so every release carries a `SHA256SUMS` file covering all of
its assets — tarballs, `.deb` and `.rpm` alike:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

The Homebrew formula carries the four tarball checksums itself, so `brew
install` verifies them without anyone thinking about it.

## From source

```bash
git clone https://github.com/mlab-sh/mlab-cli.git
cd mlab-cli
cargo build --release
install -m 0755 target/release/mlab ~/.local/bin/
```

`cargo install --path .` works too, and puts the binary in `~/.cargo/bin`.

## Requirements

| | |
| --- | --- |
| Rust | 1.74 or later (2021 edition), only to build from source |
| Network | Outbound HTTPS to `mlab.sh`, `vuln.mlab.sh` and `actors.mlab.sh` |
| Credential | An API key for the `mlab.sh` commands; none for CVE or actor lookups |

TLS is rustls with the platform trust store, so there is no OpenSSL to install
and no system certificate bundle to configure.

## First run

```bash
mlab login
```

The prompt asks for the key without echoing it, verifies it against the API
before storing anything, and writes `$HOME/.mlab/conf.yml` with mode 0600. A
typo fails there rather than at the next command. Then:

```bash
mlab whoami
mlab limits
```

## Non-interactive install

For a script or a CI job, pass the key and skip the prompt:

```bash
mlab login --key "$MLAB_KEY"
```

Or store nothing at all and let the environment carry it, which is what a
runner usually wants:

```bash
MLAB_API_KEY=... mlab limits
```

Prefer the environment variable over `--api-key`: a command line is visible to
every other process on the machine. See [Authentication](Authentication).

## Shell completions

```bash
mlab completions zsh > ~/.zfunc/_mlab
mlab completions bash > /etc/bash_completion.d/mlab
mlab man > /usr/local/share/man/man1/mlab.1
```

Details on [Completions](Completions).
