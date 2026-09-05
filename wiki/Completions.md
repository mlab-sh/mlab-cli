# `mlab completions` and `mlab man`

Both write to stdout, so both are one redirect away from being installed.

## Shell completions

```bash
mlab completions zsh  > ~/.zfunc/_mlab
mlab completions bash > /etc/bash_completion.d/mlab
mlab completions fish > ~/.config/fish/completions/mlab.fish
```

`bash`, `zsh`, `fish`, `elvish` and `powershell` are supported.

The script is generated from the command tree itself, so it never drifts from
the binary: every sub-command, every flag and every fixed value set — the
severities, the output formats — completes because the parser already knows
them.

### zsh

```bash
mkdir -p ~/.zfunc
mlab completions zsh > ~/.zfunc/_mlab
```

with `~/.zfunc` on `fpath` before `compinit` runs:

```zsh
fpath=(~/.zfunc $fpath)
autoload -Uz compinit && compinit
```

### bash

System-wide, if you can write there:

```bash
mlab completions bash | sudo tee /etc/bash_completion.d/mlab > /dev/null
```

Otherwise source it from your `~/.bashrc`:

```bash
mlab completions bash > ~/.local/share/mlab-completion.bash
echo 'source ~/.local/share/mlab-completion.bash' >> ~/.bashrc
```

## Man page

```bash
mlab man > /usr/local/share/man/man1/mlab.1
man mlab
```

A roff page, generated from the same command tree — the descriptions in it are
the ones in `--help`.

Regenerate both after an upgrade. Neither is shipped in the packages, because a
stale completion script is more annoying than none.
