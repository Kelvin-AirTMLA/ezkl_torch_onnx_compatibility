# Installing ezkl

A practical guide to installing [ezkl](https://github.com/zkonduit/ezkl), based on common failures and what actually works.

Official docs: [docs.ezkl.xyz/getting-started/installation](https://docs.ezkl.xyz/getting-started/installation)

---

## Three ways to use ezkl

ezkl is not one install — it is three different packages depending on what you need:

| What you want | Install method | Gives you a shell command? |
|---------------|----------------|----------------------------|
| **CLI** (`ezkl --help`) | GitHub release binary or build from source | Yes |
| **Python** (`import ezkl`) | `pip install ezkl` | No |
| **JavaScript** | `npm install @ezkljs/engine` | No |

`pip install ezkl` succeeding does **not** mean `ezkl` works in your terminal. Those are separate installs.

---

## Where CLI binaries come from

The CLI is **not** on Homebrew, pip, or crates.io. Pre-built binaries are published as **GitHub release assets**:

- **Repository:** [github.com/zkonduit/ezkl](https://github.com/zkonduit/ezkl)
- **Releases:** [github.com/zkonduit/ezkl/releases](https://github.com/zkonduit/ezkl/releases)
- **Install script:** [install_ezkl_cli.sh](https://github.com/zkonduit/ezkl/blob/main/install_ezkl_cli.sh)

The script detects your OS/architecture, finds the matching tarball in a release, downloads it to `~/.ezkl/ezkl`, and adds `~/.ezkl` to your PATH.

### Release assets by platform

Asset names vary by release. Typical filenames:

| Platform | Asset name (examples) |
|----------|------------------------|
| Linux x86_64 | `ezkl-linux-gnu.tar.gz` or `build-artifacts.ezkl-linux-gnu.tar.gz` |
| Linux ARM64 | `ezkl-linux-aarch64.tar.gz` or `build-artifacts.ezkl-linux-aarch64.tar.gz` |
| Windows | `ezkl-windows-msvc.tar.gz` or `build-artifacts.ezkl-windows-msvc.tar.gz` |
| macOS Apple Silicon | `build-artifacts.ezkl-macos-aarch64.tar.gz` |
| macOS Intel | `build-artifacts.ezkl-macos.tar.gz` |

**Important:** not every release includes every platform. Always check assets before installing (see [Check release assets](#check-release-assets) below).

---

## Recommended install: official CLI script

Works on Linux and Windows when the latest release includes a binary for your platform:

```bash
curl https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash
```

Install a specific version (useful when latest is missing your platform):

```bash
curl -s https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash -s v23.0.3
```

Reload your shell after install:

```bash
# zsh
source ~/.zshenv

# bash
source ~/.bashrc
```

Verify:

```bash
which ezkl
ezkl --help
```

---

## Why common methods fail

### `brew install ezkl`

No Homebrew formula exists. This always fails.

### `pip install ezkl`

Installs the **Python library only**. You get `import ezkl`, not a terminal command.

### `cargo install ezkl`

Fails with:

```
error: could not find `ezkl` in registry `crates-io`
```

The CLI is not published to crates.io. Use a GitHub release binary or build from a cloned repo instead.

### Archon (`download_archon.sh`)

A **separate** remote-proving tool, not the core ezkl CLI. The download URL may return HTML instead of a script.

---

## Platform notes

### Linux

The official installer usually works out of the box on recent releases. Latest releases (e.g. v23.0.5) include Linux assets:

- `ezkl-linux-gnu.tar.gz` — x86_64
- `ezkl-linux-aarch64.tar.gz` — ARM64

Manual download example (x86_64):

```bash
mkdir -p ~/.ezkl
curl -L \
  "https://github.com/zkonduit/ezkl/releases/download/v23.0.5/ezkl-linux-gnu.tar.gz" \
  -o ~/.ezkl/ezkl-linux-gnu.tar.gz
tar -xzf ~/.ezkl/ezkl-linux-gnu.tar.gz -C ~/.ezkl
export PATH="$PATH:$HOME/.ezkl"
```

### Windows

Use the official installer script in Git Bash or WSL, or download `ezkl-windows-msvc.tar.gz` from [releases](https://github.com/zkonduit/ezkl/releases) manually.

### macOS

The default installer **may fail silently** if the latest release has no macOS binary. This was the case for v23.0.5 at the time this guide was written — Linux and Windows assets were published, but not macOS.

Symptom: script stops after:

```
Platform: macos
Architecture: aarch64
```

`~/.ezkl` stays empty because there is nothing to download.

**Fix:** pin a release that includes macOS assets, e.g. v23.0.3:

```bash
curl -s https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash -s v23.0.3
```

Or download manually:

| Mac type | Asset | URL |
|----------|-------|-----|
| Apple Silicon (M1/M2/M3/M4) | `build-artifacts.ezkl-macos-aarch64.tar.gz` | [v23.0.3 download](https://github.com/zkonduit/ezkl/releases/download/v23.0.3/build-artifacts.ezkl-macos-aarch64.tar.gz) |
| Intel | `build-artifacts.ezkl-macos.tar.gz` | [v23.0.3 download](https://github.com/zkonduit/ezkl/releases/download/v23.0.3/build-artifacts.ezkl-macos.tar.gz) |

```bash
mkdir -p ~/.ezkl
curl -L "<url-from-table-above>" -o ~/.ezkl/ezkl.tar.gz
tar -xzf ~/.ezkl/ezkl.tar.gz -C ~/.ezkl
export PATH="$PATH:$HOME/.ezkl"
```

If macOS blocks the binary (Gatekeeper):

```bash
xattr -d com.apple.quarantine ~/.ezkl/ezkl
```

Or allow it under **System Settings → Privacy & Security**.

---

## Python bindings

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install ezkl
python3 -c "import ezkl; print('OK')"
```

Use the Python API (`ezkl.gen_settings`, `ezkl.compile_circuit`, etc.). No shell command is installed.

GPU variant: `pip install ezkl-gpu`

---

## Build from source (any platform)

Requires [Rust](https://rustup.rs) and `cargo`. Slow, but works when no pre-built binary exists for your platform.

```bash
git clone https://github.com/zkonduit/ezkl.git
cd ezkl
git checkout v23.0.3   # or a tag/commit that includes your platform
cargo install --locked --path .
```

Ensure `~/.cargo/bin` is on your PATH. Source builds can fail on some commits due to dependency issues.

---

## Docker (any platform)

If native binaries are unavailable or broken:

```bash
docker pull zkonduit/ezkl:latest
```

Run `ezkl` inside the container.

---

## Uninstall

There is no `curl` uninstall flag. Remove ezkl based on how you installed it:

| How installed | Uninstall |
|---------------|-----------|
| GitHub binary / install script | `rm -f ~/.ezkl/ezkl` (or `rm -rf ~/.ezkl`) and remove `~/.ezkl` from PATH in your shell config |
| pip | `pip uninstall ezkl` |
| cargo (from source) | `cargo uninstall ezkl` |

---

## Check release assets

Before relying on the default installer, confirm your platform is in the latest release:

```bash
curl -s "https://api.github.com/repos/zkonduit/ezkl/releases/latest" \
  | python3 -c "import sys,json; [print(a['name']) for a in json.load(sys.stdin).get('assets',[])]"
```

If your platform is missing, pin an older tag that includes it (e.g. `bash -s v23.0.3`) or build from source / use Docker.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `command not found: ezkl` after pip | pip installs Python only | Install the GitHub CLI binary |
| Installer stops after platform/arch line | Latest release missing your platform's asset | Pin an older tag or manual download |
| `~/.ezkl` is empty | Download never ran | Check release assets; install manually |
| `cargo install ezkl` fails | Not on crates.io | Use release binary or build from cloned repo |
| macOS won't open binary | Gatekeeper quarantine | `xattr -d com.apple.quarantine ~/.ezkl/ezkl` |

---

## References

- [ezkl GitHub repository](https://github.com/zkonduit/ezkl)
- [ezkl releases (binaries)](https://github.com/zkonduit/ezkl/releases)
- [Official installation docs](https://docs.ezkl.xyz/getting-started/installation)
- [install_ezkl_cli.sh](https://github.com/zkonduit/ezkl/blob/main/install_ezkl_cli.sh)
