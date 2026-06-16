# Installing ezkl on macOS (Apple Silicon)

This guide documents how to install [ezkl](https://github.com/zkonduit/ezkl) on macOS, especially Apple Silicon (`aarch64`), based on real installation failures and what actually works.

Official docs: [docs.ezkl.xyz/getting-started/installation](https://docs.ezkl.xyz/getting-started/installation)

---

## Quick answer

| Goal | Command / method |
|------|------------------|
| **CLI in terminal** (`ezkl --help`) | Install the **v23.0.3** macOS binary (see below) |
| **Python** (`import ezkl`) | `pip install ezkl` — already works, but does **not** add a shell command |

---

## Where the Apple Silicon binary comes from

The CLI binary is **not from Homebrew, pip, or crates.io**. It is a **pre-built release artifact** published by the ezkl maintainers on GitHub.

| Field | Value |
|-------|--------|
| Repository | [github.com/zkonduit/ezkl](https://github.com/zkonduit/ezkl) |
| Releases page | [github.com/zkonduit/ezkl/releases](https://github.com/zkonduit/ezkl/releases) |
| Version used here | **v23.0.3** (last release that included macOS builds at the time this was written) |
| Asset filename | `build-artifacts.ezkl-macos-aarch64.tar.gz` |
| Direct download URL | [v23.0.3 macOS Apple Silicon tarball](https://github.com/zkonduit/ezkl/releases/download/v23.0.3/build-artifacts.ezkl-macos-aarch64.tar.gz) |

**How this was determined:** the official install script calls the GitHub API for the latest release and searches release assets for a macOS `aarch64` tarball. As of v23.0.5, that asset is **missing** from the latest release (only Linux and Windows assets are published). v23.0.3 still includes:

- `build-artifacts.ezkl-macos-aarch64.tar.gz` — Apple Silicon (M1/M2/M3/M4)
- `build-artifacts.ezkl-macos.tar.gz` — Intel Mac (`x86_64`)

The install script source (for reference): [install_ezkl_cli.sh](https://github.com/zkonduit/ezkl/blob/main/install_ezkl_cli.sh)

---

## Why common install methods fail

### `brew install ezkl`

Homebrew has **no formula** named `ezkl`. This will always fail.

### Official installer (latest version)

```bash
curl https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash
```

On Apple Silicon this often **stops silently** after:

```
Platform: macos
Architecture: aarch64
```

**Reason:** the script installs from the **latest** GitHub release. If that release has no macOS asset, the script cannot find a download URL and exits before downloading anything. `~/.ezkl` stays empty.

### `pip install ezkl`

This **succeeds** and installs the Python library (`import ezkl`). It does **not** install a terminal command named `ezkl`. Running `ezkl` in the shell will still give:

```
zsh: command not found: ezkl
```

### `cargo install ezkl --locked`

This fails with:

```
error: could not find `ezkl` in registry `crates-io`
```

The CLI crate is **not published** to crates.io under that name. Building from a cloned repo is possible but slow and can hit dependency build errors.

### Archon remote CLI

```bash
curl https://download.ezkl.xyz/download_archon.sh | bash
```

This is a **separate** remote-proving tool, not the core `ezkl` CLI. The download URL may return HTML instead of a shell script, causing parse errors.

---

## Working install: CLI on Apple Silicon

### Option 1 — Pinned installer (easiest)

Install **v23.0.3** explicitly so the script does not pull the Mac-less latest release:

```bash
curl -s https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash -s v23.0.3
```

Then reload your shell:

```bash
source ~/.zshenv
```

The script installs the binary to `~/.ezkl/ezkl` and appends that directory to your PATH in `~/.zshenv` (zsh).

### Option 2 — Manual download

```bash
mkdir -p ~/.ezkl

curl -L \
  "https://github.com/zkonduit/ezkl/releases/download/v23.0.3/build-artifacts.ezkl-macos-aarch64.tar.gz" \
  -o ~/.ezkl/ezkl-macos-aarch64.tar.gz

tar -xzf ~/.ezkl/ezkl-macos-aarch64.tar.gz -C ~/.ezkl
rm ~/.ezkl/ezkl-macos-aarch64.tar.gz
```

Add to PATH if not already present (in `~/.zshenv` for zsh):

```bash
export PATH="$PATH:$HOME/.ezkl"
source ~/.zshenv
```

### Option 3 — Intel Mac

Use the Intel asset from the same release:

```bash
curl -L \
  "https://github.com/zkonduit/ezkl/releases/download/v23.0.3/build-artifacts.ezkl-macos.tar.gz" \
  -o ~/.ezkl/ezkl-macos.tar.gz

tar -xzf ~/.ezkl/ezkl-macos.tar.gz -C ~/.ezkl
```

---

## Verify the CLI install

```bash
which ezkl          # should print something like /Users/you/.ezkl/ezkl
ezkl --help
```

If macOS blocks the binary (unidentified developer):

```bash
xattr -d com.apple.quarantine ~/.ezkl/ezkl
```

Or allow it under **System Settings → Privacy & Security**.

---

## Working install: Python bindings

If you only need Python (notebooks, `import ezkl`), pip is enough:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install ezkl
python3 -c "import ezkl; print('OK')"
```

This does not provide the `ezkl` shell command. Use the Python API (`ezkl.gen_settings`, `ezkl.compile_circuit`, etc.) instead.

---

## Build from source (last resort)

```bash
git clone https://github.com/zkonduit/ezkl.git
cd ezkl
git checkout v23.0.3
cargo install --locked --path .
```

Ensure `~/.cargo/bin` is on your PATH. Expect a long compile and possible dependency issues on some commits.

---

## Docker alternative

If native macOS builds are unavailable or broken:

```bash
docker pull zkonduit/ezkl:latest
```

Run `ezkl` inside the container. Less convenient for daily CLI use, but uses the Linux release artifacts reliably.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Installer stops after `Architecture: aarch64` | Latest release has no macOS binary | Pin **v23.0.3** (see above) |
| `command not found: ezkl` after pip | pip installs Python only | Install the GitHub release binary |
| `~/.ezkl` is empty | Download never ran | Manual download or pinned installer |
| macOS won't open binary | Gatekeeper quarantine | `xattr -d com.apple.quarantine ~/.ezkl/ezkl` |
| `cargo install ezkl` fails | Not on crates.io | Use release binary or build from cloned repo |

---

## Check whether a release includes macOS

Before relying on the default installer, inspect release assets:

```bash
curl -s "https://api.github.com/repos/zkonduit/ezkl/releases/latest" \
  | python3 -c "import sys,json; [print(a['name']) for a in json.load(sys.stdin).get('assets',[])]"
```

Look for `build-artifacts.ezkl-macos-aarch64.tar.gz`. If it is missing, pin an older tag that includes it (e.g. `v23.0.3`) or build from source / use Docker.

---

## References

- [ezkl GitHub repository](https://github.com/zkonduit/ezkl)
- [ezkl releases (binaries)](https://github.com/zkonduit/ezkl/releases)
- [Official installation docs](https://docs.ezkl.xyz/getting-started/installation)
- [install_ezkl_cli.sh](https://github.com/zkonduit/ezkl/blob/main/install_ezkl_cli.sh)
