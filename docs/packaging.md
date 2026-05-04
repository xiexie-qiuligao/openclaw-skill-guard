# Packaging

This project ships two Windows executables:

- `agent-skill-guard-gui.exe`
  - primary desktop product
  - recommended for normal users
- `agent-skill-guard.exe`
  - CLI entry point
  - intended for automation and advanced users

Build both executables:

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

Build outputs:

```text
target\release\agent-skill-guard-gui.exe
target\release\agent-skill-guard.exe
```

Recommended release asset:

```text
agent-skill-guard-gui-windows.zip
```

The GUI zip should contain:

- `agent-skill-guard-gui.exe`
- `agent-skill-guard.exe`
- `README.txt`
- `LICENSE`
- `.openclaw-guard.yml`

The GUI executable is the primary entry point. The CLI executable is included in the same zip for automation and advanced users.

Do not include research folders, reference repositories, local build paths, or internal planning documents in the public release package.
