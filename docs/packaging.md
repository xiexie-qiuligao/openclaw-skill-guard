# Packaging

This project ships two Windows executables:

- `openclaw-skill-guard-gui.exe`
  - primary desktop product
  - recommended for normal users
- `openclaw-skill-guard.exe`
  - CLI entry point
  - intended for automation and advanced users

Build both executables:

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

Build outputs:

```text
target\release\openclaw-skill-guard-gui.exe
target\release\openclaw-skill-guard.exe
```

Recommended release asset:

```text
openclaw-skill-guard-gui-windows.zip
```

The GUI zip should contain:

- `openclaw-skill-guard-gui.exe`
- `README.txt`

The CLI executable can be shipped separately when automation users need it.

Do not include research folders, reference repositories, local build paths, or internal planning documents in the public release package.
