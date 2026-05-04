# Release Ready

Current public release shape:

- GUI is the main product entry point.
- CLI remains available for automation.
- JSON is the canonical report contract.
- SARIF, Markdown, and HTML are derived exports.
- The project remains a verifier / guard, not an exploit runner.

Final checks before publishing:

```powershell
cargo test
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
.\target\release\agent-skill-guard-gui.exe --smoke-test
.\target\release\agent-skill-guard.exe --help
```

Public repository hygiene:

- keep source code, schemas, tests, fixtures, and product docs
- do not keep cloned reference repositories
- do not keep research snapshots
- do not keep local absolute paths or machine-specific artifacts
- do not keep old version demo reports in the public tree

Recommended GitHub Release asset:

```text
agent-skill-guard-gui-windows.zip
```
