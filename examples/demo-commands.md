# Demo Commands

All commands below are safe demonstration commands for the included inert fixtures.

## Build both release executables

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

## GUI startup smoke test

```powershell
.\target\release\openclaw-skill-guard-gui.exe --smoke-test
```

## GUI product demo

Launch the desktop app:

```powershell
cargo run -p openclaw-skill-guard-gui
```

Run the release GUI EXE directly:

```powershell
.\target\release\openclaw-skill-guard-gui.exe
```

## Benign sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\benign\SKILL.md --format json
```

Release EXE equivalent:

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\benign\SKILL.md --format json
```

## Obvious high-risk sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\high-risk\SKILL.md --format json
```

## Install-risk sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\install-risk --format json
```

## Prompt/instruction-risk sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

Release EXE equivalent:

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

## Runtime refinement sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\runtime-refinement\SKILL.md --format json --runtime-manifest .\fixtures\v1\runtime-refinement\runtime-sandbox.json --validation-mode guarded
```

## V2 report-demo sample

Export canonical JSON:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format json
```

Export SARIF:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format sarif
```

Export Markdown and HTML:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format markdown
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format html
```

Prebuilt example outputs live under `examples/reports/`.
