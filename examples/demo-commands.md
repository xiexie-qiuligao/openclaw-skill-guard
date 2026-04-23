# Demo Commands

All commands below are safe demonstration commands for the included inert fixtures.

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

## Precedence/shadowing hint sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\precedence-shadowing --format json
```

## Runtime refinement sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\runtime-refinement\SKILL.md --format json --runtime-manifest .\fixtures\v1\runtime-refinement\runtime-sandbox.json --validation-mode guarded
```

## Suppression and audit sample

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\suppression-audit\SKILL.md --format json --suppressions .\fixtures\v1\suppression-audit\suppressions.json
```
