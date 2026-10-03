# Lab Assistant Skills

AI-assistant skills (Claude Code, opencode, or any assistant that can read a
`SKILL.md`) for hands-on lab work. Each skill is a self-contained folder: a
`SKILL.md` the assistant reads, a `README.md` written as a manual for people,
and standalone scripts that also work without any AI.

| Skill | What it does |
|---|---|
| [`vm-lab-assistant`](vm-lab-assistant/README.md) | Control, audit, harden, and patch lab VMs end to end: Windows 10/11, Windows Server, Active Directory domain controllers, and Linux. Snapshot, dry-run, rollback journals, before/after comparison, and a by-hand procedure for every step. |

## Install a skill

```bash
mkdir -p ~/.claude/skills
cp -r vm-lab-assistant ~/.claude/skills/
```

Or use the scripts directly; see each skill's README.

## CI

`.github/workflows/lint.yml` runs shellcheck, a POSIX `dash -n` syntax check,
the PowerShell parser and PSScriptAnalyzer, and a real Linux
harden-then-rollback round-trip that must restore files byte for byte.

## License

MIT (see each skill's `SKILL.md`).
