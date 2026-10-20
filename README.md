# re-skills

Two agent skills for reverse engineering.

| Skill | What it does |
| --- | --- |
| [`rizin`](skills/rizin/SKILL.md) | Inspect binaries with rizin and rzpipe. Command reference, JSON output, version quirks, PS1/MIPS notes. |
| [`re-toolbox`](skills/re-toolbox/SKILL.md) | Pick the right tool for a question: bytes, diffs, match verdicts, compiler behavior, MIPS word decode. |

## Install

```sh
git clone https://github.com/raulcorreia7/re-skills.git
cp -r re-skills/skills/* ~/.claude/skills/     # Claude Code, all projects
```

Other places to put the skill folders:

| Agent | Folder |
| --- | --- |
| Claude Code (one project) | `.claude/skills/` |
| Codex and other `.agents` agents | `~/.agents/skills/` or `.agents/skills/` |

Use `ln -s` instead of `cp -r` to follow updates. Any other agent can read the
`SKILL.md` files directly.

## Needs

`rizin` 0.8 or newer. `rzpipe` for scripts. The other tools in `re-toolbox` are
optional.

## License

MIT. The bundled `psx-spx.txt` is third-party and not covered; see
[its notice](skills/rizin/references/psx-spx.NOTICE.md).
