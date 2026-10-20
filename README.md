# re-skills

Two agent skills for reverse engineering.

| Skill | What it does |
| --- | --- |
| [`rizin`](skills/rizin/SKILL.md) | Inspect binaries with rizin and rzpipe. Command reference, JSON output, version quirks, PS1/MIPS notes. |
| [`re-toolbox`](skills/re-toolbox/SKILL.md) | Pick the right tool for a question: bytes, diffs, match verdicts, compiler behavior, MIPS word decode. |

## Install

```sh
git clone https://github.com/raulcorreia7/re-skills.git
```

Copy the skill folders to the place your agent reads. Global means every
project. Per project means only that repository.

| Agent | Global | Per project |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex and other `.agents` agents | `~/.agents/skills/` | `.agents/skills/` |

```sh
cp -r re-skills/skills/* ~/.claude/skills/          # global, Claude Code
cp -r re-skills/skills/* .claude/skills/            # this project, Claude Code
```

Use `ln -s` instead of `cp -r` to follow updates. Any other agent can read the
`SKILL.md` files directly.

## Needs

`rizin` 0.8 or newer. `rzpipe` for scripts. The other tools in `re-toolbox` are
optional.

## License

MIT. The bundled `psx-spx.txt` is third-party and not covered; see
[its notice](skills/rizin/references/psx-spx.NOTICE.md).
