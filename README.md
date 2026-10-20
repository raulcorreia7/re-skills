# re-skills

Agent skills for reverse engineering.

| Skill | Use |
| --- | --- |
| [`rizin`](skills/rizin/SKILL.md) | Inspect binaries with rizin and rzpipe: commands, JSON output, version differences, PS1/MIPS notes |
| [`re-toolbox`](skills/re-toolbox/SKILL.md) | Choose the right tool for a reverse-engineering question: bytes, diffs, match verdicts, compiler behavior, MIPS word decode |

Each skill is a folder with a `SKILL.md` (frontmatter `name` and `description`)
and optional `references/`.

## Install

Copy or symlink the skill folders into the skills directory your agent reads:

```sh
git clone <repo-url> re-skills
# user-wide (Claude Code reads ~/.claude/skills; many agents read ~/.agents/skills)
ln -s "$PWD"/re-skills/skills/rizin      ~/.claude/skills/rizin
ln -s "$PWD"/re-skills/skills/re-toolbox ~/.claude/skills/re-toolbox
# per project
mkdir -p .agents/skills && cp -r re-skills/skills/* .agents/skills/
```

- Claude Code: `~/.claude/skills/` or `<project>/.claude/skills/`.
- Codex and other agents that follow the `.agents` convention:
  `~/.agents/skills/` or `<project>/.agents/skills/`. The `rizin` skill ships
  `agents/openai.yaml` for Codex metadata.
- Any other agent: point it at the `SKILL.md` files.

## Requirements

`rizin` 0.8 or newer (and `rzpipe` for scripts). Other tools named in
`re-toolbox` are optional.

## License

MIT
