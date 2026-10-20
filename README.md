# re-skills

Notes for an AI agent that is helping you take a binary apart.

Reverse engineering with an agent goes wrong in quiet ways. The wrong
endianness still disassembles to something plausible. A "match" turns out to be
a stale object file. `aa` finds three functions where `aaa` finds five hundred.
These skills hold the lessons that avoid those traps, so the agent starts with
them instead of rediscovering them in your session.

## What is inside

**[`rizin`](skills/rizin/SKILL.md)** is for looking at a binary. It covers the
commands that matter, how to get JSON out of them, how to script them with
rzpipe, and where rizin 0.8 and 0.9 differ. There is also a PlayStation 1 and
MIPS guide, plus the full psx-spx hardware reference to search.

**[`re-toolbox`](skills/re-toolbox/SKILL.md)** is for deciding what to reach
for. Is this a bytes question, a diff question, or a "does it really match"
question? It points to the right tool (rizin, objdump, m2c, objdiff, the
permuter, Ghidra, rabbitizer) and says what each answer does and does not prove.

## Install

Grab the repo:

```sh
git clone https://github.com/raulcorreia7/re-skills.git
```

Then copy the skill folders where your agent looks. Put them in your home
folder to use them everywhere, or in a project to keep them with that repo.

| Agent | Everywhere | One project |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex and other `.agents` agents | `~/.agents/skills/` | `.agents/skills/` |

```sh
cp -r re-skills/skills/* ~/.claude/skills/    # everywhere, Claude Code
cp -r re-skills/skills/* .claude/skills/      # this project only
```

Prefer to get updates with a `git pull`? Use `ln -s` instead of `cp -r`. An
agent without a skills folder can still read the `SKILL.md` files directly.

## What you need

rizin 0.8 or newer. Add `rzpipe` if you want to script it. Everything else
`re-toolbox` mentions is optional, and the skill says so when it matters.

## License

MIT, see [LICENSE](LICENSE). The one exception is `psx-spx.txt`, which belongs
to its original authors. It is bundled unmodified for reference; see
[its notice](skills/rizin/references/psx-spx.NOTICE.md).
