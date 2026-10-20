---
name: rizin
description: Uses rizin and rzpipe for binary reverse engineering of raw, relocated, or console binaries, covering disassembly, functions, xrefs, strings, data extraction, Python scripting, and PlayStation 1/MIPS specifics. Do not use for source-level or repository code work.
---

# Rizin

## Job

Answer binary questions with rizin, or with rzpipe when the work is a script,
and leave a reproducible trail: exact command, address, trimmed output, rizin
version.

## Steps

1. Open with explicit arch, bits, endianness, and base, then confirm what
   loaded with `ij`, `iS`, and `ie`. An unusual format analysed silently as the
   wrong one wastes the whole session.
2. Analyse the least that answers the question: `af` at one address, then `aa`,
   then `aaa`. Record the level used, because every later xref, function, and
   variable result depends on it.
3. Improve the inputs before reading them back: `afn` renames functions,
   `afvt` types locals, `f`/`CC` label data. The decompiler and every later
   query follow those names and types.
4. Query with the JSON variants (`aflj`, `axtj`, `pdj`) and parse them; use
   `@ addr` to scope a command and, for many queries, one session or a script.
5. Record evidence: the command, the address or function it ran at, the trimmed
   output, and the conclusion it supports.

## Flow

```text
open (format arch bits endian base) -> confirm (ij iS ie) -> analyse least (af -> aa -> aaa)
-> query JSON (@ addr) -> keep vaddr/paddr straight -> record command + output
```

## Tool choice

| Tool | Reach for it when |
| --- | --- |
| rizin on the CLI | You need structure: xrefs, functions, flags, strings, exact bytes, scriptable JSON |
| rzpipe session | The same queries run in bulk, or the answer feeds a script |
| `llvm-objdump` / `objdump` | You want an independent second opinion on one function's disassembly, without rizin's state |
| rz-ghidra plugin (`pdg`) | You want C-like pseudocode to read intent; use it as a reading aid and verify against `pd` |
| Full Ghidra | You need its decompiler UI, its own analysis, or its plugin ecosystem |

rz-ghidra is a separate plugin, not part of a standard rizin build: a stock
0.9.1 build has no `pdg` (`ERROR: core: Error while executing command: pdg?`),
while a distro 0.8.2 install shipped `core_ghidra.so` alongside
`asm_ghidra.so`, `analysis_ghidra.so`, and its sleigh files. Check before
promising a decompiler: `pdg?` answers with the command or an error.

## References

- Read [commands.md](references/commands.md) for any rizin command: the exact
  form, what it prints, the JSON variant, and its pitfalls.
- Read [rzpipe.md](references/rzpipe.md) when automating rizin from Python:
  session lifecycle, cost, error handling, and five worked scripts.
- Read [psx-mips.md](references/psx-mips.md) when the target is a PlayStation 1
  or MIPS binary, or when you must identify PsyQ library code.

## Guardrails

- Rizin exits 0 even when a command fails: `rizin -q -c definitely_not_a_command
  /usr/bin/true` printed an error and `exit=0`. Read the output, never the exit
  code.
- Analyse the least that answers the question. `aa` on a 1.4 MB PS-X EXE
  produced 3 functions; `aaa` produced 522 in ~1.7 s and flagged GTE
  words as invalid instructions. On large or foreign-arch images `aaa` costs
  minutes, so scope with `e analysis.from` / `e analysis.to` when you can.
- Empty output has three common causes: the analysis command never ran, the
  address is outside every analysed region, or a search range defaulted. Check
  `e search.from` / `e search.to` before believing a negative search.
- Keep virtual and physical addresses apart: report vaddrs (`afl`, `axt`), and
  convert with `paddr` before touching bytes on disk, because the PS-X EXE
  header shifts file offsets by 0x800.
- Target rizin 0.8 or newer, and prefer the newest build available. Report the
  version, because flags and output shapes differ: 0.9.x needs `-E little` and
  rejects `-e cfg.bigendian=false` at startup (`ERROR: use -E argument for
  setting the endianness`), while 0.8.x rejects `-E` and needs the `-e` form.
  Setting it in-session (`-c 'e cfg.bigendian=false'`) works on both; the rest
  of the deltas are collected in the command reference.
- Set `e scr.color=false` before parsing output: 0.9.x emits ANSI escapes even
  when piped, 0.8.x does not.
- Never open a binary for write, and never run `aaa` against an image you
  cannot afford to re-analyse. Inspection changes live in the session, a saved
  project (`Ps`/`Po`), or a script — not in the file.
- rzpipe: a rizin that dies at startup (rejected flag, bad plugin path) makes
  `open()` block forever — no exception, no timeout. Test the flags on the CLI
  first, and prefer in-session `e ...` settings over spawn flags.
- rzpipe: a `TimeoutError` leaves the pipe wedged. Reset it (`set_timeout(-1)`)
  before `quit()`, or the quit fails with the same timeout; verified both ways.
- Some JSON-carrying output keeps ANSI colour escapes (`pdJ`); set
  `e scr.color=false` before parsing or logging it.
- Before promising a decompiler, check the plugin: `pdg?` answers with the
  command list or an error. Plugins need a **shared** rizin; the official
  static Linux artifact cannot load `pdg`. Build rizin and rz-ghidra from the
  same release series (0.9.x with 0.9.0, 0.8.x with 0.8.0).

## Output

- The answer to the binary question, with the exact command, the address, and
  trimmed real output.
- The rizin version, the analysis level used, and the base or mapping the
  answer assumes.
- Uncertainties stated as such: unanalysed regions, undecoded opcodes, inferred
  names, and library guesses that signature matching produced.
