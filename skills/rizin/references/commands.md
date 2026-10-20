# rizin commands

Targets **Rizin 0.8 or newer**; every command in this file exists in both 0.8.x
and 0.9.x. Verified against Rizin 0.9.1 and 0.8.2, on `/usr/bin/true` (x86-64 ELF) and a
1.4 MB little-endian MIPS PS-X EXE (`game.exe` below). Prefer the newest build
available; the differences that change parsing are in Version portability below.
Outputs are trimmed from real runs.

## Version portability (rizin >= 0.8)

A 66-case sample of the commands in this file ran on both builds: 45 outputs
were byte-identical, and every difference was shape or formatting — no command
availability change. The deltas that can break a script:

| Area | 0.9.x | 0.8.x | Rule |
| --- | --- | --- | --- |
| Endianness flag | `-E little`; `-e cfg.bigendian=false` at startup → `ERROR: use -E argument for setting the endianness` | `-E` → `rizin: illegal option -- E`; `-e cfg.bigendian=false` works | Pick per version, or set it in-session: `-c 'e cfg.bigendian=false'` works on both |
| Colour | ANSI escapes even when piped | plain output when piped | `e scr.color=false` before parsing on either |
| `pdj`/`pdrj`/`pdfj` `esil` | populated | `""` | Never gate on ESIL presence |
| Instruction text (`/ai`, `/adj`, `/z` hit `code`) | `cmp edi, 0x2` | `cmp edi, 2` | Parse numbers, do not string-match |
| `izj`/`izzj` rows | no `ordinal` | `ordinal` present | Read keys with `.get()` |
| `/zj` hits | `detail` field | absent | Same |
| `pf` | prints `[LE]` endian tag | no tag | Do not depend on the tag |
| `pfj` | one row per field with `endian` | legacy split rows | Prefer `pxwj`/`pxj` for raw values |
| `pdf` text | `setnz al`, `cmp edi, 0x02` | `setne al`, `cmp edi, 2` | Same 67-line box layout; mnemonics and immediates differ — parse `pdfj`/`pdj` fields instead of grepping text |
| Bundled types (`t`, `ts`, `tl`) | richer DB, different order | smaller DB | Define types with `td`/`to`; do not depend on shipped names |
| `phl` | provider list differs | differs | Check with `phl~sha256` instead of assuming one implementation |
| Bad config key | two error lines | one | Match on the key name, not the line count |
| rz-ghidra pairing | 0.9.x ↔ rz-ghidra 0.9.0 (Ghidra 12.1) | 0.8.x ↔ rz-ghidra 0.8.0 | The plugin follows the rizin series |

Verified identical on both (sampled): `ij`, `iSj`, `ie` (glyph-only diff), `afl`
/`aflj`, `afi`, `afvl`/`afvt`, `afn`, `afbj`, `afvx`, `afbr`, `afc`, `afs`,
`axt`/`axl`, `aau`, `f`/`fs`/`CC`, `is`/`ii`, `pd`/`pi`/`px`/`pxj`/`pxw`, `pdJ`,
`aez`/`aezvj`/`aezi`, `agf json`, `pdrj` shape, `%`, `es`/`et`/`e`, `.` repeat,
and the exit-code behaviour (always 0).

Conventions: `-q` quits after `-c` commands; `-qc 'cmd'` is an unsuffixed
one-shot; `~` filters output; append `j` for JSON. Addresses in rizin output are
virtual addresses unless a command says otherwise.

## Open, confirm, map

| Need | Command | Prints |
| --- | --- | --- |
| What loaded | `rizin -qc ij FILE \| jq '{format:.core.format,arch:.bin.arch,bits:.bin.bits,endian:.bin.endian}'` | `{"format":"psxexe","arch":"mips","bits":32,"endian":"LE"}` |
| Sections | `rizin -qc 'iSj' FILE \| jq '[.[] \| select(.name==".text")]'` | `.text` with `paddr 8256 size 33395 vaddr 8256` on `/usr/bin/true` |
| Entry points | `rizin -qc ie FILE` | `<entry vaddr> <entry vaddr> ... type program` |
| Force a loader | `-F psxexe` | Bypasses detection: a raw-in-header image still parses |
| Raw image | `-n` | No bin parsing: io only, no sections, no symbols |
| Map a raw file | `-n -m 0xBASE` | Maps the whole file at that address (`oml` confirms) |
| Set base | `-B 0x80010000` | Base for PIE-style relocation; **not** a raw-image mapping |
| Open another file | `o FILE`, then `olj` | Appends an fd; `omlj` lists per-fd maps |

```text
$ rizin -q -n -a mips -b 32 -E little -m 0xBASE \
    -c 'omlj' -c 'pd 2 @ 0xADDR' raw.bin
[{"map":1,"fd":3,"delta":0,"from":...,"to":...,"perm":"r-x","name":""}]
```

`omlj` shows the map; `pd` at an address inside it decodes instructions.
Without `-m`, runtime addresses read as file offsets.

```text```

Pitfalls:

- `S` is not a command in 0.9.1 (`ERROR: Command 'S' does not exist.`); use
  `iS` / `iSj` for sections and `iSS` for segments.
- `-B` under `-n` fails: `WARNING: Failed to read chunk of size 0x101 at
  0xADDR from io.` followed by garbage (`sdc3 31, -1(ra)`). Use `-n -m`.
- `-c 'td struct demo { int value; }'` fails: rizin splits `-c` strings on `;`.
  Escape it — `-c 'td struct demo { int value\; }'` then `-c 'ts demo'` prints
  `pf "d4 value"`.
- Rizin 0.8.2: `-E` → `rizin: illegal option -- E`; use
  `-c 'e cfg.bigendian=false; e asm.bits=32; e asm.arch=mips'` (verified: the
  PS-X EXE then disassembles correctly).
- `-q0` frames every reply with `\0` (xxd: `7b 22 63 6f 72 65 ...`) — that is
  the rzpipe protocol, not normal output.

## Analysis levels

| Command | Scope | Cost on the PS-X EXE (1.4 MB) |
| --- | --- | --- |
| `af` | Function at seek (also `af @ ADDR`) | instant |
| `aa` | Flags starting `sym.*` and entry | 3 functions |
| `aaa` | + calls, refs, preludes, signatures | 522 functions, ~1.7 s, 7 `Invalid instruction` notices |
| `aac` | Analyze function calls | run; printed nothing |
| `aar 0x100` | Xrefs in current section or N bytes | run; printed nothing |
| `aae 0x20 @ ADDR` | ESIL-based references | run; printed nothing |
| `aau 16` | Addresses not covered by any function | `0x00002040 386`, `0x0000227b 251`, … |
| `aezi` → `aezs N` → `aezvj PC` | RzIL VM: init, step, dump | `{"PC":"0x..."}`; without `aezi`: `ERROR: RzIL: Run 'aezi' first to initialize the VM` |

Pitfalls:

- `aa` alone finds few boundaries on stripped or console images: the 1.4 MB
  PS-X EXE yielded 3 functions (entry0 among them), while `aaa` yielded 522. Raise the level or
  create functions yourself with `af @ ADDR` before trusting a negative result.
- `afj <tbl> <n>` (jump-table analysis) needs a function at the seek
  (`af @ ADDR`, or an analysis pass first); otherwise it prints
  `ERROR: No function defined here` and does nothing. It also uses its second
  argument as **both** entry size and entry count (`librz/arch/jmptbl.c`):
  `afj 0xb800 4` on `/usr/bin/true` created 4 case flags, `afj 0xb800 11` only
  1. On MIPS it is usually wrong — resolve jump tables by hand — and outside an
  analysis task it logs `rz_analysis_task_item_new: assertion ... failed`.
- `afbe` (add switch-case edge) is broken in 0.9.1 (frees the block list it then
  uses); prefer `afb+`, `axc`, and `CC` comments.
- Scope long jobs: `e analysis.from=0xSTART; e analysis.to=0xEND`
  (keys are `analysis.*`; `e anal.from` is `ERROR: variable 'anal.from' does
  not exists`).

## Functions

```text
$ rizin -qc 'aa; aflj' /usr/bin/true | jq '[.[]|select(.name=="main")|{offset,size}]'
[{"offset":9376,"size":272}]
$ rizin -q -c 'aa; afi @ main' /usr/bin/true
offset: 0x000024a0
name: main
size: 272
stackframe: 32
num-bbs: 10
call-refs: 0x00003020 C ...
locals: 1
args: 2
arg int argc @ rdi
arg char **argv @ rsi
var int64_t var_10h @ stack - 0x10
```

| Need | Command | Notes |
| --- | --- | --- |
| List | `afl`, `aflj` | Table / JSON (`offset size blocks name`) |
| Info | `afi`, `afij` | `afij @ main` → `{name,offset,size,nargs,nlocals}` |
| Offset / size | `afo @ main`, `afi~size` | `afo` → `0x000024a0` |
| Rename | `afn NEW @ ADDR` | Verified: `afij @ renamed_main` → `"name":"renamed_main"` |
| Blocks | `afbj @ main` | `{addr,size,jump,fail}` per basic block |
| Vars/args | `afvl @ main`, `afvlj` | `var int64_t var_10h @ stack - 0x10` etc. |
| Set var type | `afvt var_10h int @ main` | Renames the local's type to `int`; `pdg` then declares `int var_10h;` |
| Var xrefs | `afvx @ main`, `afvR VAR`, `afvW VAR` | reads: `argc 0x24a4` / `argv 0x24bb,0x24be` / `var_10h 0x2509,0x2524`; writes analogous |
| Exit points | `afbr @ main` | `0x000024b6`, `0x0000254e` — every address that leaves the function |
| Calling convention | `afc @ main` | `amd64` from the help table; `afc?` lists the names |
| Signature | `afs @ main` | `int main(int argc, char **argv, char **envp);` |
| Disassemble | `pd N`, `pdf`, `pdfj` | `pdf` adds xref/arg comments and block arrows. Watch out: `pdf` on a 200 KB function is slow — use `pd`+`@` |
| Recursive | `pdr`, `pdrj` | Follows the call graph; JSON has `opcode`/`esil` per instruction |
| Graph | `agf json @ main`, `agf ascii` | `agf json` → `{"nodes":[...]}`; filter with jq |

```text
$ rizin -q -c 'aa' -c 'afo @ main' -c 'afvx @ main' -c 'afbr @ main' -c 'afc @ main' -c 'afs @ main' /usr/bin/true
0x000024a0
afvR
      argc  0x24a4
      argv  0x24bb,0x24be
   var_10h  0x2509,0x2524
afvW
      argc
      argv
   var_10h  0x24be,0x2519
0x000024b6
0x0000254e
amd64
int main(int argc, char **argv, char **envp);
```

## Hints

`ah` adjusts how rizin decodes or names what it cannot infer. Verified effect:
`ahb 16` (bit width) and `ahi 16` (immediate base) both changed the decode of
`0x24a9`/`0x24af` from x86-64 to 16-bit forms (`mov dx, word [di]`, `xor ax, ax`)
— hints are powerful and sticky per address, so set them deliberately and
remove them with `ah-`/`ahi-` when done.

| Need | Command |
| --- | --- |
| All hint commands | `ah?` (families: `ahb` bits, `ahi` immediate base, `ahd` data type, `ahs` size, `ahc` code, `ahr` references, `aha` arch, `ahan` name) |
| Set / clear an immediate base | `ahi <base> @ ADDR`, `ahi- @ ADDR` |
| Set / clear operand size | `ahb <bits> @ ADDR`, `ahb- @ ADDR` |

Hints stay inside the session (or a saved project); they never touch the file.

## Cross references

```text
$ rizin -qc 'axtj @ 0x3020' /usr/bin/true          # before analysis
[]
$ rizin -qc 'aa; axtj @ 0x3020' /usr/bin/true
[{"from":9411,"to":12320,"type":"CALL"}]
$ rizin -qc 'aa; axlj' /usr/bin/true | jq '[.[]|select(.type=="CALL")]|.[:2]'
[{"from":8792,"to":8541,"type":"CALL"},{"from":8813,"to":61176,"type":"CALL"}]
```

- `axt` = refs **to** the address (callers), `axf` = refs **from** it,
  `axl` = everything.
- They are empty until an analysis command creates the refs — `axt` before `aa`
  is a silent negative, not evidence.
- `afij @ F` also carries `callrefs`/`datarefs` with `{"from","to","type"}`.
- Data vs call: `CALL` entries are call sites; `DATA` entries point at
  constants or strings (`afij` shows both).

## Flags, symbols, comments

```text
$ rizin -qc 'aa; f+ sample_flag 4 @ main; flj' /usr/bin/true | jq '[.[]|select(.name=="sample_flag")]'
[{"name":"sample_flag","realname":"sample_flag","size":4,"offset":9376}]
$ rizin -qc 'aa; fs sample_space; fslj' /usr/bin/true | jq '[.[]|select(.name=="sample_space")]'
[{"name":"sample_space","count":0,"selected":true}]
$ rizin -qc 'aa; CCu sample-comment @ main; CCfj @ main' /usr/bin/true
[{"offset":9376,"type":"CCu","name":"sample-comment"}]
$ rizin -qc iij /usr/bin/true | jq '.[0:1]'
[{"ordinal":1,"bind":"GLOBAL","type":"FUNC","name":"getenv"}]
```

- `f name [size [comment]]` adds a flag at seek; `f-`, `f-*`, `fr old new`,
  `fm newaddr` manage it; `fl`, `flj`, `fdj` inspect it.
- Flagspaces: `fs NAME` creates/selects, `fsl[j]` lists, `fs- NAME` removes,
  `fs-*` clears. New flags land in the current space.
- Comments: `CC TEXT` appends at seek, `CCu` adds unique, `CClj` lists all,
  `CCfj` lists the current function's.
- Symbols: `is[j]` lists the symbol table, `ie[j]` entries, `ii[j]` imports,
  `iE[j]` exports. A stripped binary can answer `isj` with `[]` while `ii`
  still shows dynamic imports — check both.
- `afn` renames functions; it is also the fastest way to pin a name from an
  external symbol list (see the rzpipe symbol-annotation script).

## Types and variables

```text
$ rizin -qc 't' /usr/bin/true          # list loaded types
FILE 0x0
_Bool 0x8
__div_t 0x40
$ rizin -qc 'tsj' /usr/bin/true | jq '.[0:2]'
[{"name":"__sigset_t","members":{"sig":"unsigned long"}},...]
$ rizin -qc 'tl' /usr/bin/true | head -3
typedef FILE (0x0)
atomic _Bool (0x8)
struct __div_t (0x40)
$ rizin -q -c 'td struct demo { int value\; }' -c 'ts demo' -c 'tp demo @ 0' /usr/bin/true
pf "d4 value"
0x00000000 : value = 1179403647 [LE]
```

- `t`/`tj` all types, `ts`/`tsj` structs, `tu` unions, `te` enums, `tl` verbose
  listing (**`tlj` does not exist**), `tc` C output, `tt` typedefs.
- `td` defines from a C snippet or a `pf` format; `to FILE` loads a C header;
  `tp TYPE @ ADDR` casts; `tx` lists type xrefs.
- Function variables carry types too — `afvt VAR TYPE @ FUNC` — and `afvl`
  shows what rizin inferred from the code.

## Search

| Need | Command | Verified output |
| --- | --- | --- |
| Bytes | `e search.from=0x2400; e search.to=0x2600; /xj f30f1efa` | `[{"address":9376,...},{"address":9648,...}]` |
| Bytes in whole file | `/xj 7f454c46` | first hit at `address 0` (ELF magic) |
| Instruction text | `e search.from=0x24a0; e search.to=0x2600; /aj ret` | `[{"address":9398,...},{"address":9550,...}]` |
| Instruction pair | `/adj endbr64\;cmp` | `[{"offset":160,"code":"endbr64; cmp edi, 0x02"},...]` |
| Immediate operand | `e search.from=0x24a0; e search.to=0x2600; /aij 0x2` | `[{"offset":9380,"len":3,"code":"cmp edi, 0x02"}]` |
| Value, any width | `/v4j 0x464c457f` | `[{"address":0,"size":4,...}]` |
| String | `/zj TEXT l ascii` | `[{"address":...,"size":...,...}]` |
| Crypto material | `/cmj all`, `/ce 7 8 256` | Both `[]` on coreutils ELFs; available, but do not expect hits on ordinary code |
| File contents | `/Fj /tmp/probe.bin` | Hits where that file's bytes appear: `8192`, `8541`, … `flag":"hit.keyword_file.N"` |
| Known magic | `/mj` | `[{"address":0,"size":0,"flag":"hit.magic.0","detail":"ELF 64-bit LSB shared object, x86-64, version 1"}]` |
| Syscalls | `/as` | On x86-64: `0x00000738 read` — **text output**; `/asj` prints the same, no JSON |
| Deltified sequence | `/dj 101112` | `[]` here — the delta never occurs |

Pitfalls:

- The `/ad` and `/z` families take a `;`-separated or regex argument: escape
  `\;` inside `-c` strings, or the rest is parsed as a new command.
- Default search ranges cover the maps; on a mapped PS-X EXE hits come back as
  vaddrs, while `paddr` is the file offset.
- `WARNING: |GNU| < search.str.min_length so some search hits may be hidden.
  Set search.str.min_length to 3 to see them.` — short patterns are skipped
  silently otherwise.
- Scope searches (`e search.from=...; e search.to=...`) before concluding "not
  found"; the default range follows the current block or map.
- `/x` and `/aj` hits carry only `address`/`size` (plus a flag name) — the
  matched text is not in the JSON. Use `/ai` for operand-aware hits; it returns
  `len` and `code`.
- `/x` and `/v` take file-order bytes and values: a wrong-endian pattern
  silently finds nothing instead of erroring, so a negative tells you only that
  you searched the wrong bytes.

## Strings

```text
$ rizin -qc 'izj' game.exe | jq 'length'      # strings in data sections
84
$ rizin -qc 'izzj' game.exe | jq 'length'     # whole binary
2195
$ rizin -qc 'izj' game.exe | jq '.[1:2]'
[{"vaddr":...,"paddr":...,"size":21,"length":20,"section":"TEXT",
  "type":"ascii","string":"..."}]
```

- A string in a file header, before the mapped region (the PS-X EXE header
  text), reports `vaddr 18446744073709551615` (UT64_MAX); other `iz` rows have
  real vaddrs.
- `iz` = strings in data sections, `izz` = whole file, `izx` = strings with
  xrefs, `iz-` purges the string at seek (via the `bin.str.purge` flow).
- Raw-mode string loading uses `-zz` / `-z` (see `rizin` usage); there is no
  `bin.str.min` key in 0.9.1 (`e bin.str.min` errors), so filter lengths in
  `jq` when it matters.

## Disassembly and hex

```text
$ rizin -q -c 'pd 2 @ main' /usr/bin/true
            ;-- main:
            0x000024a0      endbr64
            0x000024a4      cmp   edi, 0x02
$ rizin -qc 'pdj 2 @ main' /usr/bin/true | jq -c '.[0]'
{"offset":9376,"opcode":"endbr64","disasm":"endbr64",...}
$ rizin -q -c 'pi 2 @ main' /usr/bin/true
endbr64
cmp edi, 0x02
$ rizin -q -c 'px 8 @ main' /usr/bin/true
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x000024a0  f30f 1efa 83ff 0274                      .......t
$ rizin -qc 'pxj 8 @ main' /usr/bin/true
[243,15,30,250,131,255,2,116]
$ rizin -q -c 'pxw 8 @ main' /usr/bin/true
0x000024a0  0xfa1e0ff3 0x7402ff83                        .......t
$ rizin -q -c 'pf x4 @ 0' /usr/bin/true
0x00000000 = 0x464c457f [LE]
```

- `pD N` = N **bytes** (signed tolerated), `pd N` = N instructions, `pi` drops
  the address column, `pdr` recurses, `pdb` one basic block.
- `pdJ N` returns `{"offset","text"}` rows whose text keeps **ANSI colour
  escapes** — run `e scr.color=false` first if you will parse or log them.
  There is no `pdsj`; `pds N @ main` printed only the function label in the
  verified run, so treat it as a terse cross-cutting summary, not a report.
- `pd` follows flags: at `str.help` it prints `.string "--help" ; len=7`
  instead of decoding data as instructions, so read the flag, not the guess.
- `pxj` is a byte array, `pxwj`/`pxqj` are 32/64-bit value arrays honouring
  endianness — the right form for diffing raw data.
- `pf` takes a format string (`x4`, `d2`, `z`), `pfj` returns JSON, `pfs` the
  size.
- `ph <algo>` prints a digest of the block (`ph sha256 @ main` →
  `b3d0527c437ac1b11213a12c65f05a4098f31d0d74983d18dcb8c0d2516b01ab`); `phl`
  lists algorithms and their providers — `phl~sha256` matched different
  providers across versions, so grep rather than hardcoding one entry.

## Decompiler (rz-ghidra)

`pdg` prints C-like pseudocode for the function at seek. It comes from the rz-ghidra plugin, which a build may lack: a stock 0.9.1 build has no `pdg` (`ERROR: core: Error while executing command: pdg?`). Check with `pdg?` before relying on it.

| Command | Output |
| --- | --- |
| `pdg` | Decompiled function for the seek |
| `pdgj` | Same as JSON (`{"code":"..."}`, warnings included) |
| `pdgo` | Side-by-side with offsets |
| `pdgs`, `pdgss` | Installed sleigh languages / the auto-matched one (`MIPS:LE:32:default:`) |

- Analyse first (`aa`); without it `pdg` prints `Ghidra Decompiler Error: No function at this offset`.
- The decompiler reads rizin's analysis: `afn` names and `afvt` local types propagate into the output.
- On MIPS the argument list is unreliable (`Matching calling convention n32 ... failed`), and GTE words stay holes with `Variable defined which should be unmapped` warnings. Check every call against `pd`, `axt` and `afvR`/`afvW`.
- `pdg` output is a reading aid; every fact it asserts needs the `pd`/`axt`/`afv` evidence chain.
- Plugins load only into a shared (non-static) rizin built from the matching series: rizin 0.9.x with rz-ghidra 0.9.0, 0.8.x with 0.8.0.

## Seek, iterators, filtering

| Form | Meaning |
| --- | --- |
| `CMD @ 0xADDR` | Temporary seek for this command only |
| `CMD @F:flag`, `@a:x86:64`, `@e:key=val`, `@r:rax` | Temporary flagspace/arch/eval/register context |
| `CMD @@=0x24a0 0x24a4` | Run over the listed addresses |
| `CMD @@iS`, `CMD @@is`, `CMD @@iz`, `CMD @@F:glob`, `CMD @@f:glob` | Run over every section/symbol/string/function/flag |
| `CMD @@s:0x1000 0x2000 0x10` | Run over a stepped range |
| `CMD~substr`, `CMD~[0]`, `CMD~:2..5`, `CMD~?` | Internal grep: lines, one column, a line range, or a match count |
| `CMD @@/x 90 90` | Run over the hits of a search |

```text
$ rizin -q -c 'pd 1 @@=0x24a0 0x24a4' -c 'pdf @@F:main' /usr/bin/true
            0x000024a0      endbr64
            0x000024a4      cmp   edi, 0x02
```

`~` is the cheapest way to shrink output before it reaches a model; combine
with `jq` for structure.

## Batch and scripting

- One-shot: `rizin -qc 'aa; aflj' FILE` — every command runs, then quit.
- Repeated flags: `-c 'aa' -c 'afl' -c 'pd 4 @ main'`.
- Script file: `rizin -q -i script.rz FILE` (verified `demo.rz` with
  `e scr.color=false`, `aa`, `aflj~main`); `-I` runs it before the file loads.
- Exit codes are useless as gates: a failing command still exits 0. Gate on
  output (or on rzpipe's parsed result).
- `-q0` is the machine protocol used by rzpipe; prefer rzpipe over parsing
  framed bytes yourself.

## Scripting idioms

```text
$ rizin -q -c '% 0x10+2' /usr/bin/true
int32   18
uint32  18
hex     0x12
octal   022
unit    18
$ rizin -q -c 'pd 1 @ main' -c '.' /usr/bin/true
            ;-- main:
            0x000024a0      endbr64
```

- `% <expr>` evaluates an expression and prints every representation; use it to
  sanity-check addresses and masks before pasting them into a command.
- `.` (dot) repeats the last command; pair it with `@` to walk a few addresses
  without retyping.
- `$alias=cmd` defines a command alias; `$?` lists the syntax, `$*` dumps
  aliases base64-encoded (so a session can export them).
- `es analysis` lists the sub-keys of a namespace; `et key` shows a config
  value's type (`et analysis.calls` → `bool`); `e! key` inverts a boolean
  (`e analysis.calls` → `false`, after `e!` → `true`); `e-` resets everything.
- `@e:key=val` scopes a config change to one command:
  `pd 2 @e:asm.bits=32 @ 0x24a0` decodes that one listing as 32-bit.
- Compose with `~` before `jq`: `aflj~main` greps JSON text, which is often
  cheaper than parsing everything.

## Failure modes (verified)

Every row is a real observation; the fix column is what actually worked.

| Symptom | Cause | Fix |
| --- | --- | --- |
| Command failed but `echo $?` is 0 | Rizin always exits 0 | Gate on output/JSON, never the exit code |
| `ERROR: core: Error while parsing command` | `-c` splits on `;` | Escape it: `td struct demo { int value\; }` |
| `ERROR: No binary object currently selected.` + `Failed to read chunk` + `sdc3` garbage | `-n` without a mapping | Add `-m <addr>` (not `-B`) |
| `blez` / `swr` at an entry that should be `lui/addiu` | Wrong endianness | `-E little` (0.9.1) or `e cfg.bigendian=false` |
| x86 `sbb dword [rax-...], eax` for MIPS bytes | Wrong arch | `-a mips -b 32` |
| `axt`/`axf` return `[]` on code with obvious calls | No analysis ran | `af`/`aa`/`aaa` first |
| `/zj` misses a short pattern | Below `search.str.min_length` | Raise `search.str.min_length` (the command warns) |
| `/xj`/`/aj` finds nothing for bytes you can see | Default search range covers only the current block or map | Set `e search.from`/`e search.to` and re-run |
| `ERROR: Command 'S' does not exist.` | `S` was removed before 0.9.1 | Use `iS`/`iSS` |
| `ERROR: Command 'tlj' does not exist.` | No JSON form of `tl` | Use `t`/`tj`/`tsj` |
| `/asj` prints text, not JSON | `/as` has no JSON mode | Parse the `0xADDR name` lines |
| `pdJ` text full of `\u001b[38;2;…` | Colour escapes kept in JSON | `e scr.color=false` before printing |
| `{"errors":["Ghidra Decompiler Error: No function at this offset"]}` | `pdg` before analysis | `aa`, then `pdg` |
| `ERROR: RzIL: Run 'aezi' first to initialize the VM` | Emulation not initialized | `aezi @ ADDR` before `aezs`/`aezvj` |
| `e anal.from` → `variable 'anal.from' does not exists` | Renamed key | `e analysis.from` / `e search.from` |
| `iSSj` → `[]` on a PS-X EXE | The payload has one section, no segments | Use `iSj`/`iS` |

```text
$ rizin -q -c 'Ps /tmp/demo.rzdb' /usr/bin/true
$ rizin -q -c 'Po /tmp/demo.rzdb' -c ij /usr/bin/true | jq -c '{format:.core.format}'
{"format":"elf64"}
```

- `Ps FILE` saves analysis, flags, types, and comments; `Po FILE` restores;
  `-p FILE` loads at startup. Projects are the cheapest way to keep an
  expensive `aaa` between sessions.
- Config keys are namespaced and differ from other RE tools: `e asm.arch`,
  `e asm.bits`, `e analysis.from`, `e analysis.to`, `e analysis.depth`,
  `e search.from`, `e search.to`, `e scr.color`. List them with `el`, `elj`,
  or filter with `el~analysis.`. Verify a key before depending on it — several
  plausible names (`anal.from`, `bin.str.min`, `cmd.pdc`) do not exist.
- `e key=value` sets, `e-` resets all, `et key` shows the type, `e! key`
  inverts a boolean.

## Performance

- Keep one session: a persistent rzpipe `cmdj` measured **1.075 ms** median vs
  **26.3 ms** for a fresh `rizin -q0 -c` process on `/usr/bin/true`; on the
  1.4 MB PS-X EXE it was **1.064 ms** vs **711.5 ms** (30 reps each).
- Analysis dominates the first call (`aaa` on that PS-X EXE: ~1.7 s); every
  query afterwards is cheap, so batch queries rather than re-analysis.
- Avoid `aaa` on very large images, and `pdf`/`pdr` on huge functions; use
  `pd N @ addr`, `@@F`, and `~`/jq to cut output before it reaches the model.
- `-2` (close stderr) and `-N`/`-NN` (skip user config/plugins) make batch runs
  quieter and more reproducible.
