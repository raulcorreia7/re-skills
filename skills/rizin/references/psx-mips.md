# PlayStation 1 / MIPS with rizin

Verified with Rizin 0.9.1 and 0.8.2 on a PS-X EXE (`game.exe` below). Platform
facts follow the community hardware reference psx-spx (sections named inline).
Addresses written `0xNAME` are placeholders for your binary.

## Open a PS-X EXE

```text
$ rizin -q -F psxexe -a mips -b 32 -E little -c ij game.exe | jq -c '{format:.core.format,arch:.bin.arch,bits:.bin.bits,endian:.bin.endian}'
{"format":"psxexe","arch":"mips","bits":32,"endian":"LE"}
$ rizin -q -a mips -b 32 -E little -c iSj game.exe | jq -c '[.[]|select(.name=="TEXT")|{paddr,size,vaddr}]'
[{"paddr":2048,"size":...,"vaddr":...}]     # paddr 0x800, vaddr = t_addr
$ rizin -q -a mips -b 32 -E little -c ie game.exe
0xENTRY 0xENTRY ... type program
```

The `psxexe` loader detects the `PS-X EXE` magic, so `-F` is only needed when
detection fails. `-e asm.cpu=r3000a` selects the R3000A names.

Endianness flags differ by series (full table in the commands reference): 0.9.x
takes `-E little` and rejects `-e cfg.bigendian=false` at startup
(`ERROR: use -E argument for setting the endianness`), while 0.8.x rejects `-E`
(`rizin: illegal option -- E`) and needs `-e cfg.bigendian=false`. Setting it
in-session works on both:

```text
$ rizin -q -F psxexe -a mips -b 32 \
    -c 'e cfg.bigendian=false' -c 'e asm.bits=32' -c 'e asm.arch=mips' \
    -c 'pd 2 @ 0xENTRY' game.exe
```

## The 2 KiB header

A PS-X EXE has an 0x800-byte header followed by code and data (psx-spx,
*CDROM File Formats*).

| Offset | Meaning |
| --- | --- |
| 0x000 | ASCII `PS-X EXE` |
| 0x010 | Initial PC |
| 0x014 | Initial GP/R28 |
| 0x018 | Destination address in RAM (`t_addr`) |
| 0x01C | File size excluding the header (`t_size`) |
| 0x020/0x028 | Data section start/size |
| 0x02C | BSS size (0 = none) |
| 0x030/0x034 | Initial SP/R29 base (usually 0x801FFFF0) and offset |
| 0x800 | Code/data, loaded at `t_addr` |

```text
$ python3 -I -c "
import struct; d=open('game.exe','rb').read(0x800)
print('pc=0x%08x' % struct.unpack_from('<I',d,0x10)[0], 'gp=0x%x' % struct.unpack_from('<I',d,0x14)[0],
      't_addr=0x%08x' % struct.unpack_from('<I',d,0x18)[0], 't_size=0x%x' % struct.unpack_from('<I',d,0x1c)[0],
      'sp_base=0x%08x' % struct.unpack_from('<I',d,0x30)[0])"
```

Rizin maps exactly this: one `TEXT` section with `paddr 0x800`, `vaddr t_addr`,
`size t_size`. Its internal struct names for 0x08/0x0C (`text`/`data`) and
0x30/0x34 (`S_addr`/`S_size`) do not match the psx-spx semantics; do not build
tooling on those two names.

File offset from a vaddr: `paddr = vaddr - t_addr + 0x800`.

## Traps (verified)

The same entry point under three wrong settings gives three plausible but wrong
decodes, which is why the confirm step (`ij`, `iS`, `ie`) exists:

```text
$ rizin -q -F psxexe -a mips -b 32 -E little -c 'pd 2 @ 0xENTRY' game.exe
            0xENTRY      lui   v0, ...             # correct
$ rizin -q -F psxexe -a mips -b 32 -E big -c 'pd 2 @ 0xENTRY' game.exe
        ┌─< 0xENTRY      blez  t4, ...             # wrong endianness
        │   0xENTRY      swr   s2, ...(a1)
$ rizin -q -F psxexe -a x86 -b 64 -c 'pd 2 @ 0xENTRY' game.exe
            0xENTRY      sbb   dword [rax-...], eax   # wrong arch
$ rizin -q -n -a mips -b 32 -E little -c 'iSj' -c 'pd 1 @ 0xENTRY' game.exe
ERROR: No binary object currently selected.
WARNING: Failed to read chunk of size 0x101 at 0xENTRY from io.
            0xENTRY      sdc3  31, -1(ra)             # no mapping (-n without -m)
```

Confirmed negatives on a PS-X EXE (do not read them as absence of code):
`iSSj` returns `[]` (one `TEXT` section, no segments); `izxj` returned `0` even
after `aaa`; `aav` printed nothing and changed nothing.

## Decompiling PS1 code (rz-ghidra)

When the build carries rz-ghidra, `pdg` decompiles MIPS; rizin reports the
matched sleigh language and can disassemble through Sleigh with p-code:

```text
$ rizin -q -c 'e cfg.bigendian=false; e asm.bits=32; e asm.arch=mips' \
    -c 'pdgss' -c 'pdgsd 4 @ 0xFUNC' game.exe
MIPS:LE:32:default:
0xFUNC: addiu sp, sp, -0x18
    sp = INT_ADD sp, 0xffffffe8
0xFUNC+4: sw ra, 0x10(sp)
    ...
```

(Temporary `unique` IDs differ between rz-ghidra builds; read the data flow,
not the numbers.)

- Naming and typing feed the output, as on x86: `afn NAME @ 0xFUNC` renames the
  function in the output; `afvt` on a local changes its declaration.
- Expect `// WARNING: [rz-ghidra] Matching calling convention n32 of function
  <name> failed, args may be inaccurate.` on MIPS function boundaries; verify
  arguments against the `pd` listing.
- GTE words stay holes. A function with GTE commands decompiles with many
  `Variable defined which should be unmapped` and `Removing unreachable block`
  warnings; annotate cop2 words by hand.
- If the plugin is missing (`pdg?` errors), pair the series (rizin 0.9.x with
  rz-ghidra 0.9.0, 0.8.x with 0.8.0) instead of copying plugins across
  releases; see the commands reference.

## Headerless, raw, and overlays

When the 0x800 header is missing or must be bypassed, map the raw file at the
address where its first byte lives at run time:

```text
$ rizin -q -n -a mips -b 32 -E little -m 0xLOAD \
    -c 'omlj' -c 'pd 2 @ 0xLOAD' raw.bin
```

- `-B` under `-n` does not map: `WARNING: Failed to read chunk of size 0x101
  at 0xADDR from io.` then garbage decode. Use `-n -m`.
- To map an untouched PS-X EXE file with `-n`, use `t_addr - 0x800`, so the
  first code byte lands on `t_addr`.
- Overlay files are raw code loaded at a fixed runtime address; open them the
  same way (`-n -m <loadaddr>`), one file per address. Equal load addresses in
  different overlays are unrelated code.
- Real PS-X EXE files need neither flag: the `psxexe` plugin handles the header.

## Delay slots and constructed addresses

- MIPS delay slots appear as ordinary instructions on the next line; rizin does
  not mark the slot, so read the instruction after every `jr`/`jalr`/`beq` as
  part of the transfer.
- `lui`/`addiu` and `lui`/`ori` pairs build full addresses. Rizin 0.9.1 does not
  resolve them for MIPS (the MIPS analysis plugin has no `.jmptbl` callback, and
  `afj` has the entry-size/count quirk), so read the pair and add the immediate
  by hand:

```text
lui   a0, 0x1f80
ori   a0, a0, 0x400     ; 0x1F800400
```

- `ahi` sets immediate-base hints and `aae` analyses ESIL refs, but expect to
  resolve most of these pairs manually or with a small rzpipe pass.
- `$gp`-relative accesses (`lw rt, imm(gp)`) are data accesses rizin does not
  resolve; note the offset and resolve it against the module's gp value, which
  comes from the header (initial GP) or from the startup code.

## BIOS calls: the A0h/B0h/C0h vectors

BIOS functions are reached through three entry points in low RAM, `A(nn)` at
0xA0, `B(nn)` at 0xB0 and `C(nn)` at 0xC0, and the function number selects the
routine (psx-spx, *Kernel (BIOS)*). Compiled code jumps to the vector with the
number in a register:

```text
addiu t2, zero, 0xa0
jr    t2
addiu t1, zero, 0x70     ; function number, in the delay slot
```

- Rizin prints no symbol or comment for these; the pattern is the evidence.
  Find the `jr` whose register holds 0xA0/0xB0/0xC0, read the delay slot for the
  number, then annotate with `CC` and `f`. Look the number up in psx-spx.
- Do not run function analysis at 0xA0/0xB0/0xC0: they are vector addresses in
  low RAM, not code.

## Memory map and the scratchpad

psx-spx, *Memory Map*:

| Region | KUSEG | Size |
| --- | --- | --- |
| Main RAM (first 64 KB reserved for BIOS) | 0x00000000 | 2048 KB |
| Scratchpad (D-Cache as fast RAM) | 0x1F800000 | 1 KB (0x1F800000-0x1F8003FF) |
| I/O ports | 0x1F801000 | 4 KB |
| DEV8 expansion | 0x1F802000 | 8 KB |
| BIOS ROM | 0x1FC00000 | 512 KB |

- KSEG0 is the cached mirror (`0x80000000+`); KSEG1 is uncached (`0xA0000000+`,
  so I/O registers are usually 0xBF801xxx).
- The scratchpad is not executable and is mirrored only in KUSEG/KSEG0.
- Code builds scratchpad pointers with `lui`+`ori`/`addiu` on 0x1F80.

## Hardware registers

psx-spx, *I/O Map* (all inside 0x1F801000-0x1F801FFF; KSEG1 adds 0xA0000000):

| Block | Range | Layout |
| --- | --- | --- |
| Memory control / SIO | 0x1F801000-0x1F80106F | mem control, SIO0 (pad/memcard), SIO1, DRAM_CTRL |
| Interrupts | 0x1F801070-0x1F801077 | I_STAT (R=status, W=ack), I_MASK, 16-bit |
| DMA | 0x1F801080-0x1F8010FF | D0 MDECin, D1 MDECout, D2 GPU, D3 CD-ROM, D4 SPU, D5 PIO, D6 OTC; MADR/BCR/CHCR, DPCR 0x...F0, DICR 0x...F4 |
| Timers | 0x1F801100-0x1F80112F | T0/T1/T2 at +0x00/+0x10/+0x20; COUNT/MODE/COMP |
| CD-ROM | 0x1F801800-0x1F801803 | index-banked registers (status/result/data, command/param) |
| GPU | 0x1F801810-0x1F801817 | GP0 0x1F801810, GP1 0x1F801814 |
| MDEC | 0x1F801820-0x1F801827 | MDEC0 data/command, MDEC1 control/status |
| SPU | 0x1F801C00-0x1F801FFF | voices at 0x1F801C00 + 0x10*N; main volume 0x1F801D80; reverb 0x1F801DC0 |

Interrupt bits (psx-spx, *Interrupts*): 0 VBLANK, 1 GPU, 2 CDROM, 3 DMA,
4-6 TMR0-2, 7 controller/memcard, 8 SIO, 9 SPU, 10 lightpen/PIO.

Most game code reaches hardware through the BIOS or DMA, so direct I/O accesses
are rare. A scan for `lui xx, 0x1f80` immediates is a lower bound, not a census.

## GTE (`cop2`)

Rizin 0.9.1 has no GTE support: the Capstone-based MIPS analyzer has no GTE
decoder, the register profile lacks `cop2` registers, and GTE command words
disassemble as `invalid`. Plain cop2 transfers (`mfc2`/`swc2`) decode but cannot
be re-assembled:

```text
0xADDR      invalid                  ; 0x4A180001 = RTPS
```

Annotate GTE words with `CC`/`f` from a name table, and do not trust `aez`/ESIL
through GTE-heavy code. Command numbers (low 6 bits of the word; the raw word is
`0x4A...` for the common `sf=1` forms): 01 RTPS, 06 NCLIP, 0C OP, 10 DPCS,
11 INTPL, 12 MVMVA, 13 NCDS, 14 CDP, 16 NCDT, 1B NCCS, 1C CC, 1E NCS, 20 NCT,
28 SQR, 29 DCPL, 2A DPCT, 2D AVSZ3, 2E AVSZ4, 30 RTPT, 3D GPF, 3E GPL, 3F NCCT
(psx-spx, *Geometry Transformation Engine*).

## Identifying PsyQ library code

No PS1 signatures ship with rizin, and PsyQ `.LIB`/`.OBJ` files are Sony LNK
objects that rizin cannot parse (`rz-ar` and `rz-bin` fail on them). One route
is a community signature set that lists, per library, hex prelude bytes with
`??` wildcards plus label offsets (for example the `psx_psyq_signatures`
project), converted to FLIRT `.pat` text:

1. Take the first 32 bytes of a signature, map `??` to rizin's `..`, and emit a
   FLIRT text line: `<prelude> 00 0000 <size> :0000 <name>`. The line has no
   CRC, because PsyQ patterns mix wildcards and give no CRC window.

```text
<32 prelude bytes, ".." for wildcards> 00 0000 <size hex> :0000 <name>
```

2. Apply it, or drop it into the sigdb so `aaa` applies it automatically:

```text
$ rizin -q -a mips -b 32 -E little -c aa -c 'Fs /tmp/psyq_test.pat' -c 'afl~flirt' game.exe
Found 1 FLIRT signatures via /tmp/psyq_test.pat
$ mkdir -p /tmp/sigdb/psxexe/mips/32 && cp /tmp/psyq_test.pat /tmp/sigdb/psxexe/mips/32/
$ rizin -q -a mips -b 32 -E little -e flirt.sigdb.path=/tmp/sigdb -c aaa -c 'afl~flirt' -c 'Fl~psxexe' game.exe
```

The sigdb directory name must match the bin plugin (`psxexe`), the arch
(`mips`) and the bits (`32`), because `Fa`/`aaa` compare those fields against
the loaded binary. `.pat` entries bypass the architecture check that `.sig`
files enforce: a `.pat` carries no arch, and a `.sig` converted from one is
stamped `Architecture: 0 (x86)` and refused.

Caveats: matching is prelude-only without a CRC, so expect false positives on
32-byte preludes; keep the `flirt.` prefix so the names stay identifiable; and
apply extra label offsets only after you check them against the target.
`rz-sign -o out.sig binary` generates signatures from binaries rizin can parse
(not from PsyQ LNK objects).

A converter for one JSON entry (fields `sig` and `name`):

```python
"""Convert one signature JSON entry to a FLIRT .pat line."""
import json, sys

def to_pat(entry, size, path="/tmp/psyq_entry.pat"):
    prelude = entry["sig"].split(" ")[:32]
    wild = "".join(".." if b == "??" else b for b in prelude)
    line = f"{wild} 00 0000 {size:04X} :0000 {entry['name'].split('.')[0]}\n"
    open(path, "w").write(line)
    return line

if __name__ == "__main__":
    sigs, index, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3], 0)
    print(to_pat(json.load(open(sigs))[index], size))
```

- `Found 0` is normal for a single entry: library code appears only when the
  program links it, and wildcard-heavy preludes lose matches. Run `Fl`/`Fa`
  over the whole sigdb rather than chasing one entry.
- Confirm every `Found N` by disassembling around the renamed function;
  prelude-only matching cannot prove the body matches.

## Endianness traps

- PS-X EXE payloads are little-endian; `-E little` (0.9.x) or
  `e cfg.bigendian=false` (0.8.x) is mandatory, and `pxw`/`pf`/`/v` follow that
  setting.
- `paddr` bytes are the file order on disk (little-endian words), while `vaddr`
  is where the loader copied them; mixing the two shifts every address by 0x800
  plus the section base.
- A byte-swapped-looking instruction stream usually means the wrong endianness
  or a mis-detected format: check `e cfg.bigendian` and `ij` before deeper
  analysis.
- The `PS-X EXE` magic sits at file offset 0 but its `vaddr` reports as
  UT64_MAX; never use it as a relocation anchor.
