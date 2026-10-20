# Tool command forms

Command shapes for the tools named in SKILL.md. Flags change between releases:
run `TOOL --help` before relying on one, and report the tool version with the
answer.

## rizin

One session, one analysis, many queries. Command semantics and the rzpipe
driver are in the `rizin` skill.

```text
$ rizin -q -a mips -b 32 -c 'e scr.color=false' -c 'e cfg.bigendian=false' \
    -c aa -c 'aflj' -c 'axtj @ 0xADDR' -c 'pd 20 @ 0xADDR' image.bin
```

Raw image without a header: add `-n -m 0xLOAD`. Check `ij`, `iSj`, and `ie`
first.

## objdump (second opinion, built objects)

```text
$ objdump -d -r -z OBJECT.o                                    # code with relocations inline
$ objdump -D -b binary -m mips:3000 -EL --adjust-vma=0xLOAD IMAGE.bin   # raw MIPS little-endian image
```

Use the cross build of binutils for the target (for example a
`mipsel-*-objdump`). Relocation lines show symbol and addend, which a plain
byte diff hides.

## xxd (raw bytes)

```text
$ xxd -s $((0xVADDR - 0xLOAD + 0xHEADER)) -l 16 image.bin
```

`HEADER` is the number of file bytes before the loaded payload (0 for a raw
image).

## m2c (first C draft from MIPS assembly)

```text
$ python3 m2c.py --context ctx.c -f FUNC function.s
```

Output is a starting point: types, control flow, and struct accesses need
manual correction. A context file with the struct and prototype declarations
improves the result. Check `--help` for the `--target` value that matches the
compiler.

## Ghidra headless (decompiler reading aid)

```text
$ analyzeHeadless PROJECT_DIR PROJECT_NAME -import image.bin \
    -processor "MIPS:LE:32:default" -postScript ExportScript.java
```

Raw images need the load address set in the import (or the script). Treat
decompiler output as a reading aid and verify against the disassembly. The
rz-ghidra plugin (`pdg` in rizin) offers the same decompiler inside rizin.

## splat and spimdisasm (bulk disassembly and splitting)

```text
$ python3 -m splat split config.yaml
```

The config lists the segments and the symbol address file. Re-split after any
config or symbol change; generated assembly is stale otherwise.

## objdiff and asm-differ (compare built output with the target)

```text
$ objdiff-cli diff -1 expected.o -2 candidate.o SYMBOL
```

objdiff compares relocatable objects: use it for pre-link inspection, not
acceptance. asm-differ compares assembly of a function from the target and a
build and re-runs on change.

## decomp-permuter (register-allocation residuals)

```text
$ ./import.py candidate.c target.s
$ ./permuter.py DIRECTORY -j 8
```

Start from a candidate that is close and structurally right. See SKILL.md
(Compiler behavior) for what the permuter cannot fix.

## rabbitizer (single words)

See SKILL.md (Word decode). Install with `pip install rabbitizer`.

## ast-grep (C source structure)

```text
$ ast-grep run -p 'FuncName($A);' -l c src/
```

A call pattern needs the trailing `;`. Use it instead of text search when
matching syntax, such as every call with a given argument shape.

## jq (wrapper and rizin JSON)

```text
$ rizin -qc 'aa; aflj' image.bin | jq '[.[] | select(.size > 100) | {name, offset, size}]'
```
