# rzpipe

Rizin from Python. One process stays open, you send it commands, and you get
JSON back. This page covers setup, the traps (a bad flag hangs forever), and
six scripts you can adapt.

Python driver for a live rizin process. Verified with `rzpipe` 0.6.2 against
Rizin 0.9.1 (upstream latest) and 0.8.2; pick the binary with
`rizin_home`/`PATH` and prefer the newest build available. The spawn flags must
match that binary: when the rizin you spawn rejects a flag it dies at startup
and `open()` then **blocks forever**, no exception, no timeout (verified:
`-E little` on 0.8.2 printed `rizin: illegal option -- E`, then `exit 124`
under `timeout 10`).

## Install and point it at a rizin build

```text
$ uv venv .venv
$ uv pip install --python .venv/bin/python 'rzpipe==0.6.2'
Checked 1 package in 0.38ms
```

`rzpipe.open()` spawns `<rizin> -q0 <file>` as a subprocess, so the binary it
uses matters. Pass the build explicitly, or put it first on `PATH`:

```python
rz = rzpipe.open(binary, rizin_home="/path/to/rizin/bin")
# open_sync.py: rze = os.path.join(rizin_home, "rizin") when rizin_home is set
```

Flags reach rizin before the filename, exactly like the CLI. Match them to the
binary (`commands.md` holds the full version matrix):

```python
rz = rzpipe.open(exe, flags=["-a", "mips", "-b", "32", "-E", "little"])            # 0.9.x
rz = rzpipe.open(exe, flags=["-a", "mips", "-b", "32", "-e", "cfg.bigendian=false"])  # 0.8.x
```

The portable form passes no endianness flag and sets it in-session; both
binaries then print the same instructions (verified 0.8.2 and 0.9.1, exit 0):

```python
rz = rzpipe.open(exe, flags=["-a", "mips", "-b", "32"])
rz.cmd("e cfg.bigendian=false")
```

## API essentials

| Call | Returns |
| --- | --- |
| `rz.cmd("pd 2 @ main")` | Raw text (errors included) |
| `rz.cmdj("aflj")` | Parsed JSON (dict/list), or `None` on empty or parse failure |
| `rz.cmdJ("ij")` | Same, as nested namedtuples (`ij` becomes `.core.format`) |
| `rz.set_timeout(secs)` | Per-command timeout (raises `TimeoutError`) |
| `with rzpipe.open(path) as rz:` | Closes the pipe on exit (`__exit__` calls `quit`) |
| `rz.quit()` | Sends `q`, closes and kills the process |

Error handling is the trap: a bad command does **not** raise. It prints rizin's
error on stderr and `cmdj` hands back `None`:

```text
$ python -c 'import rzpipe; r=rzpipe.open("/usr/bin/true"); print(repr(r.cmdj("definitely_not_a_command"))); r.quit()'
ERROR: Command 'definitely_not_a_command' does not exist.
...
None
```

Coalesce every JSON call (`rz.cmdj("aflj") or []`) and verify the keys you need
exist before reading them.

One pipe is one process. Do not share a pipe across threads or concurrent
tasks; open one pipe per worker. Prefer many queries in one process over many
processes.

## Cost: one pipe vs one process per query

Median of 30 runs, Rizin 0.9.1 + rzpipe 0.6.2:

| Binary | `rz.cmdj("ij")` on a persistent pipe | Fresh `rizin -q0 -c ij` process |
| --- | --- | --- |
| `/usr/bin/true` | **1.075 ms** | **26.3 ms** |
| PS-X EXE (1.4 MB) | **1.064 ms** | **711.5 ms** |

Analysis is the expensive part, not the pipe: run `aa`/`aaa` once per session
and keep querying. The fresh-process column is why shell loops over rizin are
the wrong shape for bulk work.

## Worked scripts

Each is self-contained; `open_binary` selects the rizin build.

```python
import json, os, rzpipe

BINARY = os.environ.get("RIZIN_BINARY", "/usr/bin/true")
RIZIN_HOME = os.environ.get("RIZIN_HOME")  # directory containing the rizin binary

def open_binary(path=BINARY):
    return rzpipe.open(path, rizin_home=RIZIN_HOME)
```

### 1. Function inventory to JSON

```python
def function_inventory():
    with open_binary() as rz:
        rz.cmd("aa")
        functions = rz.cmdj("aflj") or []
        return [
            {"offset": f["offset"], "size": f["size"], "name": f["name"]}
            for f in functions
            if f["name"] == "main"
        ]

# [{"offset": 9376, "size": 272, "name": "main"}]
```

### 2. Callers of a function

```python
def callers_of_first_call():
    with open_binary() as rz:
        rz.cmd("aa")
        main = rz.cmdj("afij @ main") or []
        if not main or not main[0].get("callrefs"):
            return []
        target = main[0]["callrefs"][0]["to"]
        return rz.cmdj(f"axtj @ {target:#x}") or []

# [{"from": 9411, "to": 12320, "type": "CALL"}]
```

`axt` = refs to the address. Without the `aa` before it the list is empty:
a failed analysis and a real no-caller answer look identical.

### 3. Find every use of an immediate in one function

```python
def uses_of_immediate_in_main():
    with open_binary() as rz:
        rz.cmd("aa")
        main = rz.cmdj("afij @ main") or []
        if not main:
            return []
        start = main[0]["offset"]
        end = start + main[0]["size"]
        rz.cmd(f"e search.from={start:#x}")
        rz.cmd(f"e search.to={end:#x}")
        return rz.cmdj("/aij 0x2") or []

# [{"offset": 9380, "len": 3, "code": "cmp edi, 0x02"}]
```

Scoping the search with `search.from`/`search.to` is what makes the result
exact; the default range is the current block or map.

### 4. Dump strings with both addresses

```python
def strings_with_file_and_virtual_addresses():
    with open_binary() as rz:
        strings = rz.cmdj("izj") or []   # izzj covers the whole file
        return [
            {"paddr": s.get("paddr"), "vaddr": s.get("vaddr"), "string": s.get("string")}
            for s in strings[:3]
        ]
```

On a PS-X EXE the pair differs by the mapping, and header strings use
`vaddr 18446744073709551615` (UT64_MAX) because they sit below the mapped
region:

```text
[{"paddr": 931, "vaddr": 931, "string": "^~p_+v"}, ...]            # /usr/bin/true
[{"paddr": ..., "vaddr": ..., "string": "..."}, ...]     # PS-X EXE, izj
```

### 5. Annotate a function list from a symbol file

`symbols.txt` holds `ADDRESS NAME` lines:

```text
0x24a0 sample_main
```

```python
import re

def annotate_from_file(symbol_file):
    symbols = []
    with open(symbol_file, encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            if len(fields) != 2:
                raise ValueError(f"{symbol_file}:{line_number}: expected ADDRESS NAME")
            address = int(fields[0], 0)
            name = fields[1]
            if not re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*", name):
                raise ValueError(f"{symbol_file}:{line_number}: invalid function name")
            symbols.append((address, name))

    with open_binary() as rz:
        rz.cmd("aa")
        annotated = []
        for address, name in symbols:
            rz.cmd(f"afn {name} @ {address:#x}")
            result = rz.cmdj(f"afij @ {address:#x}") or []
            if not result:
                raise ValueError(f"Rizin did not find a function at {address:#x}")
            annotated.append({"offset": result[0]["offset"], "name": result[0]["name"]})
        return annotated

# [{"offset": 9376, "name": "sample_main"}]
```

Validate names before interpolating them into `rz.cmd`: command strings are
parsed by rizin, so a name with spaces or `;` changes what runs. When a list is
large, write it to a script file and run `rizin -i` once instead of N `afn`
calls over the pipe.

## Robustness on real runs

| Behaviour | Evidence | Handling |
| --- | --- | --- |
| `open()` blocks forever when the spawned rizin dies at startup | `-E little` on 0.8.2 → `rizin: illegal option -- E`, no return; `timeout 10` → exit 124 | Test the flags on the CLI first; keep them version-correct; fix and reopen |
| Analysis writes `ESC[2K\r` to stderr | `aa` → 5 bytes (`\033[2K\r`) on 0.8.2 and 0.9.1; `2>&1` prepends it to the JSON | Keep stderr separate; never merge streams (or close it with `-2`) |
| `cmdj` returns `None` on error or empty output | `cmdj("definitely_not_a_command")` → `None` after stderr errors | `cmdj(...) or []`, then check keys before reading |
| `cmdJ` returns namedtuples | `rz.cmdJ("ij").core.format` → `elf64` | Use it for fixed-info reads only; JSON keys with dots become `_` |
| `set_timeout` raises `TimeoutError` | `set_timeout(0.002)` then `cmd("aaa")` → `Timeout reached on cmd: 'aaa'` | Wrap slow calls; treat timeout as a failed run |
| After a timeout, `quit()` also times out | same session: `quit` → `Timeout reached on cmd: 'q'` | `rz.set_timeout(-1)`, then `quit()`, verified to succeed |
| Bad `rizin_home` | `Exception: \`rizin_home\` passed is invalid, leave it None or put a valid path to rizin folder` | Validate the directory before opening |
| Colour escapes in text output | `cmd("pdJ 1 @ main")` carries `\u001b[38;2;…` | `cmd("e scr.color=false")` right after open |

### 6. Batch sweep: callref/dataref census in one session

```python
with open_binary() as rz:
    rz.cmd("e scr.color=false")
    rz.cmd("aa")
    rows = []
    for f in rz.cmdj("aflj") or []:
        info = (rz.cmdj(f"afij @ {f['offset']:#x}") or [{}])[0]
        rows.append({
            "name": f["name"],
            "size": f["size"],
            "callrefs": len(info.get("callrefs") or []),
            "datarefs": len(info.get("datarefs") or []),
        })
    busy = [r for r in rows if r["callrefs"] >= 4]

# rows[:3] -> {'name': 'sym.error', 'size': 185, 'callrefs': 2, 'datarefs': 2}, ...
# busy[:3] -> main (272, 12/18), fcn.00002bc0 (853, 25/36), fcn.000030b0 (169, 4/2)
```

One `aa`, then one `cmdj` per function: hundreds of functions stay in the
sub-second range that a fresh process per function cannot match (see the cost
table above).

## Driving the decompiler

`pdg` needs a plugin-capable (shared) rizin plus rz-ghidra, but rzpipe drives it
like any other command, verified against rizin 0.9.1 + rz-ghidra 0.9.0:

```python
rz = rzpipe.open(binary, flags=["-a", "mips", "-b", "32"],
                 rizin_home="/path/to/prefix/bin")
rz.cmd("e scr.color=false")
rz.cmd("e cfg.bigendian=false")   # portable endianness; see the flag note above
rz.cmd("aa")
code = rz.cmdj("pdgj @ main")["code"]   # x86-64 main gave 46 lines
```

`pdgx`/`pdgd` give XML; `pdg` prints the same text that `pdgj` returns in its
`code` field, so `{"errors": ...}` from `pdgj` is the robust error signal.

## Housekeeping

- `rizin_home` must be the **directory** that contains the `rizin` executable;
  a bad path raises `rizin_home passed is invalid`.
- `cmdj` returns `None` for empty output as well as for broken JSON, so log the
  raw `cmd` text when a result looks wrong.
- `rzpipe` adds no analysis of its own: every result is exactly what the
  equivalent CLI command prints.
