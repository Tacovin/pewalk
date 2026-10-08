# pewalk

Small PE (Windows .exe / .dll) triage tool in plain C. I wrote it because I kept opening three different tools to answer the same first questions about a binary: what built it, is it packed, is there anything that runs before `main`, and is there something glued to the end of the file.

No dependencies, builds with MSVC or GCC, and also runs on Linux (useful for looking at samples outside of Windows).

## What it shows

- headers, subsystem, image base, entry point and which section it lands in
- exploit mitigations from `DllCharacteristics` (ASLR, DEP, CFG, HighEntropyVA), plus a warning when ASLR is set but relocations were stripped
- section table with entropy per section and R/W/X flags
- **Rich header**: decoded entries (tool, build number, Visual Studio version) and a **checksum check**. The key at the end of the Rich header is a checksum over the DOS header and the entries, so a mismatch means the entries were edited. (It won't catch a header copied whole from another file with the same DOS stub. That's what happened with Olympic Destroyer, which was caught because the copied header said VB6 while the file never imported the VB6 runtime.)
- imports per DLL, exports
- **TLS callbacks** (code that runs before the entry point, a common anti-debug spot)
- PDB path from the CodeView debug entry, and whether the build is reproducible (`/Brepro`, where the timestamp is a hash and not a date)
- **overlay** data after the last section. The Authenticode signature and the COFF symbol table gcc/mingw leave at the end are accounted for separately, so signed files and mingw builds don't show up as false positives
- a "notes" section with things worth a second look: RWX sections, high entropy, entry point in the last section, known packer section names, injection / anti-debug imports, tiny import tables that resolve APIs at runtime, faked timestamps

The notes are hints, not a verdict. Plenty of normal software imports `NtQueryInformationProcess` or has a high entropy resource section.

## Build

GCC / MinGW:

```
make
```

MSVC (from a *x64 Native Tools Command Prompt*):

```
build.bat
```

The binary ends up in `build/`.

## Usage

```
pewalk [-i] [-e] [-j] file...
  -i   list every imported function
  -e   list every exported name
  -j   json output (one object per line)
```

Example:

```
$ pewalk C:\Windows\System32\notepad.exe
C:\Windows\System32\notepad.exe  (200704 bytes)

  Machine       AMD64, PE32+
  Type          EXE
  Subsystem     Windows GUI
  Timestamp     2028-06-20 07:03:09 UTC  (reproducible build, not a real date)
  Image base    0x140000000
  Entry point   0x23bd0  (.text)
  Mitigations   ASLR yes, DEP yes, CFG yes, HighEntropyVA yes
  PDB path      notepad.pdb

Sections (7)
  Name      VirtAddr    VirtSize    RawPtr      RawSize     Entropy  Flags
  .text     0x00001000  0x0002448f  0x00000400  0x00024600     6.27  R-X
  .rdata    0x00026000  0x00009288  0x00024a00  0x00009400     5.93  R--
  .data     0x00030000  0x00002718  0x0002de00  0x00000e00     1.81  RW-
  .pdata    0x00033000  0x000010ec  0x0002ec00  0x00001200     4.94  R--
  .didat    0x00035000  0x00000178  0x0002fe00  0x00000200     2.52  RW-
  .rsrc     0x00036000  0x00000bd8  0x00030000  0x00000c00     4.61  R--
  .reloc    0x00037000  0x000002d8  0x00030c00  0x00000400     4.13  R--

Rich header  (key 0x24fb72e6, checksum ok)
  ProdID  Tool                 Build  Toolchain       Count
  0x0093                       30729  VS2008          48
  0x0104  Utc1900_C            27412  VS2017          10
  0x0103  Masm1400             27412  VS2017          3
  0x0101  Implib1400           27412  VS2017          9
  0x0001  Import0                  0  -               1320
  0x0108  Utc1900_LTCG_C       27412  VS2017          31
  0x0105  Utc1900_CPP          27412  VS2017          31
  0x00fd                       27412  VS2017          1
  0x00ff  Cvtres1400           27412  VS2017          1
  0x0102  Linker1400           27412  VS2017          1

Imports  (28 DLLs, 260 functions)
  KERNEL32.dll                     82
  GDI32.dll                        22
  USER32.dll                       69
  ...
```

A gcc build with a TLS callback and 20000 random bytes appended (source in `tests/samples/tls_demo.c`). The COFF symbol table mingw leaves at the end of the file is recognised, so only the appended part is reported:

```
$ pewalk tls_overlay.exe
...
TLS callbacks
  0x140001760
  0x1400018a0
  0x140001959

Overlay       offset 0x7000, 52496 bytes, entropy 6.03
Symbol table  offset 0x7000, 32496 bytes (COFF symbols, gcc/mingw build)

Notes
  * 3 TLS callback(s), they run before the entry point. Set x64dbg to break on TLS callbacks
  * 20000 bytes of unexplained overlay data after 0x7000 (whole overlay entropy 6.03)
```

## Testing

`tests/check_pefile.py` runs pewalk with `-j` on a set of files and compares sections, entropy, imports, exports, Rich header and overlay offset against [pefile](https://github.com/erocarrera/pefile). CI runs it on every exe in `System32` and `SysWOW64` of the Windows runner. Locally it matched on all 4582 files I tried (every exe in System32 and SysWOW64 plus every dll in System32).

Two differences turned out to be pefile behaviour, not bugs, and the script accounts for them: pefile resolves ordinal imports of ws2_32/oleaut32 to names from its own table, and it assumes the Rich header starts at 0x80, which isn't true for files with a longer DOS stub (`tcblaunch.exe`).

`tests/fuzz_smoke.py` is a dumb mutation fuzzer (random bytes, truncation, big values in header fields) that checks pewalk never crashes on broken input.

```
pip install pefile
python tests/check_pefile.py build/pewalk.exe "C:/Windows/System32/*.exe"
```

## Limitations

- no resources, relocations, delay imports or load config parsing yet
- Rich header tool names only for VS2015+ product ids, older ones are printed as raw numbers
- whole file is read into memory, capped at 512 MB

## References

- [Microsoft PE format docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- Daniel Pistelli, *Microsoft's Rich Signature (undocumented)*
- Kaspersky GReAT, *The devil's in the Rich header* (Olympic Destroyer)
- [corkami PE notes](https://github.com/corkami/docs/blob/master/PE/PE.md)
