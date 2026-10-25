> **Ghidra-Rare fork.** This branch adds tested fixes, release builds for the three newest Ghidra
> releases and test suites; see [GHIDRA-RARE.md](GHIDRA-RARE.md) for the test results and
> remaining gaps, and [CREDITS.md](CREDITS.md) for the original authors and every change.
> Prebuilt zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this fork's
> [Releases page](https://github.com/aleph-void/ghidra-or1k-le-hack/releases). The original
> README follows; only the parts that are no longer correct were changed (marked *Ghidra-Rare*).

This is a fork of https://github.com/smaeul/ghidra-or1k with support for the hx330x chip.

## Languages

*Ghidra-Rare:* the little-endian hack is now a separate language next to the original big-endian
one, instead of replacing it:

| Language ID | Use for | ELF auto-select |
|---|---|---|
| `OpenRISC:BE:32:default` | Standard OpenRISC 1000 (or1k): big endian, with delay slots. Linux, glibc, newlib and gcc output | e_machine 92 (EM_OPENRISC) or 0x8472, ELF32 MSB |
| `OpenRISC:LE:32:default` | Little endian, no delay slot (CPUCFGR[ND]), as in hx330x camera SoCs | e_machine 92, ELF32 LSB |

Both cover ORBIS32 with the ORFPX32/ORFPX64A32 floating-point extensions.

## To use

The original steps were:

- ~~Download Ghidra. I used 11.2.1, but probably later versions work as well.~~
- ~~Clone contents of this repo into ghidra_11.2.1_PUBLIC/Ghidra/Processors~~
- Select little endian of OR1K wgen disassembling hx330x image

*Ghidra-Rare:* this branch targets Ghidra 12.1.4 and is built and tested on 12.1.3, 12.1.4 and
12.2. It now has a Java part (ELF relocation handler and PLT extension), so cloning the sources
into `Ghidra/Processors` is no longer enough on its own. Install it one of these ways:

- **Release zip:** download the zip for your Ghidra version from the
  [Releases page](https://github.com/aleph-void/ghidra-or1k-le-hack/releases), then in Ghidra
  use *File > Install Extensions*, add the zip, and restart Ghidra.
- **From source:** `GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC gradle buildExtension`,
  then install the zip from `dist/` the same way.

For an hx330x image, select `OpenRISC:LE:32:default` (*little endian*, *no delay slot*). ELF
files select their language automatically.

## Upstream limitations

*Ghidra-Rare:* status of the limitations of the original hack:

- **Fixed:** the hack removed delay slots from the shared instruction file, so the big-endian
  language lost them too. Delay slots are back for big endian; only the little-endian language
  has none.
- **Fixed:** many decoding and semantics errors in the original specification (reserved bits,
  shift fields, `l.adrp`, `l.sys`, `l.jal` link address, missing float instructions, no ELF
  relocations). See [CREDITS.md](CREDITS.md).
- **Remaining:** the little-endian language passes the decode and emulator tests, but has not
  been tested on a real hx330x image, because those firmware images are vendor binaries with
  no public license.

Neither this repository nor smaeul/ghidra-or1k has open or closed issues.
