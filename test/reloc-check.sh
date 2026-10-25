#!/usr/bin/env bash
# ELF relocation handler check: import each relocatable object (Ghidra applies its relocations
# at addresses it chooses), link the same object with GNU ld at those addresses (undefined
# symbols at Ghidra's EXTERNAL addresses) and compare every loaded byte.
#   test/reloc-check.sh <ld> <objdump> <workdir> <object.o>...
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LD=$1 OD=$2 W=$(readlink -f "$3")
shift 3
mkdir -p "$W"
for o in "$@"; do
	n=$(basename "$o")
	p=$(mktemp -d "${TMPDIR:-/tmp}/or1k-rel.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$(readlink -f "$o")" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" 0 \
		-postScript DumpMem.java "$W/$n.mem" -deleteProject >"$W/$n.log" 2>&1 || tail -20 "$W/$n.log"
	rm -rf "$p"
	args=()
	# 8/16-bit data relocations: GNU ld cannot link them (bfd assertion), formula check only
	[[ $n == relocs_small.o ]] && { echo "-- $n: $(grep '^relocations' "$W/$n.sum"); $(python3 "$HERE/got_check.py" "$o" "$W/$n.sum" "$W/$n.mem" - | tail -1)"; continue; }
	for b in $(sed -n 's/^blocks: //p' "$W/$n.sum"); do
		case ${b%@*} in
		EXTERNAL) ;;
		%got) args+=("--section-start=.got=0x${b#*@}") ;;   # ld's GOT where Ghidra put its own
		*) args+=("--section-start=${b%@*}=0x${b#*@}") ;;
		esac
	done
	for s in $(sed -n 's/^external symbols: //p' "$W/$n.sum"); do
		args+=("--defsym=${s%@*}=0x${s#*@}")
	done
	if [[ $n == got_* ]]; then
		# GOT model: Ghidra's GOT is an artificial block, so compare what the sites compute
		"$LD" -static -e get_ext --no-warn-rwx-segments \
			"${args[@]}" "$o" -o "$W/$n.ld.elf"
		echo "-- $n: $(grep '^relocations' "$W/$n.sum"); $(python3 "$HERE/got_check.py" "$o" "$W/$n.sum" "$W/$n.mem" "$W/$n.ld.elf" | tail -1)"
		python3 "$HERE/got_check.py" "$o" "$W/$n.sum" "$W/$n.mem" "$W/$n.ld.elf" >/dev/null ||
			python3 "$HERE/got_check.py" "$o" "$W/$n.sum" "$W/$n.mem" "$W/$n.ld.elf" | head -20
		continue
	fi
	"$LD" -e _start --no-warn-rwx-segments "${args[@]}" "$o" -o "$W/$n.ld.elf"
	"$OD" -s "$W/$n.ld.elf" >"$W/$n.ld.s"
	echo "-- $n: $(grep '^relocations' "$W/$n.sum"); $(python3 "$HERE/rawcmp.py" "$W/$n.mem" "$W/$n.ld.s" | tail -1)"
done
