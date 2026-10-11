#!/bin/sh
# Builds 3proxy versions for comparison, each from a clean tree and with the
# Makefile it shipped with, into bench/bin/3proxy-<name>.
#
#   bench/build.sh 0.9.9.1 1.0.1 devel     git refs (tags, branches, commits)
#   bench/build.sh .                       the working tree, uncommitted
#                                          changes included, as "worktree"
#   NAME=devel-splice EXTRA_CFLAGS=-DWITHSPLICE bench/build.sh devel
#   CC="gcc -fcommon" bench/build.sh 0.8.13   old Makefiles set CFLAGS
#                                          outright, so a flag a newer
#                                          compiler needs goes with CC
#
# Run from anywhere inside the repository.

set -e

top=$(git rev-parse --show-toplevel)
out="$top/bench/bin"
work="${TMPDIR:-/tmp}/3proxy-bench-src"
mkdir -p "$out" "$work"

for ref in "$@"; do
	if [ "$ref" = "." ]; then
		name=${NAME:-worktree}
		src="$work/$name"
		rm -rf "$src"
		mkdir -p "$src"
		# tracked and untracked files as they are now, nothing ignored
		(cd "$top" && git ls-files -co --exclude-standard -z |
			xargs -0 sh -c 'for f; do [ -f "$f" ] && printf "%s\0" "$f"; done' sh |
			tar cf - --null -T - ) | (cd "$src" && tar xf -)
	else
		name=${NAME:-$ref}
		src="$work/$name"
		rm -rf "$src"
		mkdir -p "$src"
		(cd "$top" && git archive "$ref") | (cd "$src" && tar xf -)
	fi
	echo "== $name"
	(
		cd "$src"
		mkdir -p bin
		make -f Makefile.Linux CC="${CC:-gcc}" EXTRA_CFLAGS="$EXTRA_CFLAGS" >build.log 2>&1 ||
			{ tail -20 build.log; exit 1; }
	)
	# versions before 0.9 leave the binary in src/
	for b in "$src/bin/3proxy" "$src/src/3proxy"; do
		[ -f "$b" ] && break
	done
	cp "$b" "$out/3proxy-$name"
	echo "   $out/3proxy-$name"
done
