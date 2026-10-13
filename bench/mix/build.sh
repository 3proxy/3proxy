#!/bin/sh
# Builds the mix load generator and origin for the machines the benchmark runs
# on: static Linux binaries for x86_64 and aarch64, next to this script, where
# bench.py looks for them. Needs Go 1.22 or later, on any system.
set -e
cd "$(dirname "$0")"
for arch in amd64 arm64; do
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "mix-linux-$arch" .
	echo "bench/mix/mix-linux-$arch"
done
