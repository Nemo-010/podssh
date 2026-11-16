#!/bin/sh
# scripts/install/get-core.sh - get the installer core (core.sh and
# core-net.sh) and pins.py of PodUtils/podcrates at their pinned commit, each checked by its
# SHA-256, into DIR (default: scripts/install, beside podssh.sh, which
# includes core.sh from its own directory; git ignores both). The release
# stamps podssh.sh with them; a local test does the same.
#
#   sh scripts/install/get-core.sh [DIR]
#
# A new pin: the commit of a podcrates tag, and the SHA-256 of each file at
# it. A file that does not agree is removed, and the run fails.
set -eu
COMMIT=cbbd0168d467e9a09372a5e948aaef10b651734c # podcrates v0.61.0
CORE_SHA=11d55d5ceaa2f63db8689f0a5ff46a72e39fdc87d45157c877ff5a4d8f911282
NET_SHA=6004ef84d274be1d3477590d38413d0a49e9c571aba2430947e90b4160de373c
PINS_SHA=7a3632c60494b4aace45db37e88b277a1353e8713d60c288430b452e16ea0205
dir=${1:-$(dirname "$0")}
mkdir -p "$dir"
base="https://raw.githubusercontent.com/PodUtils/podcrates/$COMMIT/scripts/install"
get() {
    curl -qfsSL --retry 4 --max-time 60 -o "$dir/$1" "$base/$1"
    got=$(sha256sum "$dir/$1" | cut -d' ' -f1)
    if [ "$got" != "$2" ]; then
        rm -f "$dir/$1"
        echo "get-core.sh: $1 at $COMMIT has SHA-256 $got, not $2" >&2
        exit 1
    fi
    echo "get-core.sh: $1 at $COMMIT: ok"
}
get core.sh "$CORE_SHA"
get core-net.sh "$NET_SHA"
get pins.py "$PINS_SHA"
