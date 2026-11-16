#!/bin/sh
# scripts/install/get-core.sh - get the installer core (core.sh) and
# pins.py of PodUtils/podcrates at their pinned commit, each checked by its
# SHA-256, into DIR (default: scripts/install, beside podssh.sh, which
# includes core.sh from its own directory; git ignores both). The release
# stamps podssh.sh with them; a local test does the same.
#
#   sh scripts/install/get-core.sh [DIR]
#
# A new pin: the commit of a podcrates tag, and the SHA-256 of each file at
# it. A file that does not agree is removed, and the run fails.
set -eu
COMMIT=ca1107f171e4c24ef515a94ef32fed68ab220705 # podcrates v0.58.0
CORE_SHA=64b5397b4beabce75f41fe4f19c1f813ae4b8647235d5245f5041931bc0077c7
PINS_SHA=fad06e6cb9843053f722f98bfffa7c2d304bc7e8ea24ce6fe3650264a675f472
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
get pins.py "$PINS_SHA"
