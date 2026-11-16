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
COMMIT=d21fd638d8aa82465643eb33b80537a1d1ddd00f # podcrates v0.63.0
CORE_SHA=1ab8578a5e2e44982d8d8f4b37fd910261958afc8666e8b0415fc8a1071beaaa
NET_SHA=63d365203c9bb1a1f8d322f2b83187e21f400f4023e6084a49e54a8d99f0def8
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
