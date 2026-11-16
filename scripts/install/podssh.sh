#!/bin/sh
# The installer of podssh (the owner's ruling "Installer"), on the core of
# PodUtils/podcrates (scripts/install/core.sh). A release publishes it as
# podssh-install.sh, with the core inline and the pins of the release
# (pins.py stamp). This copy of the tree has no pins: it refuses to install.
# scripts/install/get-core.sh gets the core and pins.py at their pinned commit.
#
#   sh podssh-install.sh [--prefix DIR] [--dry-run] [--offline FILE] [--add-path FILE]
INST_NAME=podssh
INST_ENV=PODSSH_INSTALL
INST_REPO=PodUtils/podssh

# BEGIN PINS (scripts/install/pins.py writes this block; do not edit it)
INST_VERSION=""
INST_TARGETS=""
# END PINS

# BEGIN CORE (scripts/install/pins.py puts scripts/install/core.sh here)
# shellcheck source=scripts/install/core.sh
. "$(dirname "$0")/core.sh"
# shellcheck source=scripts/install/core-net.sh
. "$(dirname "$0")/core-net.sh"
# END CORE

# The binary prints "podssh X.Y.Z (COMMIT)": the version, then the commit.
inst_version_ok() {
    case $1 in "$INST_NAME $INST_VERSION" | "$INST_NAME $INST_VERSION "*) return 0 ;; *) return 1 ;; esac
}

# The self-check, with no network: the whole manual, from the binary's own
# tables. doctor needs the network, so it is the next step, the user's.
inst_selfcheck() {
    if "$1/podssh$inst_exe" man --json > /dev/null 2>&1; then
        inst_say "self-check: podssh man --json: ok; podssh doctor measures this host"
        return 0
    fi
    "$1/podssh$inst_exe" man --json 2>&1 | tail -n 5 >&2
    return 1
}

inst_main "$@"
