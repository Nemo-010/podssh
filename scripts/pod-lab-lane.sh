#!/bin/sh
# WIP T-791: commands 2, 3 and 5 of podssh's lane in pod-lab (LANES.md), run in a lab:
#   podlab run PROFILE -- sh scripts/pod-lab-lane.sh PODSSH WORKDIR
# WORKDIR holds name (a pair on the live relay whose node serves a throwaway
# sshd outside the lab), user_key (its authorized key) and big with big.sha
# (200 MiB and its SHA-256). Commands 2 and 3 passed in ten profiles on
# 2026-11-16 (T-791); command 5 (pipe) is UNVERIFIED.
B=$1; W=$2; NAME=$(cat $W/name); want=$(cat $W/big.sha)
o="-i $W/user_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
got=$(timeout 90 $B ssh $o node://root@$NAME echo lane-ok </dev/null) || { echo "FAIL ssh rc=$?"; exit 1; }
[ "$got" = lane-ok ] || { echo "FAIL ssh said '$got'"; exit 1; }
echo "ok ssh"
rm -f /root/lane-remote/big
s=$(date +%s); timeout 600 $B cp --timeout 600s $o $W/big node://root@$NAME:/root/lane-remote/big </dev/null || { echo "FAIL cp up rc=$?"; exit 1; }
up=$(( $(date +%s) - s ))
r=$(sha256sum < /root/lane-remote/big | cut -c1-64); [ "$r" = "$want" ] || { echo "FAIL cp up: the hash differs"; exit 1; }
echo "ok cp up 200 MiB in ${up} s"
rm -f $W/back
s=$(date +%s); timeout 600 $B cp --timeout 600s $o node://root@$NAME:/root/lane-remote/big $W/back </dev/null || { echo "FAIL cp down rc=$?"; exit 1; }
dn=$(( $(date +%s) - s ))
r=$(sha256sum < $W/back | cut -c1-64); [ "$r" = "$want" ] || { echo "FAIL cp down: the hash differs"; exit 1; }
echo "ok cp down 200 MiB in ${dn} s"
rm -f $W/back /root/lane-remote/big
# Command 5: podssh pipe to the node's target, whose first bytes are the SSH banner.
got=$(sleep 3 | timeout 60 $B pipe stdio node:$NAME 2>/dev/null | head -c 7)
[ "$got" = SSH-2.0 ] || { echo "FAIL pipe said '$got'"; exit 1; }
echo "ok pipe: the target's banner"
