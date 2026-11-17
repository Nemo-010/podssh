#!/bin/sh
# scripts/pod-lab-serve-lane.sh - podssh's lane behind a network class of
# pod-lab (T-791), with podssh's own relay role as the lab's server: the
# class's proxy (its credential, its ports, its TLS, its refused upgrade, its
# filter of names) stands between the client and the role, and an OpenSSH
# server on the lab's loopback is the target. No packet leaves the lab.
#
#   podlab run --serve 8443 --serve-ca PKI/ca.pem PROFILE -- \
#       sh scripts/pod-lab-serve-lane.sh PODSSH PKI
#
# PKI holds ca.pem, leaf.pem and leaf.key: a throwaway CA and a P-256
# certificate of listed.test, the lab's name of a served port, made before
# the lab as --serve-ca names the CA. RELAY (default listed.test:8443) and
# ADDR (sni-allowlist: RELAY=listed.test:443
# ADDR=--relay-addr=listed.test=192.0.2.1) say how the class reaches the
# role. Throwaway keys, in a directory of this run alone. Exit 0 when ssh, a
# copy of 20 MiB with equal SHA-256, pipe (command 5) and a session across a
# cut of its link (command 6) pass.
set -u
B=$1
# The relay host as the class reaches the served port, and its address where
# the class has no resolver for it.
RELAY=${RELAY:-listed.test:8443}
ADDR=${ADDR:-}
W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
cd "$W" || exit 1
# The CA and the certificate of listed.test, made before the lab (PKI, the
# second argument), as podlab's --serve-ca names the CA at its start.
PKI=$2
cp "$PKI/leaf.pem" "$PKI/leaf.key" "$PKI/ca.pem" .
chmod 600 leaf.key
cat "$SSL_CERT_FILE" ca.pem > trust.pem
# An OpenSSH server on the loopback, its host key and one user key.
ssh-keygen -q -t ed25519 -N '' -f host_key
ssh-keygen -q -t ed25519 -N '' -f user_key
cp user_key.pub authorized_keys
cat > sshd_config <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $W/host_key
AuthorizedKeysFile $W/authorized_keys
PasswordAuthentication no
StrictModes no
PidFile $W/sshd.pid
EOF
# OpenSSH's privilege separation needs its directory, which a lab may lack.
mkdir -p /run/sshd
/usr/sbin/sshd -f sshd_config -D -e > sshd.log 2>&1 &
# The relay role, behind the lab's proxy.
"$B" relay serve --listen 127.0.0.1:8443 --cert leaf.pem --key leaf.key --mint anyone --allow-private \
    > relay.log 2>&1 &
sleep 2
o="-i $W/user_key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=$W/known -o Port=2222"
# shellcheck disable=SC2086 # $ADDR and $o are lists of options, a word each
got=$(SSL_CERT_FILE=$W/trust.pem timeout 60 "$B" ssh --relay-host "$RELAY" $ADDR $o root@127.0.0.1 echo lane-ok 2> ssh.err)
rc=$?
if [ "$got" = lane-ok ]; then
    echo "ok   ssh through the class's proxy to the relay role, then to sshd"
else
    echo "FAIL ssh rc=$rc said '$got'"
    tail -5 ssh.err; tail -5 relay.log
    exit 1
fi
head -c 20971520 /dev/urandom > big
want=$(sha256sum < big | cut -c1-64)
s=$(date +%s)
# shellcheck disable=SC2086 # $ADDR and $o are lists of options, a word each
SSL_CERT_FILE=$W/trust.pem timeout 300 "$B" cp --timeout 300s --relay-host "$RELAY" $ADDR $o big "root@127.0.0.1:$W/back" 2> cp.err
rc=$?
got=$(sha256sum < back 2>/dev/null | cut -c1-64)
if [ "$rc" = 0 ] && [ "$got" = "$want" ]; then
    echo "ok   cp of 20 MiB through the class, equal SHA-256, in $(( $(date +%s) - s )) s"
else
    echo "FAIL cp rc=$rc"; tail -5 cp.err
    exit 1
fi
# Command 5: podssh pipe to sshd through the role; its first bytes are the
# server's banner.
# shellcheck disable=SC2086 # $ADDR is a list of options, a word each
got=$( (sleep 3) | SSL_CERT_FILE=$W/trust.pem timeout 60 "$B" pipe --relay-host "$RELAY" $ADDR stdio \
    relay:127.0.0.1:2222 2> pipe.err | head -c 7)
if [ "$got" = SSH-2.0 ]; then
    echo "ok   pipe through the class to sshd: its banner"
else
    echo "FAIL pipe said '$got'"; tail -5 pipe.err
    exit 1
fi
# Command 6: a session outlives a cut of its link. The client's TCP
# connections into the class (to its proxy, else to the relay's port) are
# destroyed in the middle of a session that prints a line each second; the
# resumable layer carries it on a new link, each line once and in order.
# A class whose way refuses the upgrade (ws-upgrade-refused) carries each
# link on the HTTP road, a session of the road each: the layer resumes on a
# new one, or the road's own requests go again within its 60 s, so that the
# layer loses no link. A session that ends at the cut fails the lane.
if [ -n "${HTTPS_PROXY:-}" ]; then
    hp=${HTTPS_PROXY#*://}; hp=${hp##*@}; hp=${hp%%/*}; P=${hp##*:}
else
    P=${RELAY##*:}
fi
want=$(seq 1 12 | sed 's/^/tick/')
# shellcheck disable=SC2086 # $ADDR and $o are lists of options, a word each
SSL_CERT_FILE=$W/trust.pem timeout 120 "$B" ssh -v --relay-host "$RELAY" $ADDR $o root@127.0.0.1 \
    'i=1; while [ $i -le 12 ]; do echo tick$i; i=$((i+1)); sleep 1; done' > ticks 2> resume.err &
pid=$!
sleep 4
if ! ss -K -t "dport = :$P" > /dev/null 2>&1; then
    echo "FAIL the lab let no socket be destroyed (ss -K); command 6 cannot run here"
    wait $pid; exit 1
fi
wait $pid
rc=$?
if [ "$rc" = 0 ] && [ "$(cat ticks)" = "$want" ] && grep -q "the session resumed" resume.err; then
    echo "ok   a session outlived a cut of its link: $(grep -o 'the session resumed after [0-9.]* s' resume.err)"
elif [ "$rc" = 0 ] && [ "$(cat ticks)" = "$want" ] && grep -q "each link goes on the HTTP road" resume.err; then
    echo "ok   a session on the HTTP road outlived a cut of its connections: the road's requests went again"
else
    echo "FAIL the session across a cut: rc=$rc, $(wc -l < ticks) lines of 12"; grep -i -E "resum|lost|link" resume.err | tail -8
    exit 1
fi
