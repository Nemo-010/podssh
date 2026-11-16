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
# role. Throwaway keys, in a directory of this run alone. Exit 0 when ssh and
# a copy of 20 MiB with equal SHA-256 pass.
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
