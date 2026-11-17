"""The diagnostics of the stand-in relay (scripts/fake-relay.py, T-058):
`/relays.json` with the stand-in as its one pool host, and `/trace`, in the
live relay's shapes. Apart from the stand-in itself, so that each file stays
short."""

import asyncio
import json
import time
import urllib.parse

import fake_stream
from fake_ws import response


def relays_json(path, headers):
    """The live relay's `/relays.json`, with this stand-in as its pool."""
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
    authority = headers.get("host", "relay.test")
    name = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
    target, connect_url = None, None
    if "host" in query and "port" in query:
        target = {"host": query["host"][0], "port": int(query["port"][0]), "bucket": None, "source": "explicit"}
        connect_url = f"wss://{authority}/connect/{target['host']}/{target['port']}"
    doc = {
        "service": "tcp-ssh-relay", "version": "fake", "you": {"edge_colo": "TEST", "bucket": None},
        "target": target, "connect": connect_url, "policy": {"note": "a stand-in relay on the loopback"},
        "pool": [{"rank": 0, "name": "stand-in", "host": name, "bucket": None, "region": None,
                  "client_ms": 0, "target_ms": 0, "score_ms": 0}],
        "limits": {"connect_timeout_ms": 10000, "idle_timeout_ms": 180000, "max_session_ms": 43200000,
                   "max_session_bytes": 67108864, "max_frame_bytes": 262144, "udp": "unsupported",
                   "probe": fake_stream.limits()},
    }
    return json.dumps(doc).encode()


async def trace(writer, path, headers, token):
    """`/trace`: public alone; a dial of `target=HOST:PORT` needs the token in
    its header, never in the URL. The answer has the live relay's shape, and
    names no address or place of the caller."""
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)

    def send(doc):
        writer.write(response(200, "OK", json.dumps(doc).encode(), [("Content-Type", "application/json")]))

    if "token" in query:
        writer.write(response(400, "Bad Request", b"trace: a token belongs in the X-Relay-Token header"))
        return
    doc = {"request": {"edge_colo": "TEST", "path": "/trace"}, "relay": {"name": "stand-in", "version": "fake"}}
    if "target" not in query:
        send(doc)
        return
    if headers.get("x-relay-token") != token:
        writer.write(response(403, "Forbidden", b"trace: missing or wrong token"))
        return
    wanted = query["target"][0]
    host, _, port = wanted.rpartition(":")
    host = host.strip("[]")
    started = time.monotonic()
    try:
        t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 10)
    except (OSError, ValueError, asyncio.TimeoutError) as e:
        doc["target"] = {"error": f"refused: cannot reach {wanted}: {e}"}
        send(doc)
        return
    connect_ms = int((time.monotonic() - started) * 1000)
    first_ms, banner, seen = None, None, 0
    try:
        data = await asyncio.wait_for(t_reader.read(4096), 5)
        if data:
            first_ms, seen = int((time.monotonic() - started) * 1000), len(data)
            banner = data.split(b"\n")[0].rstrip(b"\r").decode("utf-8", "replace")
    except asyncio.TimeoutError:
        pass
    t_writer.close()
    doc["target"] = {"host": host, "port": int(port), "ok": True, "road": "loopback", "dialed": host,
                     "dialed_literal": True, "address_family": "4", "connect_ms": connect_ms,
                     "first_byte_ms": first_ms, "bytes_seen": seen,
                     "verdict": "live" if seen else "silent-or-unreachable", "banner": banner}
    send(doc)
