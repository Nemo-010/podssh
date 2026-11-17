#!/usr/bin/env python3
"""The second reader of podssh's wire vectors (T-723).

Written from docs/wire.md alone, with no code of podssh's codecs: it reads
each vector of crates/podssh-relay/tests/vectors/, decodes its bytes and
compares the fields, encodes its fields and compares the bytes, and checks
that the vectors' digest is the one of the page's newest version. The test
crates/podssh-relay/tests/wire_vectors.rs is the first reader, through the
codecs; a vector that both readers take is the page's, not one codec's.

Exit codes:

    0   each vector agrees with the page
    1   a vector, a version or a digest disagrees, each named
    2   a file could not be read. Never a pass.

Usage:
    check-wire-vectors.py           check each file
    check-wire-vectors.py --plant   change one byte of each file in memory;
                                    passes only when each change is found
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
import struct
import sys
from pathlib import Path

# The curve beside this file, also under `python -I`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import wire_ed25519 as ed  # noqa: E402
from wire_check_parts import check_grants, check_layer, digest_of, page_versions  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "wire.md"
VECTORS = ROOT / "crates" / "podssh-relay" / "tests" / "vectors"
PARTS = ("closes", "forward", "grants", "layer", "reverse", "tokens")


class Refused(Exception):
    """Bytes that the page refuses; its text is the vector's error name."""


# --- section 2: the forward road ---------------------------------------

OPCODES = {0x0, 0x1, 0x2, 0x8, 0x9, 0xA}


def ws_encode(fin: bool, opcode: int, payload: bytes, mask: bytes | None) -> bytes:
    out = bytes([(0x80 if fin else 0) | opcode])
    bit = 0x80 if mask is not None else 0
    n = len(payload)
    if n < 126:
        out += bytes([bit | n])
    elif n <= 0xFFFF:
        out += bytes([bit | 126]) + struct.pack(">H", n)
    else:
        out += bytes([bit | 127]) + struct.pack(">Q", n)
    if mask is None:
        return out + payload
    return out + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def ws_decode(raw: bytes, writer: str) -> tuple[bool, int, bytes, bytes | None]:
    if len(raw) < 2:
        raise Refused("short")
    fin, opcode, masked, n = bool(raw[0] & 0x80), raw[0] & 0x0F, bool(raw[1] & 0x80), raw[1] & 0x7F
    if raw[0] & 0x70:
        raise Refused("reserved bit")
    if opcode not in OPCODES:
        raise Refused("opcode")
    if masked != (writer == "client"):
        raise Refused("mask")
    at = 2
    if n == 126:
        n, at = struct.unpack(">H", raw[2:4])[0], 4
        if n < 126:
            raise Refused("length form")
    elif n == 127:
        n, at = struct.unpack(">Q", raw[2:10])[0], 10
        if n <= 0xFFFF:
            raise Refused("length form")
    if n > 262144:
        raise Refused("too long")
    if opcode >= 0x8 and (not fin or n > 125 or (opcode == 0x8 and n == 1)):
        raise Refused("control frame")
    mask = raw[at:at + 4] if masked else None
    at += 4 if masked else 0
    body = raw[at:]
    if len(body) != n:
        raise Refused("length")
    if mask is not None:
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
    return fin, opcode, body, mask


def check_forward(v: dict) -> list[str]:
    raw = bytes.fromhex(v["hex"])
    if v["kind"] == "frame-refused":
        try:
            ws_decode(raw, v["writer"])
        except Refused:
            return []
        return ["a frame that the page refuses was read"]
    mask = bytes.fromhex(v["mask"]) if "mask" in v else None
    payload = bytes.fromhex(v["payload"])
    problems = []
    if ws_encode(v["fin"], v["opcode"], payload, mask) != raw:
        problems.append("its fields do not encode to its bytes")
    try:
        if ws_decode(raw, v["writer"]) != (v["fin"], v["opcode"], payload, mask):
            problems.append("its bytes do not decode to its fields")
    except Refused as why:
        problems.append(f"its bytes are refused: {why}")
    return problems


# --- section 3: tokens --------------------------------------------------

LIFETIME_MS = 259200000


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def token_mac(secret: bytes, expiry: int) -> str:
    return b64url(hmac.new(secret, f"ephm1.{expiry}.forward".encode(), hashlib.sha256).digest())


def check_tokens(v: dict) -> list[str]:
    secret = bytes.fromhex(v["secret"])
    if v["kind"] == "mint":
        expiry = v["now_ms"] + min(v["lifetime_ms"], LIFETIME_MS)
        if (expiry, token_mac(secret, expiry)) != (v["expiry"], v["mac"]):
            return ["the minted expiry or mac is not the page's"]
        return []
    now, expiry = v["now_ms"], v["expiry"]
    taken = now < expiry <= now + LIFETIME_MS and hmac.compare_digest(v["mac"], token_mac(secret, expiry))
    return [] if taken == v["valid"] else [f"the page says valid={taken}"]


# --- section 4: the reverse road ----------------------------------------

ID_CHARS = re.compile(rb"^[0-9a-f]{32}$")


def node_decode(raw: bytes) -> tuple[str, bytes]:
    if len(raw) < 32:
        raise Refused("frame-too-short")
    if len(raw) > 65568:
        raise Refused("frame-too-long")
    if not ID_CHARS.match(raw[:32]):
        raise Refused("id-not-lowercase-hex")
    return raw[:32].decode(), raw[32:]


CLOSE_OF = {"frame-too-short": 1009, "frame-too-long": 1009, "id-not-lowercase-hex": 1003,
            "operator-payload-too-long": 1009}
MEMBERS = {"hello": None, "open": ("id",), "close": ("id", "reason"), "spent": ("digest",)}


def control_text(message: dict) -> str:
    ordered = {k: message[k] for k in ("type", "id", "reason") if k in message}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)


def control_read(text: str) -> dict:
    message = json.loads(text)
    kind = message.get("type")
    if kind not in MEMBERS:
        return {"type": "unknown"}
    return message


def check_reverse(v: dict) -> list[str]:
    kind = v["kind"]
    if kind == "node-frame":
        raw = bytes.fromhex(v["hex"])
        problems = [] if v["id"].encode() + bytes.fromhex(v["payload"]) == raw else ["fields do not encode"]
        try:
            if node_decode(raw) != (v["id"], bytes.fromhex(v["payload"])):
                problems.append("bytes do not decode to its fields")
        except Refused as why:
            problems.append(f"refused: {why}")
        return problems
    if kind == "operator-frame":
        return [] if v["payload"] == v["hex"] else ["an operator frame is its payload alone"]
    if kind == "node-frame-refused":
        try:
            node_decode(bytes.fromhex(v["hex"]))
        except Refused as why:
            ok = str(why) == v["error"] and CLOSE_OF[str(why)] == v["close"]
            return [] if ok else [f"refused as {why}, close {CLOSE_OF[str(why)]}"]
        return ["a frame that the page refuses was read"]
    if kind == "too-long":
        error = "frame-too-long" if v["leg"] == "node" else "operator-payload-too-long"
        ok = v["payload_len"] > 65536 and v["error"] == error and v["close"] == CLOSE_OF[error]
        return [] if ok else ["the page refuses it otherwise"]
    if kind == "chunks":
        n = v["bytes_len"]
        lens = [32 + min(65536, n - at) for at in range(0, n, 65536)] or [32]
        return [] if lens == v["frame_lens"] else [f"the page cuts it into {lens}"]
    if kind == "control-out":
        problems = [] if control_text(v["message"]) == v["text"] else ["the message does not encode to its text"]
        # The operator reads `ready`, `reject` and `close` as they are.
        if json.loads(v["text"]) != v["message"] or len(v["text"].encode()) > 4096:
            problems.append("its text does not read back, or passes 4096 bytes")
        return problems
    if kind == "control-in":
        return [] if control_read(v["text"]) == v["message"] else ["its text reads otherwise"]
    if kind == "control-cut":
        reason = "x" * v["reason_len"]
        while len(control_text({"type": "reject", "id": v["id"], "reason": reason}).encode()) > 4096:
            reason = reason[: len(reason) // 2]
        return [] if len(reason) == v["cut_len"] else [f"the page sends {len(reason)} bytes"]
    return [f"no kind {kind!r} in the page"]


# --- section 4: close codes ---------------------------------------------

def close_table(page: str) -> tuple[list[tuple[int, str, str, bool]], list[str]]:
    rows = re.findall(r"^\| (\d{4}) \| ([^|]+?) \| (never|new-pair|new-session|reconnect) \| (yes|no) \|$", page, re.M)
    refusals = re.search(r"The node's refusals, matched as written[^:]*: (.+)\.$", page, re.M)
    words = re.findall(r"`([^`]+)`", refusals.group(1)) if refusals else []
    return [(int(c), r, t, y == "yes") for c, r, t, y in rows], words


def classify(code: int, reason: str, rows, refusals) -> tuple[bool, str, bool]:
    needle = reason.strip().lower()
    row = next((r for r in rows if r[0] == code and r[1] == needle), None)
    if row is None and code in (1000, 1011) and (needle in ("node-supplied", "node supplied") or reason in refusals):
        row = next(r for r in rows if r[0] == code and r[1] == "node-supplied")
    if row is None and code in (1008, 1009, 1013):
        row = next(r for r in rows if r[0] == code)
    if row is None:
        unresumed = 1001 <= code <= 1003 or 1007 <= code <= 1010 or code >= 4000
        return False, "never", not unresumed
    return True, row[2], row[3]


def check_closes(v: dict, rows, refusals) -> list[str]:
    payload = struct.pack(">H", v["code"]) + v["reason"].encode()
    problems = [] if payload.hex() == v["payload"] else ["code and reason do not encode to its payload"]
    raw = bytes.fromhex(v["payload"])
    if (struct.unpack(">H", raw[:2])[0], raw[2:].decode()) != (v["code"], v["reason"]):
        problems.append("its payload does not decode to its code and reason")
    got = classify(v["code"], v["reason"], rows, refusals)
    if got != (v["matched"], v["retry"], v["resumes"]):
        problems.append(f"the page reads it as matched={got[0]} retry={got[1]} resumes={got[2]}")
    return problems


def main(argv: list[str]) -> int:
    plant = argv[1:] == ["--plant"]
    if argv[1:] and not plant:
        print(__doc__.strip().split("\n\n")[-1], file=sys.stderr)
        return 2
    problems = ed.self_test()
    try:
        page = PAGE.read_text(encoding="utf-8")
        docs = {p: json.loads((VECTORS / f"{p}.json").read_text(encoding="utf-8")) for p in PARTS}
        found = sorted(f.stem for f in VECTORS.glob("*.json"))
    except (OSError, ValueError) as e:
        print(f"check-wire-vectors: cannot read: {e}", file=sys.stderr)
        return 2
    rows, refusals = close_table(page)
    if len(rows) != 25 or len(refusals) != 9:
        problems.append(f"docs/wire.md: {len(rows)} rows of closes and {len(refusals)} refusals, not 25 and 9")
    checkers = {
        "forward": check_forward, "tokens": check_tokens, "reverse": check_reverse,
        "closes": lambda v: check_closes(v, rows, refusals), "layer": check_layer, "grants": check_grants,
    }

    def check_part(part: str, doc: dict) -> list[str]:
        out = []
        for v in doc["vectors"]:
            try:
                out += [f"{part}.json: {v['name']}: {p}" for p in checkers[part](v)]
            except (KeyError, ValueError, TypeError, IndexError, struct.error) as e:
                out.append(f"{part}.json: {v.get('name', '?')}: unreadable: {e!r}")
        return out

    if plant:
        return plant_each(docs, check_part)
    if found != sorted(PARTS):
        problems.append(f"the vector files are {found}, not {sorted(PARTS)}")
    version, rows_of_versions = page_versions(page)
    for part, doc in docs.items():
        if doc.get("wire") != version or doc.get("part") != part:
            problems.append(f"{part}.json: wire {doc.get('wire')} and part {doc.get('part')!r}, not {version}")
        problems += check_part(part, doc)
    problems += digest_problems(version, rows_of_versions, digest_of(VECTORS, PARTS))
    count = sum(len(d["vectors"]) for d in docs.values())
    for p in problems:
        print(f"check-wire-vectors: {p}")
    print(f"check-wire-vectors: {count} vectors of {len(docs)} files, wire version {version}: "
          + ("ok" if not problems else f"{len(problems)} problems"))
    return 1 if problems else 0


def digest_problems(version, rows, digest: str) -> list[str]:
    """The newest row of the page's versions is this version, with this digest."""
    if not rows:
        return ["docs/wire.md: no row of versions"]
    numbers = [n for n, _ in rows]
    problems = [] if len(set(numbers)) == len(numbers) else ["docs/wire.md: a version has two rows"]
    newest, written = rows[-1]
    if newest != version:
        problems.append(f"docs/wire.md: the newest row is version {newest}, the page says {version}")
    if written != digest:
        problems.append(f"the vectors' digest is {digest}, the row of version {newest} says {written}: "
                        "a changed vector needs a new version and a new row")
    return problems


def plant_each(docs: dict, check_part) -> int:
    """One changed character in the first vector of each file must be found."""
    missed = []
    for part, doc in docs.items():
        planted = copy.deepcopy(doc)
        first = planted["vectors"][0]
        key = next(k for k in ("hex", "mac", "payload", "text") if k in first)
        last = first[key][-1]
        first[key] = first[key][:-1] + ("0" if last != "0" else "1")
        found = check_part(part, planted)
        print(f"check-wire-vectors: planted {part}.json {first['name']} {key}: "
              + (f"found ({found[0]})" if found else "MISSED"))
        if not found:
            missed.append(part)
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
