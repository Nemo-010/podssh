"""scripts/fuzz-seeds.py: the seeds of the fuzz targets of fuzz/ (T-198).

Each seed is bytes that podssh did not make: the IRC lines that
crates/podssh-core/tests/fixtures/grammar.txt recorded from the RFCs and from
real servers, and the messages of Cap'n Proto that the reference encoder
wrote for the quick tunnel (crates/podssh-relay/tests/fixtures/quick/,
T-403). They go into fuzz/corpus/TARGET/, which libFuzzer reads first and
adds to. scripts/fuzz.sh runs this before each run. The targets of the
WebSocket frames, of the relay's lists and pool, of DNS answers and of WARP's
capsules moved with their code to PodUtils/podcrates (T-684), with their
seeds; this script seeds none of them, and counts only what it writes.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "fuzz" / "corpus"


def put(target, seed):
    """Write `seed` under its digest, as libFuzzer names a corpus file."""
    directory = CORPUS / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / hashlib.sha1(seed).hexdigest()).write_bytes(seed)


def irc_lines():
    """The wire lines of the grammar fixture, each with its CRLF."""
    text = (ROOT / "crates/podssh-core/tests/fixtures/grammar.txt").read_bytes()
    for line in text.split(b"\r\n"):
        if line.startswith(b"#") or b" ||| " not in line:
            continue
        yield line.split(b" ||| ", 1)[0] + b"\r\n"


def main():
    lines = list(irc_lines())
    if not lines:
        sys.exit("fuzz-seeds.py: the grammar fixture gave no line")
    for line in lines:
        put("irc_message", line)
    # The first byte of an input of irc_framing is where it is cut in two.
    put("irc_framing", bytes([7]) + b"".join(lines))
    messages = sorted((ROOT / "crates/podssh-relay/tests/fixtures/quick").glob("*.bin"))
    if not messages:
        sys.exit("fuzz-seeds.py: no message of Cap'n Proto in crates/podssh-relay/tests/fixtures/quick")
    for message in messages:
        frame = message.read_bytes()
        put("capnp_message", frame)
        if message.name.startswith("quic-connect-"):
            put("quick_connect_request", frame)
        if message.name.startswith("rpc-"):
            # The first byte of an input of quick_control is where it is cut.
            put("quick_control", bytes([min(len(frame) // 2, 255)]) + frame)
    print(f"fuzz-seeds.py: {len(lines)} IRC lines, {len(messages)} messages of Cap'n Proto")


if __name__ == "__main__":
    main()
