#!/usr/bin/env python3
"""The outage cell of scripts/feel-matrix.py (T-786), as osewa's
bench/outage.py measures one: a session that prints, its link cut by netem
at 100% loss for 15 s, a burst of 20 MiB written by the far end during the
cut, then the time from the link's return to the first byte and to the
burst's end. Two rounds, each a session of its own.

The far end's command says READY, sleeps 2 s, writes the burst and END, so
the burst starts inside the cut. The cut is checked: a byte that arrives
from one second into the cut to its end means that it did not hold, and the
cell fails (its planted defect is a cut left out).

`--self-test` runs the cell offline with a local `sh` for the session and a
cut that changes nothing: a cut of 1 s before a burst at 2 s holds, and
one of 4 s that lets the burst through is caught.
"""

import json
import subprocess
import sys
import threading
import time

CUT_S = 15.0
BURST = 20 * 1048576
ROUNDS = 2
# The burst begins this long after READY: inside the cut.
PAUSE_S = 2
READY_LIMIT = 60.0
AFTER_LIMIT = 180.0
EXIT_LIMIT = 30.0
# Bytes in flight when the cut begins may still land in its first second.
GRACE_S = 1.0
CUT = ["loss", "100%"]


def far_command(burst=BURST, pause=PAUSE_S):
    """The far end's shell command: READY, a pause, the burst, END."""
    return f"echo READY; sleep {pause}; head -c {burst} /dev/zero; echo; echo END"


class Reader:
    """A child's stdout read in a thread: each chunk's time and size, and
    the times of READY and of END."""

    def __init__(self, proc):
        self.proc, self.chunks, self.total = proc, [], 0
        self.ready = self.end = None
        self.tail = b""
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while True:
            data = self.proc.stdout.read1(65536)
            if not data:
                return
            now = time.monotonic()
            self.chunks.append((now, len(data)))
            self.total += len(data)
            self.tail = (self.tail + data)[-16:]
            if self.ready is None and b"READY\n" in self.tail:
                self.ready = now
            if self.end is None and self.tail.endswith(b"END\n"):
                self.end = now

    def wait(self, test, limit):
        deadline = time.monotonic() + limit
        while not test():
            if time.monotonic() > deadline or (self.proc.poll() is not None and not self.thread.is_alive()):
                return test()
            time.sleep(0.02)
        return True

    def bytes_between(self, start, stop):
        return sum(n for t, n in self.chunks if start <= t < stop)

    def first_after(self, start):
        return next((t for t, _ in self.chunks if t >= start), None)


def ms(seconds):
    return round(seconds * 1000, 1)


class Stamped:
    """The child's stderr into `err`, each line after the seconds since the
    round's start, with the cut and the return on the same clock: a `-v`
    line is read against the cut's end (T-789)."""

    def __init__(self, proc, err):
        self.t0, self.lock = time.monotonic(), threading.Lock()
        self.sink = open(err, "ab")
        self.thread = threading.Thread(target=self.pump, args=(proc.stderr,), daemon=True)
        self.thread.start()

    def line(self, text):
        with self.lock:
            self.sink.write(f"{time.monotonic() - self.t0:9.3f} {text}".encode(errors="replace"))
            self.sink.flush()

    def pump(self, stream):
        for raw in iter(stream.readline, b""):
            self.line(raw.decode(errors="replace").rstrip("\n") + "\n")

    def close(self):
        self.thread.join(5)
        self.sink.close()


def one_round(argv, env, cut, err, cut_s=CUT_S, burst=BURST, pause=PAUSE_S):
    """One session through `argv` + the far command; `cut(on)` cuts and
    restores the link. Its figures, or an `error`."""
    got = {"exit": None, "error": None}
    proc = subprocess.Popen(argv + [far_command(burst, pause)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    stamped = Stamped(proc, err)
    reader, cut_on = Reader(proc), False
    try:
        if not reader.wait(lambda: reader.ready is not None, READY_LIMIT):
            got["error"] = f"no READY within {READY_LIMIT:.0f} s"
            return got
        began = time.monotonic()
        cut(True)
        cut_on = True
        stamped.line("feel: the cut begins\n")
        time.sleep(cut_s)
        up = time.monotonic()
        cut(False)
        cut_on = False
        stamped.line("feel: the link is back\n")
        leaked = reader.bytes_between(began + GRACE_S, up)
        got["leaked_bytes"] = leaked
        got["held"] = leaked == 0
        if not reader.wait(lambda: reader.end is not None, AFTER_LIMIT):
            got["error"] = f"no END within {AFTER_LIMIT:.0f} s of the link's return ({reader.total} bytes)"
        first = reader.first_after(up)
        got["first_ms"] = ms(first - up) if first is not None else None
        got["catch_up_ms"] = ms(reader.end - up) if reader.end is not None else None
        got["bytes"] = reader.total
        if not got["held"] and got["error"] is None:
            got["error"] = f"the cut did not hold: {leaked} bytes arrived during it"
    finally:
        if cut_on:
            cut(False)
        try:
            got["exit"] = proc.wait(EXIT_LIMIT)
        except subprocess.TimeoutExpired:
            proc.kill()
            got["exit"] = proc.wait()
            got["error"] = got["error"] or f"no exit within {EXIT_LIMIT:.0f} s of END"
        reader.thread.join(5)
        stamped.close()
    if got["exit"] != 0 and got["error"] is None:
        got["error"] = f"exit {got['exit']}"
    return got


def measure(client, argv, env, cut, err, rounds=ROUNDS, **knobs):
    """The cell's document: each round, and `exit` 0 when each held and
    caught up, else 1."""
    done = [one_round(argv, env, cut, err, **knobs) for _ in range(rounds)]
    doc = {"schema": 1, "client": client, "cut_s": knobs.get("cut_s", CUT_S), "burst": knobs.get("burst", BURST),
           "far": far_command(knobs.get("burst", BURST), knobs.get("pause", PAUSE_S)), "rounds": done}
    doc["exit"] = 0 if all(r["error"] is None for r in done) else 1
    doc["error"] = next((r["error"] for r in done if r["error"]), None)
    return doc


def note(doc):
    """The cell's figures for a line of summary.tsv."""
    if doc is None:
        return "no outage document"
    parts = [f"first {r.get('first_ms')} ms, caught up {r.get('catch_up_ms')} ms" for r in doc["rounds"]]
    return "; ".join(parts) + (f" ({doc['error']})" if doc.get("error") else "")


def netem_cut(links, ports):
    """A cut of `ports` through feel_netem's Links."""
    def cut(on):
        links.clear()
        if on:
            links.install(CUT, ports)
    return cut


def cell(bench, road, links, osewa_road):
    """The outage cell of one road of feel-matrix's bench: OpenSSH, osewa's
    exec, or podssh ssh; its document is written as ROAD.outage.json."""
    if road == "openssh":
        argv = ["ssh", "-F", "/dev/null", "-o", "LogLevel=ERROR", "-o", "IdentityAgent=none",
                "-p", str(bench.sshd_port)] + bench.common(bench.work / "known_hosts.openssh")
        argv, env = argv + [f"{bench.user}@127.0.0.1"], bench.env()
    elif osewa_road is not None:
        import feel_osewa  # beside this file, as feel-matrix imports it
        o = bench.osewa
        env = o.env(bench.env(), {**o.client, "OSEWA_CARRIER": osewa_road})
        argv = [o.program, "exec", feel_osewa.HOST, "--", "sh", "-c"]
    else:
        flags, dest, _ = bench.road(road)
        argv = [bench.podssh, "ssh"] + flags + bench.common(bench.work / f"known_hosts.{road}") + [dest]
        env = bench.env()
    ports = bench.ports()
    if road == "role":
        # The client's leg alone: the role's port, never the sshd's, which
        # the role's own leg uses; the name of `bench.road` is the loopback.
        env = bench.env(PODSSH_RELAY_ADDR="relay-a.test=127.0.0.1")
        ports = [bench.role_port]
        # The layer's lines (each spare link, each resume) in ROAD.outage.err,
        # to read against the cut's end (T-789).
        argv = argv[:2] + ["-v"] + argv[2:]
    doc = measure(road, argv, env, netem_cut(links, ports), bench.out / f"{road}.outage.err")
    with open(bench.out / f"{road}.outage.json", "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    return doc


def self_test():
    import os
    import tempfile
    argv, err = ["sh", "-c"], os.path.join(tempfile.gettempdir(), "feel-outage-self-test.err")
    calls = []
    small = {"rounds": 1, "burst": 1048576, "pause": 2}
    held = measure("sh", argv, None, calls.append, err, cut_s=1.0, **small)
    leaked = measure("sh", argv, None, calls.append, err, cut_s=4.0, **small)
    r, s = held["rounds"][0], leaked["rounds"][0]
    checks = {
        "a cut before the burst holds": held["exit"] == 0 and r["held"] and r["bytes"] == 1048576 + 11,
        "the first byte after the return is the burst's, a second later": 600 <= (r["first_ms"] or 0) <= 2000,
        "the catch-up ends at END": r["catch_up_ms"] is not None and r["catch_up_ms"] >= r["first_ms"],
        "a cut that lets the burst through is caught": leaked["exit"] == 1 and not s["held"]
        and "did not hold" in (leaked["error"] or ""),
        "each cut is restored": calls == [True, False, True, False],
        "the note names both figures": "first" in note(held) and "caught up" in note(held),
    }
    for name, ok in checks.items():
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    print(json.dumps({"usage": "feel_outage.py --self-test; the cell runs from feel-matrix.py --shapes outage"}))
    sys.exit(2)
