"""The stage `role` of scripts/relay-measure.py (T-726): the rate of podssh's
own relay role, `podssh relay serve`, on this host's loopback, as podssh's
client gets it. The role and an OpenSSH sshd run as scripts/smoke_servers.py
starts them (a throwaway CA, keys in a scratch directory of .work/, deleted
at the end); each measure is a run of `podssh ping` through the role.

  one      `ping --size SIZE`: the throughput down and up of one session.
  many     PARALLEL sessions of `ping --size SIZE` at once: the sum of the
           bytes of each over the wall time of all, down and up together.
  connect  `ping --connect-runs N`: cold connects (the token, TLS, the
           upgrade, the SSH login and `true`), one after the other; and
           PARALLEL such runs at once, their count over the wall time.
  memory   the role's peak resident memory (VmHWM of /proc; Linux alone).

A release build measures the role; a debug build measures the debug build.
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import smoke_servers as servers  # noqa: E402


class Run:
    """What smoke_servers needs of a run: the binary, the scratch directory,
    the environment, and `run`."""

    def __init__(self, podssh, scratch):
        self.podssh, self.w = str(podssh), scratch
        self.env = servers.isolated_env(scratch)
        self.key = scratch / "id_ed25519"
        self.port = self.user = self.relay = None

    def run(self, args, timeout=120):
        try:
            r = subprocess.run([self.podssh, *args], capture_output=True, timeout=timeout, cwd=self.w, env=self.env,
                               stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return None
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")

    def ping(self, *flags):
        return [self.podssh, "ping", "--json", *flags, "--relay-host", f"relay.test:{self.relay}", "--relay-addr",
                "relay.test=127.0.0.1", "--ca-file", str(self.w / "ca.pem"), "-p", str(self.port), "-i",
                str(self.key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
                f"UserKnownHostsFile={self.w / 'known_hosts'}", f"{self.user}@127.0.0.1"]


def at_once(r, commands, limit):
    """Each of `commands` at once: (wall seconds, each parsed JSON or the
    reason it has none)."""
    started = time.monotonic()
    procs = [subprocess.Popen(c, cwd=r.w, env=r.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              stdin=subprocess.DEVNULL) for c in commands]
    out = []
    for p in procs:
        try:
            stdout, stderr = p.communicate(timeout=max(1.0, limit - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            out.append("no end within the limit")
            continue
        try:
            out.append(json.loads(stdout))
        except ValueError:
            out.append(f"exit {p.returncode}: {stderr.decode(errors='replace').strip()[-200:]}")
    return time.monotonic() - started, out


def mib(n):
    return round(n / (1 << 20), 1)


def peak_memory(pid):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    except OSError:
        return None
    return None


def measure(podssh, size="30M", parallel=16, connects=20, limit=600):
    """The stage's result: a JSON object with each measure, or why it has
    none; its sessions run through the role and nothing leaves the host."""
    root = HERE.parent / ".work"
    root.mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="role-measure-", dir=root))
    r = Run(Path(podssh).resolve(), scratch)
    result = {"stage": "role", "host": sys.platform, "size": size, "parallel": parallel}
    sshd = relay = None
    try:
        made = r.run(["keygen", "-q", "-t", "ed25519", "-N", "", "-C", "measure", "-f", str(r.key)])
        if made is None or made[0] != 0:
            return {**result, "error": "podssh keygen made no key"}
        r.port, r.user, sshd = servers.start_sshd(r)
        r.relay, relay = servers.start_relay(r)
        _, (one,) = at_once(r, [r.ping("--size", size)], limit)
        if isinstance(one, dict) and one["destination"].get("error") is None:
            d = one["destination"]
            result["one"] = {"down_mib_s": round(d["down"]["bytes"] / (1 << 20) / d["down"]["seconds"], 1),
                             "up_mib_s": round(d["up"]["bytes"] / (1 << 20) / d["up"]["seconds"], 1)}
        else:
            result["one"] = {"error": one if isinstance(one, str) else one["destination"].get("error")}
        wall, many = at_once(r, [r.ping("--size", size) for _ in range(parallel)], limit)
        done = [m for m in many if isinstance(m, dict) and m["destination"].get("error") is None]
        moved = sum(m["destination"]["down"]["bytes"] + m["destination"]["up"]["bytes"] for m in done)
        result["many"] = {"sessions": parallel, "passed": len(done), "wall_s": round(wall, 2),
                          "moved_mib": mib(moved), "mib_s": round(moved / (1 << 20) / wall, 1),
                          "failed": [m for m in many if not isinstance(m, dict)][:3]}
        _, (cold,) = at_once(r, [r.ping("--connect-runs", str(connects))], limit)
        if isinstance(cold, dict) and cold["destination"].get("connect"):
            c = cold["destination"]["connect"]
            result["connect"] = {"runs": c["runs"], "p50_ms": c["p50_ms"], "p95_ms": c["p95_ms"]}
        wall, runs = at_once(r, [r.ping("--connect-runs", str(connects)) for _ in range(parallel)], limit)
        opened = sum(m["destination"]["connect"]["runs"] for m in runs
                     if isinstance(m, dict) and m["destination"].get("connect"))
        result["connect_parallel"] = {"sessions": parallel, "connects": opened, "wall_s": round(wall, 2),
                                      "per_s": round(opened / wall, 1)}
        peak = peak_memory(relay.pid)
        result["memory"] = {"peak_mib": mib(peak)} if peak else {"error": "no /proc on this host"}
    finally:
        servers.stop(relay)
        servers.stop_sshd(r, sshd)
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)
    return result


if __name__ == "__main__":
    print(json.dumps(measure(sys.argv[1]), indent=1))
