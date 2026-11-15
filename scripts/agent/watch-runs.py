#!/usr/bin/env python3
"""Watch the GitHub Actions runs of one repository, for a session whose
account cannot start or see a run itself.

One line for each run that starts, each that ends (with its conclusion and
the names of its failed jobs), and each rerun (a new attempt of a run). Run
it under a monitor of the session, beside the watcher of issues, so that a
run that the owner's agent started is seen at once and not waited for.

    python3 -I scripts/agent/watch-runs.py OWNER/REPO [STATE_FILE] [SECONDS]
    python3 -I scripts/agent/watch-runs.py --self-test

The reads go through forge.web.pkgforge.dev/github, a keyless read-only
mirror of GitHub's REST API (https://forge.web.pkgforge.dev/llms.txt). Its
quota is shared by each caller of an address (GitHub's 60 an hour), so it
polls each SECONDS (default 120), adds a little jitter, and backs off on
403, 429 and 5xx, after `Retry-After` when the mirror gives one. The first
poll records what exists and prints nothing for it. Stdlib only.
"""
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

MIRROR = "https://forge.web.pkgforge.dev/github"
# Transient answers of the mirror or of GitHub behind it.
TRANSIENT = (403, 429, 500, 502, 503, 504)
TRIES = 6
LONGEST = 900


def get(path, n, opener=None):
    """The JSON of `path`, or None after TRIES transient answers. A query
    word `n` defeats the mirror's cache, as watch-org.sh does."""
    sep = "&" if "?" in path else "?"
    wait = 20
    for _ in range(TRIES):
        url = f"{MIRROR}/{path}{sep}n={n}{random.randint(0, 1 << 30)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "watch-runs"})
        try:
            with (opener or urllib.request.urlopen)(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in TRANSIENT:
                raise
            after = e.headers.get("Retry-After") if e.headers else None
            time.sleep(int(after) if after and after.isdigit() else wait + random.uniform(0, 5))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            time.sleep(wait + random.uniform(0, 5))
        wait = min(wait * 2, LONGEST)
    return None


def failed_jobs(repo, run, n, fetch=get):
    """The names of a failed run's failed jobs, or [] when not read."""
    doc = fetch(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100", n)
    if not doc:
        return []
    return [j["name"] for j in doc.get("jobs", []) if j.get("conclusion") not in ("success", "skipped", None)]


def line(run, word, jobs=()):
    sha = (run.get("head_sha") or "")[:7]
    attempt = run.get("run_attempt") or 1
    tail = f", attempt {attempt}" if attempt > 1 else ""
    end = f": {run.get('conclusion')}" if run.get("status") == "completed" else ""
    failed = f" (failed: {', '.join(jobs)})" if jobs else ""
    return f"RUN {word}: {run.get('name')} {run.get('id')} ({run.get('event')}, {sha}{tail}){end}{failed}"


def step(repo, seen, runs, announce, n, fetch=get):
    """The lines of one poll; `seen` maps a run's id to [attempt, status]."""
    out = []
    for run in reversed(runs):
        key = str(run["id"])
        attempt, status = run.get("run_attempt") or 1, run.get("status")
        before = seen.get(key)
        word = None
        if before is None:
            word = "ended" if status == "completed" else "started"
        elif attempt > before[0]:
            word = "ended" if status == "completed" else "rerun"
        elif before[1] != "completed" and status == "completed":
            word = "ended"
        if word and announce:
            jobs = failed_jobs(repo, run, n, fetch) if status == "completed" and run.get("conclusion") == "failure" else []
            out.append(line(run, word, jobs))
        seen[key] = [attempt, status]
    # Keep the newest 200 runs, so the state stays small.
    for key in sorted(seen, key=int)[:-200]:
        del seen[key]
    return out


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save(path, seen):
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(seen, f)
    os.replace(tmp, path)


def main(argv):
    if len(argv) < 2 or "/" not in argv[1]:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: watch-runs.py OWNER/REPO [STATE_FILE] [SECONDS] | --self-test", file=sys.stderr)
        return 64
    repo = argv[1]
    state = argv[2] if len(argv) > 2 else f".work/agent/runs-{repo.replace('/', '_')}.json"
    pause = int(argv[3]) if len(argv) > 3 else 120
    os.makedirs(os.path.dirname(state) or ".", exist_ok=True)
    seen = load(state)
    announce = seen is not None
    seen = seen or {}
    n, down = 0, False
    while True:
        n += 1
        doc = get(f"repos/{repo}/actions/runs?per_page=30", n)
        if doc is None:
            if not down:
                print(f"RUN watcher: the mirror did not answer {TRIES} times; it goes on trying", flush=True)
            down = True
        else:
            down = False
            for text in step(repo, seen, doc.get("workflow_runs", []), announce, n):
                print(text, flush=True)
            save(state, seen)
            announce = True
        time.sleep(pause + random.uniform(0, 10))


def self_test():
    ok = True

    def check(what, got, want):
        nonlocal ok
        good = got == want
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} {what}" + ("" if good else f": {got!r}, not {want!r}"))

    def run(i, status="in_progress", conclusion=None, attempt=1):
        return {"id": i, "name": "build", "event": "push", "head_sha": "abcdef0123", "status": status,
                "conclusion": conclusion, "run_attempt": attempt}

    jobs = {"jobs": [{"name": "gate (ssh)", "conclusion": "failure"}, {"name": "plan", "conclusion": "success"}]}
    fetch = lambda path, n: jobs  # noqa: E731
    seen = {}
    check("the first poll says nothing", step("o/r", seen, [run(1, "completed", "success")], False, 1, fetch), [])
    check("a new run starts", step("o/r", seen, [run(2), run(1, "completed", "success")], True, 2, fetch),
          ["RUN started: build 2 (push, abcdef0)"])
    check("a run that ends red names its failed jobs",
          step("o/r", seen, [run(2, "completed", "failure")], True, 3, fetch),
          ["RUN ended: build 2 (push, abcdef0): failure (failed: gate (ssh))"])
    check("an unchanged poll says nothing", step("o/r", seen, [run(2, "completed", "failure")], True, 4, fetch), [])
    check("a rerun is a new attempt", step("o/r", seen, [run(2, "queued", None, 2)], True, 5, fetch),
          ["RUN rerun: build 2 (push, abcdef0, attempt 2)"])
    check("the rerun ends green", step("o/r", seen, [run(2, "completed", "success", 2)], True, 6, fetch),
          ["RUN ended: build 2 (push, abcdef0, attempt 2): success"])
    check("a run seen first as ended says so", step("o/r", seen, [run(3, "completed", "cancelled")], True, 7, fetch),
          ["RUN ended: build 3 (push, abcdef0): cancelled"])
    for i in range(10, 260):
        seen[str(i)] = [1, "completed"]
    step("o/r", seen, [], True, 8, fetch)
    check("the state keeps the newest 200 runs", (len(seen), min(map(int, seen))), (200, 60))
    print("watch-runs self-test:", "passed" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main(sys.argv))
