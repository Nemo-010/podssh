"""The servers of scripts/smoke-operator.py (T-728): an OpenSSH sshd and
`podssh relay serve` on free ports of 127.0.0.1, the environment of a run,
and the small tools of its rows. Apart from smoke-operator.py so that each
file stays within 500 lines.
"""

import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

WINDOWS = sys.platform == "win32"
MSYS2 = Path(os.environ.get("MSYS2_ROOT", r"C:\msys64"))
BASH = MSYS2 / "usr" / "bin" / "bash.exe"
PACKAGES = "openssh openssl"


def cannot_run(why):
    print(f"smoke-operator: the rows did not run: {why}", flush=True)
    sys.exit(2)


def isolated_env(scratch):
    """This process's environment with HOME, the cache and the settings in
    `scratch`, no agent and no setting of podssh's own; a proxy stays for
    `update --check`, and the relay's name goes around it."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PODSSH_") and k != "SSH_AUTH_SOCK"}
    home = scratch / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        env[name] = str(home)
    for name, sub in (("XDG_CACHE_HOME", "cache"), ("XDG_CONFIG_HOME", "config"), ("LOCALAPPDATA", "local"),
                      ("APPDATA", "roaming")):
        (scratch / sub).mkdir(exist_ok=True)
        env[name] = str(scratch / sub)
    skip = "relay.test,127.0.0.1,localhost"
    for name in ("NO_PROXY", "no_proxy"):
        env[name] = ",".join(p for p in (env.get(name, ""), skip) if p)
    env["PODSSH_SETTINGS"] = "none"
    return env


def msys(command, timeout=120):
    """COMMAND in MSYS2's bash, a login shell that stays in this directory."""
    env = dict(os.environ, MSYSTEM="MSYS", CHERE_INVOKING="1")
    try:
        return subprocess.run([str(BASH), "-lc", command], env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        cannot_run(f"MSYS2's bash did not finish in {timeout} s: {command}")


def posix(path):
    if not WINDOWS:
        return str(path)
    r = msys(f"cygpath -u '{path}'", 60)
    if r.returncode != 0 or not r.stdout.strip():
        cannot_run(f"cygpath could not convert {path}: {r.stderr.strip()}")
    return r.stdout.strip()


def install():
    if not WINDOWS:
        return
    for flags in ("-S", "-Sy"):
        r = msys(f"pacman {flags} --noconfirm --needed {PACKAGES}", 900)
        if r.returncode == 0:
            print(f"smoke-operator: pacman {flags}: {PACKAGES} installed", flush=True)
            return
        print(f"pacman {flags} exited {r.returncode}:\n{r.stdout[-1500:]}{r.stderr[-1500:]}", flush=True)
    cannot_run(f"pacman could not install {PACKAGES}")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def command_line(words):
    """One line of `words` for a ProxyCommand or an EDITOR."""
    return subprocess.list2cmdline(words) if WINDOWS else shlex.join(words)


def openssh_client():
    """OpenSSH's client: Windows' own on Windows, else the one on PATH."""
    if WINDOWS:
        own = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"
        return str(own) if own.is_file() else None
    return shutil.which("ssh")


def plant_wrapper(r):
    """The words of `podssh proxy`; with the plant, a wrapper that writes one
    byte before the proxy's, as a podssh that wrote it would."""
    if r.env.get("PODSSH_SMOKE_PLANT") != "proxy-byte":
        return [r.podssh, "proxy"]
    wrapper = r.w / "plant.py"
    wrapper.write_text("import os, subprocess, sys\nos.write(1, b'X')\n"
                       "sys.exit(subprocess.call(sys.argv[1:]))\n")
    return [sys.executable, str(wrapper), r.podssh, "proxy"]


def read_some(pipe, seconds):
    """Up to 4 KiB of `pipe` within `seconds`; b"" at its end or past them.
    A thread reads, as Windows has no select() on a pipe."""
    import threading
    got = []
    reader = threading.Thread(target=lambda: got.append(os.read(pipe.fileno(), 4096)), daemon=True)
    reader.start()
    reader.join(max(seconds, 0.1))
    return got[0] if got else b""


def tail(path, lines=8):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return f"({Path(path).name}: none)"
    return "\n".join(f"  {Path(path).stem}| {line}" for line in text[-lines:])


def wait_for(path, text, seconds, proc):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if text in Path(path).read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            pass
        if proc.poll() is not None:
            return False
        time.sleep(0.3)
    return False


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def sshd_binary():
    if WINDOWS:
        return "/usr/bin/sshd"
    for candidate in (shutil.which("sshd"), "/usr/sbin/sshd", "/usr/local/sbin/sshd"):
        if candidate and Path(candidate).is_file():
            return candidate
    cannot_run("no sshd here")


def user():
    if WINDOWS:
        name = msys("id -un", 60).stdout.strip()
    else:
        import getpass
        name = getpass.getuser()
    if not name:
        cannot_run("no user name")
    return name


def start_sshd(r):
    """An sshd on a free port of 127.0.0.1, its host key made by podssh, a
    key login for this user alone: (port, user, process)."""
    w = r.w
    host_key = w / "host_ed25519"
    if WINDOWS:
        # MSYS2's own, as interop-conpty-msys2.py makes it: its sshd reads the
        # modes of the file as MSYS2 wrote them.
        made = msys(f"ssh-keygen -q -t ed25519 -N '' -C smoke-host -f '{posix(host_key)}'", 60).returncode == 0
    else:
        got = r.run(["keygen", "-q", "-t", "ed25519", "-N", "", "-C", "smoke-host", "-f", str(host_key)])
        made = got is not None and got[0] == 0
    if not made:
        cannot_run("no host key was made")
    if not WINDOWS:
        os.chmod(host_key, 0o600)
    (w / "authorized_keys").write_bytes((w / "id_ed25519.pub").read_bytes())
    port = free_port()
    lines = [f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {posix(host_key)}",
             f"PidFile {posix(w / 'sshd.pid')}", f"AuthorizedKeysFile {posix(w / 'authorized_keys')}",
             "PubkeyAuthentication yes", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
             "StrictModes no", "Subsystem sftp internal-sftp"]
    config = w / "sshd_config"
    binary = sshd_binary()
    if not WINDOWS and os.geteuid() == 0:
        Path("/run/sshd").mkdir(exist_ok=True)
    # UsePAM no where the sshd knows the word: a non-root sshd cannot use PAM.
    for extra in (["UsePAM no"], []):
        config.write_bytes(("\n".join(lines + extra) + "\n").encode())
        if WINDOWS:
            ok = msys(f"{binary} -t -f '{posix(config)}'", 60).returncode == 0
        else:
            ok = subprocess.run([binary, "-t", "-f", str(config)], capture_output=True).returncode == 0
        if ok:
            break
    else:
        cannot_run(f"{binary} refused its configuration")
    log = open(w / "sshd.log", "wb")
    if WINDOWS:
        env = dict(os.environ, MSYSTEM="MSYS", CHERE_INVOKING="1")
        proc = subprocess.Popen([str(BASH), "-lc", f"exec {binary} -D -e -f '{posix(config)}'"], env=env,
                                stdout=log, stderr=subprocess.STDOUT)
    else:
        proc = subprocess.Popen([binary, "-D", "-e", "-f", str(config)], stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            cannot_run(f"sshd exited with {proc.returncode}:\n{tail(w / 'sshd.log')}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.settimeout(5)
                if s.recv(64).startswith(b"SSH-2.0-"):
                    return port, user(), proc
        except OSError:
            time.sleep(0.5)
    stop(proc)
    cannot_run(f"sshd did not answer on 127.0.0.1:{port} in 30 s:\n{tail(w / 'sshd.log')}")


def stop_sshd(r, proc):
    if proc is None:
        return
    pid = (r.w / "sshd.pid").read_text().strip() if (r.w / "sshd.pid").exists() else ""
    if WINDOWS and pid:
        msys(f"kill {pid}", 30)
    stop(proc)


def openssl():
    found = shutil.which("openssl")
    if found:
        return [found]
    for candidate in (Path(r"C:\Program Files\Git\usr\bin\openssl.exe"), MSYS2 / "usr" / "bin" / "openssl.exe"):
        if candidate.is_file():
            return [str(candidate)]
    cannot_run("no openssl to make the relay's throwaway CA")


def make_certificates(w):
    """A throwaway CA and a P-256 certificate of relay.test, in `w`."""
    tool = openssl()
    (w / "openssl.cnf").write_text("[req]\ndistinguished_name = dn\n[dn]\n")
    (w / "leaf.ext").write_text("subjectAltName = DNS:relay.test\nbasicConstraints = critical, CA:FALSE\n"
                                "keyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n")
    cnf = ["-config", str(w / "openssl.cnf")]
    steps = [
        ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(w / "ca.key")],
        ["req", "-x509", "-new", "-key", str(w / "ca.key"), "-subj", "/CN=podssh smoke CA", "-days", "2",
         "-out", str(w / "ca.pem"), *cnf, "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(w / "leaf.key")],
        ["req", "-new", "-key", str(w / "leaf.key"), "-subj", "/CN=relay.test", "-out", str(w / "leaf.csr"), *cnf],
        ["x509", "-req", "-in", str(w / "leaf.csr"), "-CA", str(w / "ca.pem"), "-CAkey", str(w / "ca.key"),
         "-set_serial", str(int(time.time())), "-days", "2", "-out", str(w / "leaf.pem"),
         "-extfile", str(w / "leaf.ext")],
    ]
    for step in steps:
        r = subprocess.run(tool + step, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            cannot_run(f"openssl {step[0]} exited {r.returncode}: {r.stderr.strip()[-300:]}")
    if not WINDOWS:
        os.chmod(w / "leaf.key", 0o600)


def start_relay(r):
    """`podssh relay serve` on a free port of 127.0.0.1, minting for anyone
    and dialing the loopback: (port, process)."""
    make_certificates(r.w)
    port_file = r.w / "relay.port"
    log = open(r.w / "relay.log", "wb")
    proc = subprocess.Popen([r.podssh, "relay", "serve", "--listen", "127.0.0.1:0", "--port-file", str(port_file),
                             "--cert", str(r.w / "leaf.pem"), "--key", str(r.w / "leaf.key"), "--mint", "anyone",
                             "--allow-private"], cwd=r.w, env=r.env, stdout=log, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            cannot_run(f"relay serve exited with {proc.returncode}:\n{tail(r.w / 'relay.log')}")
        text = port_file.read_text().strip() if port_file.exists() else ""
        if text.isdigit():
            return int(text), proc
        time.sleep(0.3)
    stop(proc)
    cannot_run(f"relay serve wrote no port in 30 s:\n{tail(r.w / 'relay.log')}")
