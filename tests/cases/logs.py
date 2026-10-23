"""Logs: one for each log string, shared by every service naming it, kept
over a reload while something uses it and closed once nothing does. A log
which cannot be written passes its lines to standard error."""

import os
import time


def _read(path):
    try:
        with open(path, "rb") as fp:
            return fp.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _proxied(path, mark):
    """Whether a proxy, not the origin, logged the request marked so."""
    return any(line.startswith("LOG PROXY") and mark in line
               for line in _read(path).splitlines())


def _wait(cond, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def _opened(pid, path):
    """How many times the process has the file open, None without /proc."""
    fds = f"/proc/{pid}/fd"
    if not os.path.isdir(fds):
        return None
    n = 0
    for fd in os.listdir(fds):
        try:
            if os.readlink(os.path.join(fds, fd)) == path:
                n += 1
        except OSError:
            pass
    return n


def config(origin, p1, p2, p3, adm, main, shared=None):
    """p2 and p3 log to shared with -l, if it is given, or are not there."""
    lines = [f"log {main}", 'logformat "LLOG %N %T"', "auth iponly", "allow *",
             "http data * /data", f"httpsrv -p{origin}", f"proxy -p{p1}"]
    if shared:
        lines += [f"proxy -p{p2} -l{shared}", f"proxy -p{p3} -l{shared}"]
    lines.append(f"admin -p{adm}")
    return "\n".join(lines) + "\n"


def run(t):
    origin, p1, p2, p3, adm = (t.free_port() for _ in range(5))
    first = os.path.join(t.tmpdir, "logs-first.log")
    second = os.path.join(t.tmpdir, "logs-second.log")
    shared = os.path.join(t.tmpdir, "logs-shared.log")

    server = t.start("logs", config(origin, p1, p2, p3, adm, first, shared),
                     ports=[origin, p1, p2, p3, adm])
    pid = server.proc.pid

    def get(port, mark):
        return t.http(f"http://127.0.0.1:{origin}/data?size=10&{mark}",
                      proxy=f"127.0.0.1:{port}").status

    # --- the log command and -l ----------------------------------------
    t.eq(200, get(p1, "one"), "a request through the first proxy")
    t.eq(200, get(p2, "two"), "one through the second")
    t.eq(200, get(p3, "three"), "one through the third")
    t.eq(True, _wait(lambda: _proxied(first, "one")), "the log command's file gets its line")
    t.eq(True, _wait(lambda: _proxied(shared, "two") and _proxied(shared, "three")),
         "the two services with the same -l write to the same file")
    t.eq(False, _proxied(first, "two"), "and not to the log command's")
    t.eq(False, _proxied(shared, "one"), "nor the other way round")
    n = _opened(pid, shared)
    if n is not None:
        t.eq(1, n, "the file named by both is opened once")
        t.eq(1, _opened(pid, first), "the log command's file is open")

    def reload(main, until):
        t.write_config("logs", config(origin, p1, p2, p3, adm, main))
        t.http(f"http://127.0.0.1:{adm}/R")
        return _wait(until)

    # --- a reload to another file: the old one is closed once unused -----
    t.eq(True, reload(second, lambda: "Accepting connections" in _read(second)),
         "the new configuration logs to the new file")
    t.eq(200, get(p1, "four"), "a request after the reload")
    t.eq(True, _wait(lambda: _proxied(second, "four")), "goes to the new file")
    t.eq(False, _proxied(first, "four"), "not to the old one")
    if n is not None:
        t.eq(True, _wait(lambda: _opened(pid, first) == 0),
             "the old file is closed once its services are gone")
        t.eq(True, _wait(lambda: _opened(pid, shared) == 0),
             "and so is the file of -l nobody names any more")
        t.eq(1, _opened(pid, second), "the new one is open")

    # --- the same file, rotated daily: reopened under the day's name -----
    dated = second + "." + time.strftime("%Y.%m.%d")
    t.eq(True, reload(second + " D", lambda: os.path.exists(dated)),
         "a rotation given to the log reopens it under the dated name")
    t.eq(200, get(p1, "five"), "a request after that")
    t.eq(True, _wait(lambda: _proxied(dated, "five")), "goes to the dated file")
    t.eq(False, _proxied(second, "five"), "not to the undated one")

    # --- a log which fails ------------------------------------------------
    if os.path.exists("/dev/full"):
        o2, q = t.free_port(), t.free_port()
        full = t.start("logs_full", f"""
            log /dev/full
            logformat "LLOG %N %T"
            auth iponly
            allow *
            http data * /data
            httpsrv -p{o2}
            proxy -p{q}
        """, ports=[o2, q])
        # a buffer's worth, at least, before writing it fails
        for i in range(80):
            t.http(f"http://127.0.0.1:{o2}/data?size=10&{'x' * 40}{i}",
                   proxy=f"127.0.0.1:{q}")
        t.eq(True, _wait(lambda: "LOG PROXY" in full.output()),
             "the lines a full device refuses go to standard error")

    # --- a log which cannot be opened is an error in the configuration ---
    out = t.run_config("logs_bad", f"""
        log {os.path.join(t.tmpdir, "no", "such", "dir", "x.log")}
        proxy -p{t.free_port()}
    """)
    t.contains(out, "x.log", "a log which cannot be opened is named")
