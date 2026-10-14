"""Reloading the configuration: a file with an error leaves the configuration
in force, services and users, as it was; a good one replaces it, while the
connections of the old services finish undisturbed."""

import threading
import time


def config(origin, proxy, adm, user, extra=""):
    return f"""
        log
        auth iponly
        allow *
        http data * /data
        httpsrv -p{origin}

        flush
        users {user}
        auth strong
        allow *
        proxy -p{proxy}

        flush
        auth iponly
        allow *
        admin -p{adm}
        {extra}
    """


def run(t):
    origin = t.free_port()
    first = t.free_port()
    second = t.free_port()
    adm = t.free_port()

    server = t.start("reload", config(origin, first, adm, "alice:CL:one"),
                     ports=[origin, first, adm])
    url = f"http://127.0.0.1:{origin}/data?size=1000"
    proxy = f"127.0.0.1:{first}"

    def as_user(user, password, through=proxy):
        return t.http(url, proxy=through, proxy_auth=(user, password)).status

    t.eq(200, as_user("alice", "one"), "the first configuration lets alice in")

    def reload_and_wait(expect_failure=False):
        before = server.output()
        accepting = before.count("Accepting connections")
        t.http(f"http://127.0.0.1:{adm}/R")
        deadline = time.time() + 10
        while time.time() < deadline:
            out = server.output()
            if expect_failure and "Unknown command" in out[len(before):]:
                return out
            if not expect_failure and out.count("Accepting connections") >= accepting + 3:
                return out
            time.sleep(0.05)
        return server.output()

    # --- a file with an error: nothing changes --------------------------
    t.write_config("reload", config(origin, first, adm, "bob:CL:two", "nosuchcommand"))
    out = reload_and_wait(expect_failure=True)
    t.contains(out, "Unknown command", "the broken configuration is refused")
    time.sleep(1.5)	# what a switch would take: the old services stop within a second
    t.eq(200, as_user("alice", "one"), "after a failed reload alice still gets in")
    t.ne(200, as_user("bob", "two"), "and bob, from the refused file, does not")

    # --- a good file: the new configuration takes over -------------------
    slow = {}

    def download():
        # about two seconds: 2 MB in 64 KB blocks, 60 ms apart
        r = t.http(f"http://127.0.0.1:{origin}/data?size=2000000&block=65536&delay=60",
                   proxy=proxy, proxy_auth=("alice", "one"))
        slow["status"], slow["length"] = r.status, r.length

    th = threading.Thread(target=download)
    th.start()
    time.sleep(0.3)

    t.write_config("reload", config(origin, second, adm, "bob:CL:two"))
    reload_and_wait()
    # The old services stop accepting within a second; until then both the
    # old and the new origin listen, and a connection the old one has queued
    # is reset when it closes (a listener is not handed over yet).
    time.sleep(1.5)
    t.ok("the new services start") if t.wait_port(second) else \
        t.fail("the new services start", f"port {second} open", "closed")
    moved = f"127.0.0.1:{second}"
    t.eq(200, as_user("bob", "two", moved), "the new configuration lets bob in")
    t.ne(200, as_user("alice", "one", moved), "and not alice, who is gone from it")

    # the old service stops accepting, its port closes
    deadline = time.time() + 5
    while time.time() < deadline and t.wait_port(first, timeout=0.2):
        time.sleep(0.2)
    t.ok("the old service stops listening") if not t.wait_port(first, timeout=0.2) else \
        t.fail("the old service stops listening", f"port {first} closed", "open")

    th.join(20)
    t.eq(200, slow.get("status"), "a download through the old service finishes")
    t.eq(2000000, slow.get("length"), "with the whole answer")
