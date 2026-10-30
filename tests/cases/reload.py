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
    if not t.skip_unless("httpsrv"):
        return
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

    # --- a good file: the new configuration takes over, and the connections
    # of the old services go by its rules from then on ---------------------
    def download(result):
        # about two seconds: 400 KB in 8 KB blocks (httpsrv's largest),
        # 40 ms apart
        r = t.http(f"http://127.0.0.1:{origin}/data?size=400000&block=8192&delay=40",
                   proxy=proxy, proxy_auth=("alice", "one"))
        result["status"], result["length"] = r.status, r.length

    def during_reload(users, port):
        result = {}
        th = threading.Thread(target=download, args=(result,))
        th.start()
        time.sleep(0.3)
        t.write_config("reload", config(origin, port, adm, users))
        reload_and_wait()
        return th, result

    # alice stays: her download goes on under the new service
    th, kept = during_reload("alice:CL:one bob:CL:two", first)
    t.eq(200, as_user("bob", "two"), "the new configuration lets bob in")
    th.join(60)
    t.eq(400000, kept.get("length"),
         "a download of a user the new configuration keeps finishes whole")

    # a connection kept alive: each request is authorized by the rules in
    # force, so alice's next request after she is removed is refused
    keep = t.connection("127.0.0.1", origin, proxy=proxy)
    t.eq(200, t.http(url, proxy=proxy, proxy_auth=("alice", "one"), conn=keep).status,
         "a kept-alive connection serves alice")
    t.write_config("reload", config(origin, first, adm, "bob:CL:two"))
    reload_and_wait()
    r = t.http(url, proxy=proxy, proxy_auth=("alice", "one"), conn=keep)
    t.eq(407, r.status, "after she is removed, her next request on it is refused "
         "with a request for credentials, authorized by the new rules")
    t.write_config("reload", config(origin, first, adm, "alice:CL:one bob:CL:two"))
    reload_and_wait()

    # alice is removed: her download is cut, being re-authenticated
    th, cut = during_reload("bob:CL:two", first)
    th.join(60)
    t.ok("a download of a user the new configuration removes is cut") \
        if cut.get("length", 0) < 400000 else \
        t.fail("a download of a user the new configuration removes is cut",
               "less than 400000 bytes", cut.get("length"))
    t.ne(200, as_user("alice", "one"), "and alice cannot come back")

    # the service moves to another port: the old one closes
    t.write_config("reload", config(origin, second, adm, "bob:CL:two"))
    reload_and_wait()
    t.ok("the moved service listens on its new port") if t.wait_port(second) else \
        t.fail("the moved service listens on its new port", f"port {second} open", "closed")
    t.eq(200, as_user("bob", "two", f"127.0.0.1:{second}"), "bob gets in there")
    deadline = time.time() + 5
    while time.time() < deadline and t.wait_port(first, timeout=0.2):
        time.sleep(0.2)
    t.ok("the old port is closed") if not t.wait_port(first, timeout=0.2) else \
        t.fail("the old port is closed", f"port {first} closed", "open")
