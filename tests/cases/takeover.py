"""Listening sockets across a reload: a service of the new configuration on
the same address and port takes over the old service's socket, so clients
connecting all the while are never refused nor reset."""

import socket
import threading
import time


def run(t):
    origin = t.free_port()
    proxy = t.free_port()
    adm = t.free_port()
    conf = f"""
        log
        auth iponly
        allow *
        http data * /data
        httpsrv -p{origin}

        flush
        auth iponly
        allow *
        proxy -p{proxy}
        admin -p{adm}
    """
    server = t.start("takeover", conf, ports=[origin, proxy, adm])

    done = {"ok": 0, "failed": 0, "errors": []}
    stop = threading.Event()

    def client():
        url = f"http://127.0.0.1:{origin}/data?size=2000"
        while not stop.is_set():
            r = t.http(url, proxy=f"127.0.0.1:{proxy}")
            if r.status == 200 and r.length == 2000:
                done["ok"] += 1
            else:
                done["failed"] += 1
                if len(done["errors"]) < 3:
                    done["errors"].append(r.error or r.status)
            # paced, so as not to run out of local ports
            time.sleep(0.02)

    clients = [threading.Thread(target=client) for _ in range(4)]
    for c in clients:
        c.start()

    for i in range(3):
        time.sleep(0.5)
        before = server.output().count("taken over")
        t.write_config("takeover", conf)
        t.http(f"http://127.0.0.1:{adm}/R")
        deadline = time.time() + 10
        while time.time() < deadline and server.output().count("taken over") < before + 3:
            time.sleep(0.05)
    # the old services stop within a second of each reload
    time.sleep(1.5)
    stop.set()
    for c in clients:
        c.join(20)

    taken = server.output().count("Accepting connections, taken over")
    t.eq(9, taken, "each reload hands the three listening sockets over")
    t.ok(f"requests go on through the reloads ({done['ok']})") if done["ok"] > 100 else \
        t.fail("requests go on through the reloads", "more than 100", done["ok"])
    t.eq(0, done["failed"], "no request is refused or reset by a reload "
         f"(first errors: {done['errors']})")

    # a changed port is a new socket: the old one closes, the new one opens
    moved = t.free_port()
    t.write_config("takeover", conf.replace(f"proxy -p{proxy}", f"proxy -p{moved}"))
    t.http(f"http://127.0.0.1:{adm}/R")
    t.ok("a service moved to another port listens there") if t.wait_port(moved) else \
        t.fail("a service moved to another port listens there", "open", "closed")
    deadline = time.time() + 5
    while time.time() < deadline and t.wait_port(proxy, timeout=0.2):
        time.sleep(0.2)
    with socket.socket() as s:
        s.settimeout(1)
        refused = s.connect_ex(("127.0.0.1", proxy)) != 0
    t.ok("and its old port is closed") if refused else \
        t.fail("and its old port is closed", "refused", "accepted")
