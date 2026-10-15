"""Listening sockets across a reload: a service of the new configuration on
the same address and port takes over the old service's socket, so clients
connecting all the while are never refused nor reset."""

import re
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

    # the listener counts its clients, whichever service took them: through
    # the reloads the proxy's socket is one, its count goes on
    def listener_counts(service):
        """The listener counters of the running service of that type: its
        item has nested ones, acl and clients, before its counters."""
        page = t.http(f"http://127.0.0.1:{adm}/S").text
        m = re.search(r"type of the service/client</description><value><!\[CDATA\[" + service +
                      r"\]\].*?<name>listenerclients</name>.*?CDATA\[(\d+)\]"
                      r".*?<name>listenerprocessed</name>.*?CDATA\[(\d+)\]", page, re.S)
        return (int(m.group(1)), int(m.group(2))) if m else (None, None)

    clients, processed = listener_counts("PROXY")
    t.eq(0, clients, "no client is connected to the proxy's listener after the run")
    total = done["ok"] + done["failed"]
    t.ok(f"its count of clients done with goes on through the reloads ({processed} of {total})") \
        if processed is not None and processed >= total else \
        t.fail("its count of clients done with goes on through the reloads", f"at least {total}", processed)

    # --- UDP: the socket is handed over too, and a session of the old
    # service goes on through it, its datagrams forwarded by the new one ---
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    echo_port = echo.getsockname()[1]

    def echo_server():
        while True:
            try:
                data, addr = echo.recvfrom(2048)
            except OSError:
                return
            echo.sendto(data, addr)

    threading.Thread(target=echo_server, daemon=True).start()
    udp = t.free_port()
    uconf = conf + f"\n        udppm {udp} 127.0.0.1 {echo_port}\n"
    t.write_config("takeover", uconf)
    t.http(f"http://127.0.0.1:{adm}/R")
    time.sleep(1.5)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1)
    sent = lost = 0
    stopudp = time.time() + 5
    reloads = 0
    next_reload = time.time() + 0.5
    while time.time() < stopudp:
        if reloads < 3 and time.time() >= next_reload:
            t.write_config("takeover", uconf)
            t.http(f"http://127.0.0.1:{adm}/R")
            reloads += 1
            next_reload = time.time() + 1.2
        msg = f"n{sent}".encode()
        client.sendto(msg, ("127.0.0.1", udp))
        sent += 1
        try:
            data, _ = client.recvfrom(2048)
            if data != msg:
                lost += 1
        except OSError:
            lost += 1
        time.sleep(0.02)
    client.close()
    echo.close()
    t.ok(f"a UDP session sends through three reloads ({sent} datagrams)") if sent > 100 else \
        t.fail("a UDP session sends through three reloads", "more than 100", sent)
    t.eq(0, lost, "and every datagram comes back, the socket handed over")
    t.contains(server.output(), f"{udp} 0.0.0.0:0 0 0 0 Accepting connections, taken over",
               "the UDP service takes the socket over")

    # --- options: a live -ol option changed is set on the socket taken over,
    # a bind-time one makes another socket; two services of one
    # configuration on one address are each taken over ----------------------
    def taken_for(port, since):
        return server.output()[since:].count(f":{port} 0.0.0.0:0 0 0 0 Accepting connections, taken over")

    def reload_conf(c):
        mark = len(server.output())
        t.write_config("takeover", c)
        t.http(f"http://127.0.0.1:{adm}/R")
        time.sleep(1.5)
        return mark

    oconf = conf.replace(f"proxy -p{proxy}", f"proxy -olTCP_NODELAY -p{proxy}")
    reload_conf(oconf)
    mark = reload_conf(oconf.replace("-olTCP_NODELAY", "-olTCP_NODELAY,SO_KEEPALIVE"))
    t.eq(1, taken_for(proxy, mark), "a live socket option changed: the socket is taken over")
    t.eq(200, t.http(f"http://127.0.0.1:{origin}/data?size=100", proxy=f"127.0.0.1:{proxy}").status,
         "and serves")
    mark = reload_conf(oconf.replace("-olTCP_NODELAY", "-olTCP_NODELAY,SO_KEEPALIVE,SO_REUSEADDR=0"))
    t.eq(0, taken_for(proxy, mark), "a bind-time socket option changed: another socket")
    t.ok("which serves") if t.wait_port(proxy) and t.http(
        f"http://127.0.0.1:{origin}/data?size=100", proxy=f"127.0.0.1:{proxy}").status == 200 else \
        t.fail("which serves", 200, "no answer")
    twice = conf.replace(f"proxy -p{proxy}", f"proxy -p{proxy}\n        proxy -p{proxy}")
    reload_conf(twice)
    mark = reload_conf(twice)
    t.eq(2, taken_for(proxy, mark), "two services on one address are both taken over")
    reload_conf(conf)

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
