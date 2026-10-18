"""UDP services in one thread: udppm sessions, many at once, their limits and
deadlines, and their adoption by the new service on a reload; dnspr
forwarding to a name server without holding up other queries."""

import socket
import struct
import threading
import time


def exchange(sock, port, payload, timeout=2.0):
    sock.settimeout(timeout)
    sock.sendto(payload, ("127.0.0.1", port))
    try:
        return sock.recvfrom(65536)[0]
    except OSError:
        return None


def dns_raw(name, qtype, qid=0x3B3B):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", qtype, 1)


def fake_name_server(answer):
    """A name server answering every query with one TXT record, the text
    given; and one which answers nothing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def serve():
        while True:
            try:
                data, peer = sock.recvfrom(65536)
            except OSError:
                return
            if answer is None:
                continue
            reply = bytearray(data)
            reply[2] = 0x81
            reply[3] = 0x80
            reply[6:8] = struct.pack("!H", 1)
            txt = bytes([len(answer)]) + answer
            reply += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt)) + txt
            sock.sendto(bytes(reply), peer)

    threading.Thread(target=serve, daemon=True).start()
    return sock, sock.getsockname()[1]


def run(t):
    echo = t.udp_echo()
    adm = t.free_port()
    many, single, idle, limited, acl = (t.free_port() for _ in range(5))

    def config(acl_line):
        return f"""
            log
            auth iponly
            allow *
            admin -p{adm}

            flush
            auth iponly
            allow *
            udppm {many} 127.0.0.1 {echo}
            udppm -s {single} 127.0.0.1 {echo}

            flush
            timeouts 1 5 30 2 180 1800 15 60 15 5 5
            auth iponly
            allow *
            udppm {idle} 127.0.0.1 {echo}

            flush
            maxconn 2
            auth iponly
            allow *
            udppm {limited} 127.0.0.1 {echo}

            flush
            auth iponly
            {acl_line}
            udppm {acl} 127.0.0.1 {echo}
        """

    server = t.start("udploop", config("allow *"), ports=[adm])
    for p in (many, single, idle, limited, acl):
        t.wait_udp(p)

    # --- many sessions at once, each answered with its own datagrams ------
    clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(20)]
    wrong = 0
    for rnd in range(3):
        for i, c in enumerate(clients):
            c.sendto(f"c{i}r{rnd}".encode(), ("127.0.0.1", many))
        for i, c in enumerate(clients):
            c.settimeout(2)
            try:
                got = c.recvfrom(2048)[0]
            except OSError:
                got = None
            if got != f"echo:c{i}r{rnd}".encode():
                wrong += 1
    for c in clients:
        c.close()
    t.eq(0, wrong, "20 clients at once each get their own answers, three rounds")

    # --- -s: a session ends with its first answer -------------------------
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.eq(b"echo:one", exchange(s, single, b"one"), "with -s a datagram is answered")
    t.eq(b"echo:two", exchange(s, single, b"two"), "and the next one too, in a new session")
    cport = s.getsockname()[1]
    s.close()
    time.sleep(0.3)
    ended = [l for l in server.output().splitlines()
             if f" {single} 00000 " in l and f":{cport} " in l]
    t.eq(2, len(ended), "each answer ended its session, logged")

    # --- idle timeout: STRING_LONG of silence ends a session (92) ----------
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.eq(b"echo:x", exchange(s, idle, b"x"), "a session is answered")
    cport = s.getsockname()[1]
    def idle_ended():
        return any(f" {idle} 00092 " in l and f":{cport} " in l for l in server.output().splitlines())

    deadline = time.time() + 6
    while time.time() < deadline and not idle_ended():
        time.sleep(0.2)
    t.ok("two seconds of silence end it, logged with 92") if idle_ended() else \
        t.fail("two seconds of silence end it, logged with 92", "a 00092 line", "none")
    s.close()

    # --- maxconn: a client without a free slot is not answered -------------
    held = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
    t.eq([b"echo:a", b"echo:a"], [exchange(h, limited, b"a") for h in held],
         "two clients take the two slots")
    third = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.eq(None, exchange(third, limited, b"b", timeout=1),
         "a third gets no answer while they hold them")
    t.contains(server.output(), "too many connected clients",
               "and that is logged")
    for h in held + [third]:
        h.close()

    # --- reload: sessions are adopted and re-authenticated -----------------
    kept = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.eq(b"echo:k1", exchange(kept, acl, b"k1"), "a session before the reload")
    mark = len(server.output())
    t.write_config("udploop", config("deny *"))
    t.http(f"http://127.0.0.1:{adm}/R")
    time.sleep(2.5)
    t.eq(None, exchange(kept, acl, b"k2", timeout=1),
         "denied by the new rules it is answered no more")
    cport = kept.getsockname()[1]
    t.ok("its session ended by the re-authentication") \
        if any(f" {acl} " in l and f":{cport} " in l and " 00000 " not in l
               for l in server.output()[mark:].splitlines()) else \
        t.fail("its session ended by the re-authentication", "a line with a result", "none")
    kept.close()
    t.write_config("udploop", config("allow *"))
    t.http(f"http://127.0.0.1:{adm}/R")
    time.sleep(2.5)

    # --- dnspr: forwarded queries wait in the loop, not in it ---------------
    good, gport = fake_name_server(b"from-the-server")
    mute, mport = fake_name_server(None)
    fwd, slow, local = t.free_port(), t.free_port(), t.free_port()
    t.start("udploop_dns", f"""
        log
        timeouts 1 5 30 60 180 1800 3 60 15 5 5
        nserver 127.0.0.1:{gport}
        nscache 256
        nsrecord local.test 10.1.2.3
        auth iponly
        allow *
        dnspr -p{fwd}

        flush
        auth iponly
        allow *
        dnspr -p{local}
    """)
    # a service of its own whose name server says nothing
    dns2 = t.start("udploop_mute", f"""
        log
        timeouts 1 5 30 60 180 1800 3 60 15 5 5
        nserver 127.0.0.1:{mport}
        nscache 256
        nsrecord local.test 10.1.2.3
        auth iponly
        allow *
        dnspr -p{slow}
    """)
    t.wait_udp(fwd, payload=dns_raw("local.test", 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    got = exchange(s, fwd, dns_raw("txt.test", 16))
    t.ok("a TXT query is sent on to the name server and its answer relayed") \
        if got and b"from-the-server" in got else \
        t.fail("a TXT query is sent on to the name server and its answer relayed", "the TXT", got)

    t.wait_udp(slow, payload=dns_raw("local.test", 1))
    pending = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pending.sendto(dns_raw("mute.test", 16), ("127.0.0.1", slow))
    start = time.time()
    other = exchange(s, slow, dns_raw("local.test", 1), timeout=2)
    t.ok(f"while one query waits for a silent name server another is answered ({time.time() - start:.2f} s)") \
        if other and b"\x0a\x01\x02\x03" in other else \
        t.fail("while one query waits for a silent name server another is answered", "10.1.2.3", other)
    deadline = time.time() + 6
    while time.time() < deadline and " 00821 " not in dns2.output():
        time.sleep(0.2)
    t.contains(dns2.output(), " 00821 ", "the waiting one ends at DNS_TO (821)")
    for x in (s, pending, good, mute):
        x.close()
