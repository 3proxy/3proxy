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


def dns_reply(data, answer):
    """The answer to a query: an A record 10.9.8.7 for an A query, else a TXT
    record with the text given."""
    reply = bytearray(data)
    reply[2] = 0x81
    reply[3] = 0x80
    reply[6:8] = struct.pack("!H", 1)
    pos = 12
    while data[pos]:
        pos += data[pos] + 1
    qtype = struct.unpack("!H", data[pos + 1:pos + 3])[0]
    if qtype == 1:
        reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([10, 9, 8, 7])
    else:
        txt = bytes([len(answer)]) + answer
        reply += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt)) + txt
    return bytes(reply)


def fake_name_server(answer, tcp=False, wrongid=False):
    """A name server answering every query (see dns_reply), over UDP or
    TCP; with answer None, one which answers nothing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))

    def serve_tcp(c):
        try:
            c.settimeout(10)
            head = c.recv(2)
            n = struct.unpack("!H", head)[0]
            data = b""
            while len(data) < n:
                data += c.recv(n - len(data))
            reply = dns_reply(data, answer)
            # in two pieces, as a stream may bring it
            c.sendall(struct.pack("!H", len(reply)) + reply[:5])
            time.sleep(0.05)
            c.sendall(reply[5:])
        except OSError:
            pass
        c.close()

    def serve():
        while True:
            try:
                if tcp:
                    c, _ = sock.accept()
                    threading.Thread(target=serve_tcp, args=(c,), daemon=True).start()
                    continue
                data, peer = sock.recvfrom(65536)
            except OSError:
                return
            if answer is not None:
                reply = dns_reply(data, answer)
                if wrongid:
                    reply = bytes([reply[0] ^ 0x55, reply[1]]) + reply[2:]
                sock.sendto(reply, peer)

    if tcp:
        sock.listen(8)
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

    # --- a session heard from lives on past its first deadline, and ends
    # its idle time after the last datagram, neither sooner nor much later
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    answered = 0
    for i in range(10):
        if exchange(s, idle, f"k{i}".encode()) == f"echo:k{i}".encode():
            answered += 1
        time.sleep(0.5)
    cport = s.getsockname()[1]
    last = time.time()
    t.eq(10, answered, "a datagram every half second for five seconds is answered")
    t.ok("and the session lives on through them") if not idle_ended() else \
        t.fail("and the session lives on through them", "no 00092 line", "ended")
    while time.time() < last + 6 and not idle_ended():
        time.sleep(0.1)
    took = time.time() - last
    if idle_ended() and 1.5 <= took <= 3.5:
        t.ok("then two seconds of silence end it")
    else:
        t.fail("then two seconds of silence end it", "ended 1.5-3.5 s after the last",
               f"{'ended' if idle_ended() else 'not ended'} after {took:.1f} s")
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

    # an address not in the cache is asked of the name server, and kept
    got = exchange(s, fwd, dns_raw("a.test", 1))
    t.ok("an A query not in the cache is answered by the name server") \
        if got and bytes([10, 9, 8, 7]) in got else \
        t.fail("an A query not in the cache is answered by the name server", "10.9.8.7", got)
    good.close()
    time.sleep(0.2)
    got = exchange(s, fwd, dns_raw("a.test", 1))
    t.ok("and then from the name cache, the name server gone") \
        if got and bytes([10, 9, 8, 7]) in got else \
        t.fail("and then from the name cache, the name server gone", "10.9.8.7", got)

    t.wait_udp(slow, payload=dns_raw("local.test", 1))
    pending = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # an A query, which the resolver used to wait for in place
    pending.sendto(dns_raw("mute.test", 1), ("127.0.0.1", slow))
    start = time.time()
    other = exchange(s, slow, dns_raw("local.test", 1), timeout=2)
    t.ok(f"while one query waits for a silent name server another is answered ({time.time() - start:.2f} s)") \
        if other and b"\x0a\x01\x02\x03" in other else \
        t.fail("while one query waits for a silent name server another is answered", "10.1.2.3", other)
    deadline = time.time() + 6
    while time.time() < deadline and " 00821 " not in dns2.output():
        time.sleep(0.2)
    t.contains(dns2.output(), " 00821 ", "the waiting one ends at DNS_TO (821)")

    # a name server over TCP; and a second one asked when the first is silent
    tcpns, tport = fake_name_server(b"over-tcp", tcp=True)
    second, sport = fake_name_server(b"the-second")
    viatcp, fallback = t.free_port(), t.free_port()
    t.start("udploop_tcpns", f"""
        log
        timeouts 1 5 30 60 180 1800 2 60 15 5 5
        nserver 127.0.0.1:{tport}/tcp
        nscache 256
        nsrecord local.test 10.1.2.3
        auth iponly
        allow *
        dnspr -p{viatcp}
    """)
    t.start("udploop_fallback", f"""
        log
        timeouts 1 5 30 60 180 1800 2 60 15 5 5
        nserver 127.0.0.1:{mport}
        nserver 127.0.0.1:{sport}
        nscache 256
        nsrecord local.test 10.1.2.3
        auth iponly
        allow *
        dnspr -p{fallback}
    """)
    t.wait_udp(viatcp, payload=dns_raw("local.test", 1))
    got = exchange(s, viatcp, dns_raw("tcp.test", 16), timeout=4)
    t.ok("a name server over TCP is asked, its answer in pieces put together") \
        if got and b"over-tcp" in got else \
        t.fail("a name server over TCP is asked, its answer in pieces put together", "the TXT", got)
    t.wait_udp(fallback, payload=dns_raw("local.test", 1))
    got = exchange(s, fallback, dns_raw("second.test", 16), timeout=6)
    t.ok("the first name server silent, the second is asked after DNS_TO") \
        if got and b"the-second" in got else \
        t.fail("the first name server silent, the second is asked after DNS_TO", "the TXT", got)

    # an answer with another id is not the answer: neither relayed nor kept
    liar, lport = fake_name_server(b"forged", wrongid=True)
    guarded = t.free_port()
    t.start("udploop_liar", f"""
        log
        timeouts 1 5 30 60 180 1800 2 60 15 5 5
        nserver 127.0.0.1:{lport}
        nscache 256
        nsrecord local.test 10.1.2.3
        auth iponly
        allow *
        dnspr -p{guarded}
    """)
    t.wait_udp(guarded, payload=dns_raw("local.test", 1))
    t.eq(None, exchange(s, guarded, dns_raw("forged.test", 1), timeout=3),
         "an answer with another transaction id is not relayed")
    t.eq(None, exchange(s, guarded, dns_raw("forged.test", 1), timeout=3),
         "nor kept in the name cache")
    # a label with a '.' in it is another name than its text reads: answered,
    # but not kept under that text
    caching, cport2 = fake_name_server(b"x")
    dotted = t.free_port()
    t.start("udploop_dotted", f"""
        log
        nserver 127.0.0.1:{cport2}
        nscache 256
        nsrecord local.test 10.1.2.3
        auth iponly
        allow *
        dnspr -p{dotted}
    """)
    t.wait_udp(dotted, payload=dns_raw("local.test", 1))
    odd = struct.pack("!HHHHHH", 0x4C4C, 0x0100, 1, 0, 0, 0) + b"\x08evil.dot\x04test\x00" + struct.pack("!HH", 1, 1)
    got = exchange(s, dotted, odd)
    t.ok("a name with a '.' inside a label is answered") \
        if got and bytes([10, 9, 8, 7]) in got else t.fail("a name with a '.' inside a label is answered", "10.9.8.7", got)
    caching.close()
    time.sleep(0.2)
    t.eq(None, exchange(s, dotted, dns_raw("evil.dot.test", 1), timeout=3),
         "and the name its text reads as was not cached from it")
    for x in (s, pending, mute, tcpns, second, liar):
        x.close()
