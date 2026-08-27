"""extport and intport: binding the local side of a connection to a range.

Access rules accumulate until "flush": without it an earlier "allow *"
matches first and the rule carrying the range is never reached.
"""

from harness import int_field


def _windows():
    """Pick port windows this platform will actually honour.

    On Linux the kernel applies IP_LOCAL_PORT_RANGE only within
    net.ipv4.ip_local_port_range; a window outside it is ignored and an
    ordinary ephemeral port is used, so a fixed low window would be
    measuring the kernel's own choice rather than the setting.
    """
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as fp:
            low, high = (int(part) for part in fp.read().split()[:2])
    except (OSError, ValueError):
        return (21400, 21449), (21500, 21549)
    base = low + 1000 if low + 1150 <= high else low
    return (base, base + 49), (base + 100, base + 149)


(LOW, HIGH), (ILOW, IHIGH) = _windows()

# Privileged ports: the kernel ignores such a range on Linux, since it is
# outside net.ipv4.ip_local_port_range, and binding them fails outright
# without privileges. Either way nothing in the range can be taken, which
# is the case the fallback exists for.
UNHONOURED = (1, 99)


def run(t):
    srv = t.free_port()
    prx = t.free_port()
    sks = t.free_port()
    meth = t.free_port()

    t.start("parent_ports", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        httpsrv -p{srv}

        # every outgoing connection binds inside the range
        flush
        auth iponly
        allow *
        parent 1000 extport 0.0.0.0 {LOW}-{HIGH}
        proxy -p{prx}

        # the range applies only to CONNECT: an HTTP proxy CONNECT is
        # HTTP_CONNECT, the bare CONNECT operation being the SOCKS one
        flush
        auth iponly
        allow * * * * HTTP_CONNECT
        parent 1000 extport 0.0.0.0 {LOW}-{HIGH}
        allow *
        proxy -p{meth}

        # socks, for the same setting on another service
        flush
        auth iponly
        allow *
        parent 1000 extport 0.0.0.0 {LOW}-{HIGH}
        socks -p{sks}
    """, ports=[srv, prx, sks, meth])

    origin = f"http://127.0.0.1:{srv}"
    proxy = f"127.0.0.1:{prx}"

    # --- extport ---------------------------------------------------------
    # the origin reports the source port it actually saw
    port = int_field(t.http(origin + "/echo", proxy=proxy), "peer.port")
    t.in_range(port, LOW, HIGH, "the outgoing connection binds inside the range")

    seen = []
    for _ in range(5):
        seen.append(int_field(t.http(origin + "/echo", proxy=proxy), "peer.port"))
    outside = [p for p in seen if p is None or not LOW <= p <= HIGH]
    t.eq([], outside, "repeated connections all bind inside the range")

    port = int_field(t.socks_http(f"127.0.0.1:{sks}", origin + "/echo"),
                     "peer.port")
    t.in_range(port, LOW, HIGH,
               "socks binds the outgoing connection inside the range")

    # --- per-method scoping ------------------------------------------------
    method_proxy = f"127.0.0.1:{meth}"
    port = int_field(t.http(origin + "/echo", proxy=method_proxy, tunnel=True),
                     "peer.port")
    t.in_range(port, LOW, HIGH, "CONNECT uses the range its rule sets")

    # a plain GET matches the later rule, which sets no range
    port = int_field(t.http(origin + "/echo", proxy=method_proxy), "peer.port")
    t.not_in_range(port, LOW, HIGH,
                   "a method outside that rule keeps an ephemeral port")

    # --- a range the platform cannot honour --------------------------------
    # Linux ignores a range outside net.ipv4.ip_local_port_range, and any
    # platform can run out of free ports in a range. Either way the
    # connection falls back to an ephemeral port instead of failing.
    unhonoured = t.free_port()
    t.start("parent_unhonoured", f"""
        log
        flush
        auth iponly
        allow *
        parent 1000 extport 0.0.0.0 {UNHONOURED[0]}-{UNHONOURED[1]}
        proxy -p{unhonoured}
    """, ports=[unhonoured])
    r = t.http(origin + "/echo", proxy=f"127.0.0.1:{unhonoured}")
    t.eq(200, r.status, "a range the platform cannot honour still connects")
    t.ne(None, int_field(r, "peer.port"),
         "the connection still has a source port")

    # --- intport -----------------------------------------------------------
    # A UDP association allocates its socket after the destination is known,
    # so the range has to be applied when the rule matches rather than when
    # the chain is walked.
    udps = t.free_port()
    t.start("parent_intport", f"""
        log
        flush
        auth iponly
        allow *
        parent 1000 intport 0.0.0.0 {ILOW}-{IHIGH}
        socks -p{udps}
    """, ports=[udps])
    t.in_range(t.socks_udp_associate(udps), ILOW, IHIGH,
               "UDP ASSOCIATE binds inside the internal range")

    # and the association still carries traffic while bound in the range
    echo = t.udp_echo()
    reply, bound = t.socks_udp(f"127.0.0.1:{udps}", "127.0.0.1", echo, b"data")
    t.eq(b"echo:data", reply, "a range-bound association still relays")
    t.in_range(bound, ILOW, IHIGH, "and the port it relays from is in the range")

    # without a range the association still works, on an ephemeral port
    udps2 = t.free_port()
    t.start("parent_intport_none", f"""
        log
        flush
        auth iponly
        allow *
        socks -p{udps2}
    """, ports=[udps2])
    t.ne(None, t.socks_udp_associate(udps2),
         "UDP ASSOCIATE works without a range")

    # --- configuration errors ------------------------------------------------
    dead = t.free_port()
    t.contains(t.run_config("badaddr", f"""
        log
        allow *
        parent 1000 extport 127.0.0.1 {LOW}-{HIGH}
        proxy -p{dead}
    """), "requires 0.0.0.0", "a non-zero address with extport is rejected")

    t.contains(t.run_config("badrange", f"""
        log
        allow *
        parent 1000 extport 0.0.0.0 notaport
        proxy -p{dead}
    """), "bad port range", "a malformed range is rejected")

    t.contains(t.run_config("badorder", f"""
        log
        allow *
        parent 1000 extport 0.0.0.0 {HIGH}-{LOW}
        proxy -p{dead}
    """), "bad port range", "a reversed range is rejected")
