"""extport and intport: binding the local side of a connection to a range.

Access rules accumulate until "flush": without it an earlier "allow *"
matches first and the rule carrying the range is never reached.
"""

from harness import int_field

LOW = 21400
HIGH = 21449
ILOW = 21500
IHIGH = 21549


def run(t):
    srv = t.free_port()
    prx = t.free_port()
    sks = t.free_port()
    meth = t.free_port()

    t.start("parent_ports", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
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
