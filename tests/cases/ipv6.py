"""IPv6: listening on it, reaching it, and the rules that mention it.

A service resolves IPv4 only unless told otherwise, so the proxies that are
meant to reach IPv6 carry a family flag. Names resolving to IPv6 need
nscache6: nscache holds the IPv4 side and nothing else.
"""


def run(t):
    if not t.has_ipv6():
        t.skip("IPv6 (this machine has no IPv6 loopback)")
        return

    origin = t.free_port()
    v6proxy = t.free_port()
    mixed = t.free_port()
    v4only = t.free_port()
    socks6 = t.free_port()

    t.start("ipv6", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        http * /data data
        httpsrv -p{origin} -i::1

        # reached over IPv6, and allowed to reach IPv6
        flush
        auth iponly
        allow *
        proxy -p{v6proxy} -i::1 -6

        # reached over IPv4, still able to reach IPv6
        flush
        auth iponly
        allow *
        proxy -p{mixed} -6

        # asked for IPv4 only, so an IPv6 destination is not for it
        flush
        auth iponly
        allow *
        proxy -p{v4only} -4

        flush
        auth iponly
        allow *
        socks -p{socks6} -6
    """, ports=[("::1", origin), ("::1", v6proxy), mixed, v4only, socks6])

    url = f"http://[::1]:{origin}/echo"

    # --- listening on IPv6 -------------------------------------------------
    r = t.http(url)
    t.eq(200, r.status, "a service bound to ::1 answers over IPv6")
    t.contains(r, "peer.addr=::1", "the client is seen as an IPv6 address")
    t.contains(r, "path=/echo", "and the request arrives intact")

    # the Host header carries the address in brackets, and a rule matching
    # any host still matches it
    t.contains(r, "host=[::1]", "the host header keeps its brackets")

    # --- proxying over IPv6 -------------------------------------------------
    r = t.http(url, proxy=f"[::1]:{v6proxy}")
    t.eq(200, r.status, "a proxy reached over IPv6 serves an IPv6 destination")
    t.contains(r, "peer.addr=::1", "the proxy connects from IPv6 as well")

    t.eq(20000, t.http(f"http://[::1]:{origin}/data?size=20000",
                       proxy=f"[::1]:{v6proxy}").length,
         "a body passes over IPv6")

    t.eq(200, t.http(url, proxy=f"[::1]:{v6proxy}", tunnel=True).status,
         "CONNECT works over IPv6")

    # --- across the two families --------------------------------------------
    r = t.http(url, proxy=f"127.0.0.1:{mixed}")
    t.eq(200, r.status, "a client on IPv4 can be given an IPv6 destination")
    t.contains(r, "peer.addr=::1", "and the far side is still reached over IPv6")

    # a service told to use one family stays in it
    t.ne(200, t.http(url, proxy=f"127.0.0.1:{v4only}").status,
         "a service asked for IPv4 only refuses an IPv6 destination")

    # --- SOCKS with an IPv6 destination -------------------------------------
    r = t.socks_http(f"127.0.0.1:{socks6}", url)
    t.eq(200, r.status, "SOCKS5 carries an IPv6 destination address")
    t.contains(r, "peer.addr=::1", "which is reached over IPv6")

    # --- which family a service will use --------------------------------------
    # -46 and -64 both reach either family; -4 and -6 are each restricted to
    # one; and nothing said means -46.
    v4origin = t.free_port()
    flags = {"nothing said": "", "-4": "-4", "-6": "-6", "-46": "-46", "-64": "-64"}
    family_ports = {name: t.free_port() for name in flags}
    sections = [f"""
        flush
        auth iponly
        allow *
        proxy -p{family_ports[name]} {flag}""" for name, flag in flags.items()]
    t.start("ipv6_family", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        httpsrv -p{v4origin}
        {"".join(sections)}
    """, ports=[v4origin] + list(family_ports.values()))

    expected = {
        "nothing said": (200, None),      # -4 is the default
        "-4": (200, None),
        "-6": (None, 200),
        "-46": (200, 200),
        "-64": (200, 200),
    }
    for name, port in family_ports.items():
        want4, want6 = expected[name]
        got4 = t.http(f"http://127.0.0.1:{v4origin}/echo", proxy=f"127.0.0.1:{port}").status
        got6 = t.http(url, proxy=f"127.0.0.1:{port}").status
        if want4 == 200:
            t.eq(200, got4, f"{name}: an IPv4 destination is reached")
        else:
            t.ne(200, got4, f"{name}: an IPv4 destination is refused")
        if want6 == 200:
            t.eq(200, got6, f"{name}: an IPv6 destination is reached")
        else:
            t.ne(200, got6, f"{name}: an IPv6 destination is refused")

    # --- a name that resolves to an IPv6 address ------------------------------
    # The two caches are separate, and the record is only kept in the one
    # that matches the address family.
    # separate processes: the caches belong to the process, not the service,
    # so one section configuring nscache6 would answer for the other too
    with_cache6 = t.free_port()
    without = t.free_port()
    t.start("ipv6_names", f"""
        log
        flush
        nserver 127.0.0.1
        nscache6 1024
        nsrecord v6.test ::1
        auth iponly
        allow *
        proxy -p{with_cache6} -6
    """, ports=[with_cache6])
    t.start("ipv6_names_nocache", f"""
        log
        flush
        nserver 127.0.0.1
        nsrecord v6.test ::1
        auth iponly
        allow *
        proxy -p{without} -6
    """, ports=[without])

    t.eq(200, t.http(f"http://v6.test:{origin}/echo",
                     proxy=f"127.0.0.1:{with_cache6}").status,
         "a name kept in nscache6 resolves to its IPv6 address")
    t.ne(200, t.http(f"http://v6.test:{origin}/echo",
                     proxy=f"127.0.0.1:{without}").status,
         "the same record without nscache6 is not there to be found")

    # --- an address has more than one spelling --------------------------------
    # Denying the IPv4 form does not deny the same host asked for as an
    # IPv4-mapped address, nor the IPv6 loopback, which is why the security
    # notes say to deny all of them. Both halves are checked so a change in
    # either direction is noticed.
    partial = t.free_port()
    complete = t.free_port()
    t.start("ipv6_deny", f"""
        log
        flush
        auth iponly
        deny * * 127.0.0.1
        allow *
        proxy -p{partial} -46

        flush
        auth iponly
        deny * * 127.0.0.1
        deny * * ::1
        deny * * ::ffff:127.0.0.1
        allow *
        proxy -p{complete} -46
    """, ports=[partial, complete])

    v4url = f"http://127.0.0.1:{v4origin}/echo"
    mapped = f"http://[::ffff:127.0.0.1]:{v4origin}/echo"

    t.ne(200, t.http(v4url, proxy=f"127.0.0.1:{partial}").status,
         "denying 127.0.0.1 denies the address as written")

    # Whether the mapped form reaches the same host is up to the stack: it
    # does where a mapped address is routed to IPv4, and that is the hazard
    # the security notes describe. Where it does not, there is nothing to
    # assert, but the rule that names every spelling still has to hold.
    if t.http(mapped, proxy=f"127.0.0.1:{partial}").status == 200:
        t.ok("the same host asked for as ::ffff:127.0.0.1 is still reached")
    else:
        t.skip("the mapped form (this stack does not route it to IPv4)")

    t.eq(200, t.http(url, proxy=f"127.0.0.1:{partial}").status,
         "and ::1 is reached, which the rule never mentioned")

    t.ne(200, t.http(v4url, proxy=f"127.0.0.1:{complete}").status,
         "naming every spelling denies the plain address")
    t.ne(200, t.http(mapped, proxy=f"127.0.0.1:{complete}").status,
         "and the mapped one, whether or not it would have been reachable")
    t.ne(200, t.http(url, proxy=f"127.0.0.1:{complete}").status,
         "and the IPv6 loopback")

    # --- rules that name addresses ------------------------------------------
    allowed = t.free_port()
    refused = t.free_port()
    t.start("ipv6_rules", f"""
        log
        flush
        auth iponly
        allow * ::1
        proxy -p{allowed} -i::1 -6

        flush
        auth iponly
        allow * 127.0.0.1
        proxy -p{refused} -i::1 -6
    """, ports=[("::1", allowed), ("::1", refused)])

    t.eq(200, t.http(url, proxy=f"[::1]:{allowed}").status,
         "a rule naming ::1 admits an IPv6 client")
    t.ne(200, t.http(url, proxy=f"[::1]:{refused}").status,
         "a rule naming only an IPv4 address does not")
