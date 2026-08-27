"""The SOCKS proxy, reaching the built-in server."""


def run(t):
    srv = t.free_port()
    sks = t.free_port()
    sauth = t.free_port()

    t.start("socks", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        http data * /data
        httpsrv -p{srv}

        flush
        auth iponly
        allow *
        socks -p{sks}

        flush
        auth strong
        users alice:CL:secret
        allow alice
        socks -p{sauth}
    """, ports=[srv, sks, sauth])

    origin = f"http://127.0.0.1:{srv}"
    plain = f"127.0.0.1:{sks}"
    guarded = f"127.0.0.1:{sauth}"

    # --- SOCKS5 ---------------------------------------------------------
    r = t.socks_http(plain, origin + "/echo")
    t.eq(200, r.status, "a SOCKS5 connection")
    t.contains(r, "path=/echo", "the origin sees the request made over SOCKS5")
    t.eq(10000, t.socks_http(plain, origin + "/data?size=10000").length,
         "a body survives SOCKS5")

    # resolution delegated to the proxy
    t.eq(200, t.socks_http(plain, f"http://localhost:{srv}/echo",
                           remote_dns=True).status,
         "SOCKS5 resolves the hostname itself")

    # --- SOCKS4 -----------------------------------------------------------
    t.eq(200, t.socks_http(plain, origin + "/echo", socks4=True).status,
         "a SOCKS4 connection")

    # --- the UDP association, and what goes through it ---------------------
    # Binding the association is one thing; carrying a datagram is what it
    # is for.
    echo = t.udp_echo()
    reply, bound = t.socks_udp(plain, "127.0.0.1", echo, b"ping")
    t.eq(b"echo:ping", reply, "a datagram is relayed and answered")
    t.ne(None, bound, "the association reports the port to send to")

    reply, _ = t.socks_udp(plain, "127.0.0.1", echo, b"x" * 2000)
    t.eq(b"echo:" + b"x" * 2000, reply, "a larger datagram survives the relay")

    # each association gets its own socket
    _, first = t.socks_udp(plain, "127.0.0.1", echo, b"one")
    _, second = t.socks_udp(plain, "127.0.0.1", echo, b"two")
    t.ne(first, second, "a second association binds its own port")

    # --- authentication ----------------------------------------------------
    t.eq(200, t.socks_http(guarded, origin + "/echo",
                           auth=("alice", "secret")).status,
         "valid SOCKS5 credentials pass")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", srv,
                               auth=("alice", "wrong")),
         "wrong SOCKS5 credentials are refused")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", srv),
         "SOCKS5 without credentials is refused")
