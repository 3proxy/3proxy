"""The SOCKS proxy, reaching the built-in server."""


def run(t):
    srv = t.free_port()
    sks = t.free_port()
    sauth = t.free_port()

    t.start("socks", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        http * /data data
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

    # --- authentication ----------------------------------------------------
    t.eq(200, t.socks_http(guarded, origin + "/echo",
                           auth=("alice", "secret")).status,
         "valid SOCKS5 credentials pass")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", srv,
                               auth=("alice", "wrong")),
         "wrong SOCKS5 credentials are refused")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", srv),
         "SOCKS5 without credentials is refused")
