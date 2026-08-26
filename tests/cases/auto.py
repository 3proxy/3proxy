"""auto: one port that works out which protocol the client is speaking.

Two origins, because the protocols reach different places: an HTTP or SOCKS
client names its own destination, while a TLS client names a host in the
handshake and the service supplies the port.
"""


def run(t):
    certs = t.certs()
    plain = t.free_port()
    port = t.free_port()
    secure = t.free_port() if certs else None

    tls_origin = ""
    if certs:
        tls_origin = f"""
        flush
        ssl_server_cert {certs.server}
        ssl_server_key {certs.server_key}
        ssl_serv
        auth iponly
        allow *
        http * /echo* echo
        httpsrv -p{secure}
        ssl_noserv"""

    ports = [plain, port] + ([secure] if certs else [])
    server = t.start("auto", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        httpsrv -p{plain}
{tls_origin}

        flush
        nserver 127.0.0.1
        nscache 1024
        nsrecord sni.test 127.0.0.1
        auth iponly
        allow *
        auto -p{port}{f' -P{secure}' if certs else ''}
    """, ports=ports)

    url = f"http://127.0.0.1:{plain}/echo"
    at = f"127.0.0.1:{port}"

    # --- as an HTTP proxy -------------------------------------------------
    r = t.http(url, proxy=at)
    t.eq(200, r.status, "the same port serves an HTTP proxy request")
    t.contains(r, "path=/echo", "the origin sees it")
    t.contains(t.http(url, proxy=at, method="POST", body="x=1"), "method=POST",
               "a POST is recognised as HTTP too")

    # --- as a SOCKS proxy --------------------------------------------------
    r = t.socks_http(at, url)
    t.eq(200, r.status, "the same port serves SOCKS5")
    t.contains(r, "path=/echo", "the origin sees the SOCKS request")
    t.eq(200, t.socks_http(at, url, socks4=True).status,
         "and SOCKS4 on the same port")

    # --- as a name-directed TLS proxy --------------------------------------
    if certs and "Unknown command" not in server.output():
        r = t.https(f"https://sni.test:{port}/echo", ca=certs.ca, strict=False,
                    connect_to=("127.0.0.1", port))
        t.eq(200, r.status, "and a TLS handshake, routed by the name it carries")
        t.contains(r, "path=/echo", "which reaches the TLS origin")
    else:
        t.skip("auto over TLS (no SSL support, or no openssl to make certificates)")

    # --- what it is not ----------------------------------------------------
    t.not_contains(t.raw(port, "GIBBERISH\r\n\r\n"), "200 OK",
                   "nonsense is not served as anything")
