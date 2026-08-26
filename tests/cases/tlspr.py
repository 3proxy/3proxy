"""tlspr: the destination comes from the name in the TLS handshake."""


def run(t):
    certs = t.certs()
    if not certs:
        t.skip("tlspr (openssl is not available to generate certificates)")
        return

    origin = t.free_port()
    sni = t.free_port()

    server = t.start("tlspr", f"""
        log
        ssl_server_cert {certs.server}
        ssl_server_key {certs.server_key}
        ssl_serv
        auth iponly
        allow *
        http * /echo* echo
        httpsrv -p{origin}

        flush
        ssl_noserv
        nserver 127.0.0.1
        nscache 1024
        nsrecord sni.test 127.0.0.1
        auth iponly
        allow *
        tlspr -p{sni} -P{origin}
    """, ports=[origin, sni])

    if "Unknown command" in server.output():
        t.skip("tlspr (this build has no SSL support)")
        return

    # The certificate names sni.test, so the name in the handshake is both
    # what picks the destination and what the client checks.
    r = t.https(f"https://sni.test:{sni}/echo", ca=certs.ca, strict=False,
                connect_to=("127.0.0.1", sni))
    t.eq(200, r.status, "the name in the handshake reaches its destination")
    t.contains(r, "path=/echo", "the request arrives at the origin")

    # a name the proxy cannot resolve has nowhere to go
    r = t.https(f"https://nowhere.test:{sni}/echo", ca=certs.ca, strict=False,
                verify_name=False, connect_to=("127.0.0.1", sni))
    t.ne(200, r.status, "a name that does not resolve is refused")
