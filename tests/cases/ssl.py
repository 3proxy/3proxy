"""TLS: a proxy wrapped in TLS, one chained to another over TLS, and MITM.

The key material is generated for the run, so nothing long-lived lives in
the tree. Cases skip when the build has no TLS or openssl is missing.
"""


def _no_tls(t, server):
    """True when the binary rejected the TLS commands in a configuration."""
    return "Unknown command" in server


def run(t):
    certs = t.certs()
    if not certs:
        t.skip("TLS (openssl is not available to generate certificates)")
        return

    # The key material has to be sound before anything is asked of the
    # proxy, or every failure below points at the wrong thing.
    if not certs.verified:
        t.fail("the generated certificate chain verifies", "OK",
               certs.verify_output or "openssl verify failed")
        return
    t.ok("the generated certificate chain verifies")

    # --- a proxy wrapped in TLS (ssl_serv) ----------------------------
    origin = t.free_port()
    tlsproxy = t.free_port()

    server = t.start("ssl_serv", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        httpsrv -p{origin}

        flush
        ssl_server_cert {certs.server}
        ssl_server_key {certs.server_key}
        ssl_serv
        auth iponly
        allow *
        proxy -p{tlsproxy}
    """, ports=[origin, tlsproxy])

    if _no_tls(t, server.output()):
        t.skip("TLS (this build has no SSL support)")
        return

    url = f"http://127.0.0.1:{origin}/echo"
    r = t.tls_proxy_http(f"127.0.0.1:{tlsproxy}", url, ca=certs.ca)
    t.eq(200, r.status, "a proxy wrapped in TLS serves a request")
    t.contains(r, "path=/echo", "the origin sees the request made over TLS")

    # a client holding a different CA must not accept the certificate
    bad = t.tls_proxy_http(f"127.0.0.1:{tlsproxy}", url, ca=certs.other)
    t.ne(200, bad.status, "a client that does not trust the CA is refused")
    t.contains(bad, "CERTIFICATE_VERIFY_FAILED",
               "the refusal is a certificate verification failure")

    # and plain HTTP must not get through a TLS listener
    t.ne(200, t.http(url, proxy=f"127.0.0.1:{tlsproxy}").status,
         "a plain request to the TLS port is refused")

    t.stop_all()

    # --- a TLS client chained to a TLS server -------------------------
    # The ssl_serv proxy is the parent; the ssl_cli proxy reaches it over
    # TLS and verifies it against the CA.
    origin = t.free_port()
    parent = t.free_port()
    client = t.free_port()

    server = t.start("ssl_chain", f"""
        log
        auth iponly
        allow *
        http * /echo* echo
        http * /data data
        httpsrv -p{origin}

        flush
        ssl_server_cert {certs.server}
        ssl_server_key {certs.server_key}
        ssl_serv
        auth iponly
        allow *
        proxy -p{parent}

        flush
        ssl_noserv
        auth iponly
        allow *
        parent 1000 connects 127.0.0.1 {parent}
        ssl_client_mode 3
        ssl_client_ca_file {certs.ca}
        ssl_client_verify
        ssl_cli
        proxy -p{client}
    """, ports=[origin, parent, client])

    through = f"127.0.0.1:{client}"
    r = t.http(f"http://127.0.0.1:{origin}/echo", proxy=through)
    t.eq(200, r.status, "a request through the TLS chain arrives")
    t.contains(r, "path=/echo", "the origin sees the chained request")

    # the origin is reached by the parent, not by the client proxy
    t.contains(r, "peer.addr=127.0.0.1", "the parent makes the final connection")

    t.eq(10000, t.http(f"http://127.0.0.1:{origin}/data?size=10000",
                       proxy=through).length,
         "a body survives the TLS chain")
    t.eq(10000, t.http(f"http://127.0.0.1:{origin}/data?size=10000&chunked=1",
                       proxy=through).length,
         "a chunked body survives the TLS chain")

    t.stop_all()

    # --- MITM ----------------------------------------------------------
    # The origin runs in its own process so the proxy log holds only what
    # the proxy saw, and an https origin gives the tunnel something real to
    # carry.
    origin = t.free_port()
    t.start("ssl_mitm_origin", f"""
        log
        ssl_server_cert {certs.server}
        ssl_server_key {certs.server_key}
        ssl_serv
        auth iponly
        allow *
        http * /secret* echo
        httpsrv -p{origin}
    """, ports=[origin])

    mitm = t.free_port()
    plain = t.free_port()
    proxies = t.start("ssl_mitm", f"""
        log
        nserver 127.0.0.1
        nscache 1024
        nsrecord intercepted.test 127.0.0.1
        ssl_server_ca_file {certs.ca}
        ssl_server_ca_key {certs.ca_key}
        ssl_certcache {certs.cache}
        ssl_client_ca_file {certs.ca}
        ssl_mitm
        auth iponly
        allow *
        proxy -p{mitm}

        flush
        ssl_nomitm
        ssl_nocli
        auth iponly
        allow *
        proxy -p{plain}
    """, ports=[mitm, plain])

    # A name the proxy resolves itself through nsrecord, so the request
    # carries a hostname the way a real one would, without depending on
    # what the machine running the tests puts in its hosts file.
    target = f"https://intercepted.test:{origin}/secret/page"

    # The client trusts our CA, which is what signs the spoofed certificate.
    # Verification is not strict: 3proxy issues those certificates without an
    # Authority Key Identifier, which Python rejects under its 3.13 defaults.
    # The spoofed certificate names the upstream host rather than the one
    # asked for, so the chain is checked but the name is not.
    r = t.https(target, proxy=f"127.0.0.1:{mitm}", ca=certs.ca, strict=False,
                verify_name=False)
    t.eq(200, r.status, "MITM passes the request through")
    t.contains(r, "path=/secret/page", "the intercepted request reaches the origin")

    # the point of interception: the decrypted request line reaches the log
    log = t.wait_output(proxies, "/secret/page")
    t.contains(log, "/secret/page", "MITM puts the request URI in the log")
    t.contains(log, "GET", "MITM logs the method")
    t.contains(log, "intercepted.test", "MITM logs the host that was asked for")

    # a client that does not trust the CA sees the substitution
    refused = t.https(target, proxy=f"127.0.0.1:{mitm}", ca=certs.other,
                      strict=False, verify_name=False)
    t.ne(200, refused.status, "MITM is visible to a client with another CA")

    # Without interception the same request is opaque: the proxy logs the
    # CONNECT target and nothing from inside the tunnel.
    before = len(proxies.output())
    r = t.https(target, proxy=f"127.0.0.1:{plain}", ca=certs.ca, strict=False,
                verify_name=False)
    t.eq(200, r.status, "the plain proxy tunnels the same request")
    tunnelled = t.wait_output(proxies, "intercepted.test", since=before)
    t.contains(tunnelled, "intercepted.test", "the tunnel logs the CONNECT target")
    t.not_contains(tunnelled, "/secret/page",
                   "a tunnelled request keeps its URI out of the log")
