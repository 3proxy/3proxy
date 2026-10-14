"""Kernel TLS (ssl_ktls): a TLS chain works the same whether or not the
kernel takes the encryption, and the proxy says which it did.

Whether it does depends on the TLS library (OpenSSL built with enable-ktls),
the kernel (the tls module on Linux) and the cipher, so the case checks the
data and the report, not that the kernel took it.
"""


def run(t):
    certs = t.certs()
    if not certs:
        t.skip("kernel TLS (openssl is not available to generate certificates)")
        return
    if not certs.verified:
        t.fail("the generated certificate chain verifies", "OK",
               certs.verify_output or "openssl verify failed")
        return

    origin = t.free_port()
    parent = t.free_port()
    client = t.free_port()

    server = t.start("ktls", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        http data * /data
        httpsrv -p{origin}

        flush
        ssl_ktls
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

    out = server.output()
    if "Unknown command" in out:
        t.skip("kernel TLS (this build has no SSL support)")
        return

    through = f"127.0.0.1:{client}"
    r = t.http(f"http://127.0.0.1:{origin}/echo", proxy=through)
    t.eq(200, r.status, "a request through the TLS chain with ssl_ktls arrives")
    t.contains(r, "path=/echo", "the origin sees it")

    # many records, both ways through both TLS legs; where the kernel took
    # TLS a large body is spliced, so what arrives is compared with the origin
    for size in (100000, 3000000):
        url = f"http://127.0.0.1:{origin}/data?size={size}"
        got = t.http(url, proxy=through)
        t.eq(size, got.length, f"a {size} byte body survives the kernel TLS chain")
        t.ok(f"the {size} byte body arrives unchanged") if got.body == t.http(url).body \
            else t.fail(f"the {size} byte body arrives unchanged", "the origin's bytes",
                        "different bytes")
    t.eq(200000, t.http(f"http://127.0.0.1:{origin}/data?size=200000&chunked=1",
                        proxy=through).length,
         "a chunked body survives the kernel TLS chain")

    if "not supported by this TLS library" in server.output():
        t.skip("the kernel TLS report (this TLS library has no kernel TLS)")
        return
    log = t.wait_output(server, "kernel TLS:")
    t.contains(log, "kernel TLS: sending", "the proxy says whether the kernel took TLS")
