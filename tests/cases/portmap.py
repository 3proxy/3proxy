"""The port mappers: tcppm forwards a TCP port, udppm a UDP one."""


def run(t):
    # --- tcppm ---------------------------------------------------------
    origin = t.free_port()
    mapped = t.free_port()
    refused = t.free_port()

    t.start("portmap_tcp", f"""
        log
        auth iponly
        allow *
        http echo * /echo**
        http data * /data
        httpsrv -p{origin}

        flush
        auth iponly
        allow *
        tcppm {mapped} 127.0.0.1 {origin}

        flush
        auth iponly
        deny *
        tcppm {refused} 127.0.0.1 {origin}
    """, ports=[origin, mapped, refused])

    r = t.http(f"http://127.0.0.1:{mapped}/echo")
    t.eq(200, r.status, "a mapped TCP port reaches the target")
    t.contains(r, "path=/echo", "the target sees the request")
    t.contains(r, "peer.addr=127.0.0.1", "the mapper makes the connection")

    t.eq(20000, t.http(f"http://127.0.0.1:{mapped}/data?size=20000").length,
         "a body passes through the mapper")

    # the mapper is a service like any other, so its rules apply
    r = t.http(f"http://127.0.0.1:{refused}/echo")
    t.ne(200, r.status, "a mapper whose rules deny the client answers nothing")

    t.stop_all()

    # --- udppm ---------------------------------------------------------
    # something has to be listening for the mapped datagrams to go anywhere
    echo = t.udp_echo()
    mapped = t.free_port()
    t.start("portmap_udp", f"""
        log
        flush
        auth iponly
        allow *
        udppm {mapped} 127.0.0.1 {echo}
    """)
    # a UDP service has no listening socket to wait for, so ask until it
    # answers rather than racing it
    t.wait_udp(mapped)
    t.eq(b"echo:hello", t.udp_exchange(mapped, b"hello"),
         "a datagram is relayed and the reply comes back")
    t.eq(b"echo:second", t.udp_exchange(mapped, b"second"),
         "a second datagram uses the mapping again")

    big = b"x" * 2000
    t.eq(b"echo:" + big, t.udp_exchange(mapped, big),
         "a larger datagram survives the round trip")
