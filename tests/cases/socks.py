"""The SOCKS proxy, reaching the built-in server."""

import socket


def run(t):
    if not t.skip_unless("httpsrv"):
        return
    srv = t.free_port()
    sks = t.free_port()
    sauth = t.free_port()
    sdeny = t.free_port()
    sallow = t.free_port()

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

        flush
        auth iponly
        deny * * *.example.com
        allow *
        socks -p{sdeny}

        flush
        auth iponly
        allow * * *.example.com
        socks -p{sallow}
    """, ports=[srv, sks, sauth, sdeny, sallow])

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

    # A datagram names its destination by address. A rule listing host names
    # only has to judge it by that address as text, the way CONNECT is judged,
    # rather than match whatever the address is.
    reply, _ = t.socks_udp(f"127.0.0.1:{sdeny}", "127.0.0.1", echo, b"ip")
    t.eq(b"echo:ip", reply,
         "a deny by host name leaves datagrams to an address alone")
    reply, _ = t.socks_udp(f"127.0.0.1:{sallow}", "127.0.0.1", echo, b"ip")
    t.eq(None, reply,
         "an allow by host name does not let datagrams to an address through")

    # --- BIND: the proxy accepts a connection for the client --------------
    # The far side connects to where the first reply says, the second reply
    # names it, and the two are then joined both ways.
    ctrl, where = t.socks_bind(plain, "127.0.0.1")
    peer = None
    try:
        peer = socket.create_connection(where, t.timeout)
        peer.settimeout(t.timeout)
        t.ne(None, t.socks_bind_peer(ctrl), "BIND takes the connection expected")
        peer.sendall(b"from the far side")
        t.eq(b"from the far side", t._recvall(ctrl, 17),
             "what the far side sends reaches the client")
        ctrl.sendall(b"from the client")
        t.eq(b"from the client", t._recvall(peer, 15),
             "what the client sends reaches the far side")
    finally:
        ctrl.close()
        if peer:
            peer.close()

    # A connection from elsewhere than the address given is not the one
    # waited for.
    ctrl, where = t.socks_bind(plain, "192.0.2.1")
    peer = None
    try:
        peer = socket.create_connection(where, t.timeout)
        t.eq(None, t.socks_bind_peer(ctrl),
             "BIND refuses a connection from another address")
    finally:
        ctrl.close()
        if peer:
            peer.close()

    # --- authentication ----------------------------------------------------
    t.eq(200, t.socks_http(guarded, origin + "/echo",
                           auth=("alice", "secret")).status,
         "valid SOCKS5 credentials pass")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", srv,
                               auth=("alice", "wrong")),
         "wrong SOCKS5 credentials are refused")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", srv),
         "SOCKS5 without credentials is refused")
