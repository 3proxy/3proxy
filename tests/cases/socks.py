"""The SOCKS proxy, reaching the built-in server."""

import socket
import struct


def recvall(sock, count):
    """Bytes from a socket, fewer only when the peer stops sending."""
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            break
        data += chunk
    return data


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

    # --- names a client may not choose -------------------------------------
    # A destination name travels into the request lines of parent protocols,
    # so a control byte or a space in it could end the line early and name
    # another destination. Such a name is refused where it is read, before
    # anything is resolved or connected: reply 1, not the reply of a
    # destination which does not answer.
    sname = t.free_port()
    standin = t.free_port()
    t.start("socks_names", f"""
        log
        fakeresolve
        auth iponly
        allow *
        socks -p{sname}
    """, ports=[sname])

    def socks5_name(name, port):
        """The reply code of a SOCKS5 CONNECT naming the given name."""
        with socket.create_connection(("127.0.0.1", sname), t.timeout) as s:
            s.settimeout(t.timeout)
            s.sendall(b"\x05\x01\x00")
            if recvall(s, 2) != b"\x05\x00":
                return None
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name +
                      struct.pack("!H", port))
            reply = recvall(s, 4)
            return reply[1] if len(reply) > 1 else None

    def socks4_name(name, port):
        """The reply code of a SOCKS4a CONNECT naming the given name."""
        with socket.create_connection(("127.0.0.1", sname), t.timeout) as s:
            s.settimeout(t.timeout)
            s.sendall(struct.pack(">BBH", 4, 1, port) +
                      socket.inet_aton("0.0.0.0") + b"case\x00" + name +
                      b"\x00")
            reply = recvall(s, 8)
            return reply[1] if len(reply) > 1 else None

    t.eq(1, socks5_name(b"127.0.0.1\r\nGET /other HTTP/1.1\r\n\r\nstand-in.example",
                        standin),
         "a name with CR LF in it is refused")
    t.eq(91, socks4_name(b"127.0.0.1\r\nGET /other HTTP/1.1\r\n\r\nstand-in.example",
                         standin),
         "SOCKS4a refuses a name with CR LF in it")
    t.eq(1, socks5_name(b"127.0.0.1 stand-in.example", standin),
         "a name with a space in it is refused")
    t.eq(1, socks5_name(b"stand-in\x7f.example", standin),
         "a name with a control byte in it is refused")

    # a well-formed name is let through, to the 127.0.0.2 fakeresolve maps
    # every name to; where that address can be served, the tunnel has to be
    # carried all the way to it
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.2", 0))
    except OSError:
        probe.close()
        t.skip("the stand-in address 127.0.0.2 can not be bound here")
    else:
        probe.close()
        stop = t.raw_server(standin, b"from the stand-in\r\n",
                           host="127.0.0.2")
        t.eq(0, socks5_name(b"stand-in.example", standin),
             "a well-formed name is connected by name")
        t.eq(90, socks4_name(b"stand-in.example", standin),
             "a well-formed name is connected by name over SOCKS4a")
        stop()

