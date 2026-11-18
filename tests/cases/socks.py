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

    # --- a pre-authorized association decides nothing for later ------------
    # A UDP ASSOCIATE is allowed without looking at the destination its rules
    # name, so that verdict may not be kept in the auth cache and returned
    # for a CONNECT later.
    scache = t.free_port()
    allowed = t.free_port()
    denied = t.free_port()
    t.start("socks_cacheacl", f"""
        log
        authcache user,pass,dstport 60
        auth cacheacl strong
        users u:CL:p
        allow u * * {allowed}
        deny *
        socks -p{scache}
    """, ports=[scache])
    # both destinations are alive: what decides between them is the rule
    stop = t.raw_server(allowed, b"from the allowed stand-in\r\n")
    refuse = t.raw_server(denied, b"from the refused stand-in\r\n")

    def associate_declared():
        """The reply code of a UDP ASSOCIATE naming the refused destination."""
        with socket.create_connection(("127.0.0.1", scache), t.timeout) as s:
            s.settimeout(t.timeout)
            s.sendall(b"\x05\x01\x02")
            reply = recvall(s, 2)
            if len(reply) < 2 or reply[1] != 0x02:
                return None
            s.sendall(b"\x01\x01u\x01p")
            reply = recvall(s, 2)
            if len(reply) < 2 or reply[1] != 0:
                return None
            s.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1") +
                      struct.pack("!H", denied))
            reply = recvall(s, 4)
            return reply[1] if len(reply) > 1 else None

    guarded = f"127.0.0.1:{scache}"
    t.eq(None, t.socks_connect(guarded, "127.0.0.1", allowed, auth=("u", "p")),
         "a CONNECT the rules allow is connected")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", denied, auth=("u", "p")),
         "a CONNECT the rules refuse is refused")

    t.eq(0, associate_declared(),
         "the association itself is allowed without its destination")
    t.ne(None, t.socks_connect(guarded, "127.0.0.1", denied, auth=("u", "p")),
         "a CONNECT after the association is refused all the same")
    stop()
    refuse()
