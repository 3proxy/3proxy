"""The SMTP proxy login: what it may be sent, and what may not be done."""

import base64
import socket


def recvline(sock):
    """One reply line, shorter only when the peer stops sending."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def drain_ehlo(sock):
    """Read the multi-line EHLO answer up to its last line."""
    while True:
        line = recvline(sock)
        if not line or line.startswith(b"250 "):
            return


def run(t):
    if not t.skip_unless("smtpp"):
        return
    sp = t.free_port()
    pp = t.free_port()
    t.start("smtpp_login", f"""
        log
        auth iponly
        allow *
        proxy -p{pp}

        flush
        auth none
        allow *
        smtpp -p{sp}
    """, ports=[pp, sp])

    def auth_login(name):
        """The reply the login ends with for the given name."""
        with socket.create_connection(("127.0.0.1", sp), t.timeout) as s:
            s.settimeout(t.timeout)
            recvline(s)
            s.sendall(b"EHLO case\r\n")
            drain_ehlo(s)
            s.sendall(b"AUTH LOGIN\r\n")
            recvline(s)
            s.sendall(base64.b64encode(name) + b"\r\n")
            reply = recvline(s)
            # the name carries the destination, so a refusal can come with
            # the username already, before any password is asked for
            if not reply.startswith(b"334"):
                return reply
            s.sendall(base64.b64encode(b"pw") + b"\r\n")
            return recvline(s)

    def auth_plain(name):
        """The reply of a one-line AUTH PLAIN carrying the given name."""
        with socket.create_connection(("127.0.0.1", sp), t.timeout) as s:
            s.settimeout(t.timeout)
            recvline(s)
            s.sendall(b"EHLO case\r\n")
            drain_ehlo(s)
            s.sendall(b"AUTH PLAIN " +
                      base64.b64encode(b"\x00" + name + b"\x00pw") +
                      b"\r\n")
            return recvline(s)

    # A name of a port alone names no destination: the login is refused
    # with a reply, and the daemon is left standing, its other listeners
    # among them.
    t.contains(auth_login(b"x@:25"), b"571",
               "a login name of a port alone is refused")
    t.contains(auth_plain(b"x@:25"), b"571",
               "the same name over AUTH PLAIN is refused")
    t.contains(auth_login(b"x@127.0.0.1:9"), b"571",
               "a login name of a dead host is refused")

    with socket.create_connection(("127.0.0.1", sp), t.timeout) as s:
        s.settimeout(t.timeout)
        t.eq(True, recvline(s).startswith(b"220"),
             "the SMTP proxy answers again after the refused logins")
    try:
        with socket.create_connection(("127.0.0.1", pp), t.timeout):
            t.ok("the other services of the process keep accepting")
    except OSError:
        t.fail("the other services of the process keep accepting")
