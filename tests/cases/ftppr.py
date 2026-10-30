"""The FTP proxy logging in to its server: whatever the server answers the
login with reaches the client, which waits for the answer to its PASS."""

import socket
import threading

# what the server answers USER with, and PASS if it asks for one
LOGINS = {
    "230 to USER": ([b"230 Anonymous user logged in"], None),
    "multiline 230 to USER": ([b"230-Welcome", b"230-to the server", b"230 Login successful."], None),
    "331 to USER, 230 to PASS": ([b"331 Please specify the password."], [b"230 Login successful."]),
    "530 to USER": ([b"530 Not allowed here"], None),
    "331 to USER, 530 to PASS": ([b"331 Please specify the password."], [b"530 Login incorrect."]),
}


def ftp_server(listener, user, password):
    """Greets, answers the login as told, then NOOP and QUIT."""
    while True:
        try:
            c, _ = listener.accept()
        except OSError:
            return
        try:
            f = c.makefile("rb")
            c.sendall(b"220 Fake FTP\r\n")
            if not f.readline().upper().startswith(b"USER "):
                continue
            c.sendall(b"".join(line + b"\r\n" for line in user))
            if password is not None:
                if not f.readline().upper().startswith(b"PASS "):
                    continue
                c.sendall(b"".join(line + b"\r\n" for line in password))
            for line in f:
                if line.upper().startswith(b"NOOP"):
                    c.sendall(b"200 NOOP ok\r\n")
                elif line.upper().startswith(b"QUIT"):
                    c.sendall(b"221 Bye\r\n")
                    break
                else:
                    c.sendall(b"502 Not implemented\r\n")
        except OSError:
            pass
        finally:
            c.close()


def reply(f):
    """The last line of a reply, multiline or not; empty at the end or on a
    time out."""
    while True:
        try:
            line = f.readline()
        except OSError:
            return b""
        if not line:
            return b""
        if len(line) < 4 or line[3:4] != b"-":
            return line.rstrip()


def run(t):
    if not t.skip_unless("ftppr"):
        return
    servers = {}
    for name, (user, password) in LOGINS.items():
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        threading.Thread(target=ftp_server, args=(listener, user, password), daemon=True).start()
        servers[name] = listener

    port = t.free_port()
    t.start("ftppr", f"""
        log
        auth none
        ftppr -p{port}
    """, ports=[port])

    # without WITH_FTP the service closes the connection at once
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    built = reply(s.makefile("rb"))
    s.close()
    if not built:
        t.skip("the FTP proxy (not built in this configuration)")
        for listener in servers.values():
            listener.close()
        t.stop_all()
        return

    for name, listener in servers.items():
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        f = s.makefile("rb")
        reply(f)
        s.sendall(b"USER anonymous@127.0.0.1:%d\r\n" % listener.getsockname()[1])
        reply(f)
        s.sendall(b"PASS test@example.com\r\n")
        got = reply(f)
        ok = LOGINS[name][1] if LOGINS[name][1] is not None else LOGINS[name][0]
        t.eq(ok[-1][:3], got[:3], f"{name}: the client gets the server's answer")
        if got.startswith(b"230"):
            s.sendall(b"NOOP\r\n")
            t.eq(b"200", reply(f)[:3], f"{name}: and the session goes on")
        s.close()

    for listener in servers.values():
        listener.close()
    t.stop_all()
