"""Connections of old services after a reload (unless noforce): each goes by
the rules of the newest service on its listener, taking one of its maxconn
slots, and is dropped where that cannot be."""

import base64
import socket
import threading
import time


def run(t):
    origin = t.free_port()
    proxy = t.free_port()
    adm = t.free_port()

    def config(service_line, maxconn=50):
        return f"""
            log
            auth iponly
            allow *
            http data * /data
            httpsrv -p{origin}

            flush
            maxconn {maxconn}
            auth iponly
            allow *
            {service_line}

            flush
            maxconn 50
            auth iponly
            allow *
            admin -p{adm}
        """

    server = t.start("reattach", config(f"proxy -p{proxy}"), ports=[origin, proxy, adm])

    def reload(conf):
        before = server.output().count("Accepting connections")
        t.write_config("reattach", conf)
        t.http(f"http://127.0.0.1:{adm}/R")
        deadline = time.time() + 10
        while time.time() < deadline and server.output().count("Accepting connections") < before + 3:
            time.sleep(0.05)

    def downloads(n):
        """n downloads of about two seconds each through the proxy, started
        now; the results fill in as they finish."""
        results = [{} for _ in range(n)]

        def one(r):
            got = t.http(f"http://127.0.0.1:{origin}/data?size=2000000&block=65536&delay=60",
                         proxy=f"127.0.0.1:{proxy}")
            r["length"] = got.length

        threads = [threading.Thread(target=one, args=(r,)) for r in results]
        for th in threads:
            th.start()
        time.sleep(0.4)
        return threads, results

    # --- the newest service has one slot free: one connection moves, one is
    # cut. A service holds one of its maxconn slots for the next connection
    # it accepts, so maxconn 2 leaves one.
    threads, results = downloads(2)
    reload(config(f"proxy -p{proxy}", maxconn=2))
    for th in threads:
        th.join(20)
    whole = sum(1 for r in results if r.get("length") == 2000000)
    t.eq(1, whole, "with one slot free in the new service one download goes on")
    t.contains(server.output(), " 00027 ",
               "the other is cut for want of a slot (27)")

    # --- the service on the port is of another type now: cut (26)
    reload(config(f"proxy -p{proxy}"))
    threads, results = downloads(1)
    reload(config(f"socks -p{proxy}"))
    for th in threads:
        th.join(20)
    t.ok("a proxy download is cut when a socks service takes the port") \
        if results[0].get("length", 0) < 2000000 else \
        t.fail("a proxy download is cut when a socks service takes the port",
               "less than 2000000 bytes", results[0].get("length"))
    t.contains(server.output(), " 00026 ", "as its service is another one now (26)")

    # --- services of one configuration on one address share its socket, so
    # they must be of one type with the same options: otherwise the file is
    # refused and the configuration in force stays ---------------------------
    for line, why in ((f"proxy -p{proxy}\n            socks -p{proxy}",
                       "a service of another type listens there"),
                      (f"proxy -p{proxy}\n            proxy -olSO_KEEPALIVE -p{proxy}",
                       "a service with other socket options listens there")):
        mark = len(server.output())
        t.write_config("reattach", config(line))
        t.http(f"http://127.0.0.1:{adm}/R")
        deadline = time.time() + 10
        while time.time() < deadline and why not in server.output()[mark:]:
            time.sleep(0.05)
        t.contains(server.output()[mark:], why, f"refused: {why}")
    # the socks service of the case before is still the one there
    t.ne(200, t.http(f"http://127.0.0.1:{origin}/data?size=100", proxy=f"127.0.0.1:{proxy}").status,
         "the configuration in force stays: the socks service, no HTTP proxy")
    reload(config(f"proxy -p{proxy}\n            proxy -p{proxy}"))
    ok = sum(1 for _ in range(20)
             if t.http(f"http://127.0.0.1:{origin}/data?size=100", proxy=f"127.0.0.1:{proxy}").status == 200)
    t.eq(20, ok, "two proxy services on one address both serve, sharing its socket")

    # --- a service connecting back (-r) has no socket, but a listener for the
    # place it connects to, here shared by two services connecting there: its
    # clients are re-authenticated all the same ---
    peer = socket.socket()
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    peer.bind(("127.0.0.1", 0))
    peer.listen(16)
    peer.settimeout(10)
    cb = peer.getsockname()[1]

    def cbconfig(users):
        return config(f"proxy -p{proxy}").replace(
            "flush\n            maxconn 50\n            auth iponly\n            allow *\n            admin",
            f"flush\n            users {users}\n            auth strong\n            allow *\n"
            f"            proxy -r127.0.0.1:{cb}\n            proxy -r127.0.0.1:{cb}\n\n"
            "            flush\n            maxconn 50\n"
            "            auth iponly\n            allow *\n            admin")

    def cb_download(result):
        """A request over a connection the -r service made: the peer is its
        client once it has sent C."""
        try:
            c, _ = peer.accept()
            c.settimeout(20)
            c.sendall(b"C")
            auth = base64.b64encode(b"alice:one").decode()
            c.sendall((f"GET http://127.0.0.1:{origin}/data?size=2000000&block=65536&delay=60 HTTP/1.1\r\n"
                       f"Host: 127.0.0.1:{origin}\r\nProxy-Authorization: Basic {auth}\r\n"
                       "Connection: close\r\n\r\n").encode())
            got = b""
            while True:
                b = c.recv(65536)
                if not b:
                    break
                got += b
            c.close()
            result["body"] = len(got.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in got else 0
        except OSError as e:
            result["error"] = str(e)

    reload(cbconfig("alice:CL:one"))
    for keep, users, want in ((True, "alice:CL:one bob:CL:two", "finishes whole"),
                              (False, "bob:CL:two", "is cut")):
        result = {}
        th = threading.Thread(target=cb_download, args=(result,))
        th.start()
        time.sleep(0.5)
        reload(cbconfig(users))
        th.join(25)
        whole = result.get("body") == 2000000
        name = f"a download through a connect-back service {want} when alice is " + \
            ("kept" if keep else "removed")
        t.ok(name) if whole == keep else t.fail(name, "whole" if keep else "cut", result)
        if keep:
            reload(cbconfig("alice:CL:one"))
    peer.close()
