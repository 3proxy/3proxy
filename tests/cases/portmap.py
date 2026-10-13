"""The port mappers: tcppm forwards a TCP port, udppm a UDP one."""

import socket
import threading
import time

HALFCLOSE_SIZE = 20000000


def halfclose_origin(listener):
    """Answers each connection which asks for something with HALFCLOSE_SIZE
    bytes, then waits for the client's end of the stream and closes. The
    connections waiting for the service to start ask nothing."""
    while True:
        try:
            c, _ = listener.accept()
        except OSError:
            return
        try:
            if c.recv(1000):
                c.sendall(b"x" * HALFCLOSE_SIZE)
                c.recv(10)
        except OSError:
            pass
        c.close()


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

    # A client which shuts down its sending side still gets the whole answer,
    # even when it reads slowly: the server has finished and closed by then,
    # and the rest of the answer waits in the proxy's buffer and the kernel's.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    threading.Thread(target=halfclose_origin, args=(listener,), daemon=True).start()
    halfclosed = t.free_port()
    t.start("portmap_halfclose", f"""
        log
        auth none
        tcppm {halfclosed} 127.0.0.1 {listener.getsockname()[1]}
    """, ports=[halfclosed])
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    s.settimeout(30)
    got = 0
    try:
        s.connect(("127.0.0.1", halfclosed))
        s.sendall(b"request")
        s.shutdown(socket.SHUT_WR)
        time.sleep(1)
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += len(d)
    except OSError:
        pass
    s.close()
    listener.close()
    t.eq(HALFCLOSE_SIZE, got, "a half-closed client reading slowly gets the whole answer")

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
