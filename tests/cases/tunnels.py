"""The UDP<->TCP tunnels: udptotcp takes datagrams to a TCP connection,
tcptoudp takes a TCP connection to datagrams, the datagrams on the
connection carrying their length, as udptunnel and ProxyGuard put them."""

import socket
import struct
import threading

UDP_MAGIC = b"udptunnel by md.\0\0\0\x01\x03\x06\x10\x15\x21\x28\x36\x45\x55\x66\x78\x91"
PG_GET = (b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: test\r\n"
          b"Connection: Upgrade\r\nUpgrade: UoTLV/1\r\n\r\n")


def frame(payload):
    return struct.pack(">H", len(payload)) + payload


def read_frames(sock, state, count, timeout=10.0):
    """count length-prefixed datagrams from sock; state[0] is the bytes
    already read and not yet used."""
    out = []
    sock.settimeout(timeout)
    while len(out) < count:
        while len(state[0]) >= 2:
            need = 2 + struct.unpack(">H", state[0][:2])[0]
            if len(state[0]) < need:
                break
            out.append(state[0][2:need])
            state[0] = state[0][need:]
        if len(out) >= count:
            return out
        data = sock.recv(65536)
        if not data:
            raise EOFError("the tunnel closed")
        state[0] += data
    return out


def run(t):
    echo = t.udp_echo()
    tunnel = t.free_port()      # udptotcp listens here
    tunnel_hs = t.free_port()   # the same, udptunnel's handshake
    server = t.free_port()      # tcptoudp listens here
    plain = t.free_port()       # tcptoudp for the handshake clients

    t.start("tunnels", f"""
        log
        auth iponly
        allow *
        udptotcp {tunnel} 127.0.0.1 {server}
        udptotcp -m {tunnel_hs} 127.0.0.1 {server}

        flush
        auth iponly
        allow *
        tcptoudp {server} 127.0.0.1 {echo}
        tcptoudp {plain} 127.0.0.1 {echo}
    """, ports=[server, plain])
    # a UDP service answers only once it is asked, so ask until it does
    if t.wait_udp(tunnel):
        t.ok("the UDP side of the tunnel is up")
    else:
        t.fail("the UDP side of the tunnel is up")

    # --- a datagram each way, through both services ---------------
    t.eq(b"echo:hello", t.udp_exchange(tunnel, b"hello"),
         "a datagram reaches the target through the tunnel")
    t.eq(b"echo:again", t.udp_exchange(tunnel, b"again"),
         "a second datagram uses the same session")
    big = b"x" * 4000
    t.eq(b"echo:" + big, t.udp_exchange(tunnel, big),
         "a larger datagram survives the round trip")

    # --- udptunnel's handshake, accepted by tcptoudp ---------------
    if t.wait_udp(tunnel_hs):
        t.ok("the UDP side of the udptunnel-handshake tunnel is up")
    t.eq(b"echo:with handshake", t.udp_exchange(tunnel_hs, b"with handshake"),
         "a datagram with udptunnel's handshake before it is answered")

    # --- a client speaking udptunnel, to tcptoudp ------------------
    s = socket.create_connection(("127.0.0.1", plain), timeout=10)
    s.sendall(UDP_MAGIC + frame(b"udptunnel asks"))
    t.eq([b"echo:udptunnel asks"], read_frames(s, [b""], 1),
         "a udptunnel client is answered")
    s.close()

    # --- a client speaking ProxyGuard, to tcptoudp -----------------
    s = socket.create_connection(("127.0.0.1", plain), timeout=10)
    s.sendall(PG_GET)
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(4096)
    t.eq(True, head.startswith(b"HTTP/1.1 101"),
         "ProxyGuard's client is told the protocols are switched")
    t.contains(head.decode("latin1"), "UoTLV/1", "the answer names the protocol")
    s.sendall(frame(b"proxyguard asks"))
    t.eq([b"echo:proxyguard asks"], read_frames(s, [b""], 1),
         "ProxyGuard's datagram is answered")
    s.close()

    # --- a client that frames, two datagrams in one write ----------
    s = socket.create_connection(("127.0.0.1", plain), timeout=10)
    s.sendall(frame(b"first") + frame(b"second"))
    t.eq([b"echo:first", b"echo:second"], read_frames(s, [b""], 2),
         "two datagrams in one write are both answered")
    s.close()
