"""Support code for the 3proxy regression tests.

Everything here is standard library, so the suite runs wherever 3proxy
builds: no shell, no curl, no netcat.

A test case is a module under tests/cases/ exporting run(t). It writes the
configurations it needs, starts them, and states what it expects:

    def run(t):
        srv = t.free_port()
        t.start("echo", f'''
            log
            auth iponly
            allow *
            http * /echo echo
            httpsrv -p{srv}
        ''', ports=[srv])
        r = t.http(f"http://127.0.0.1:{srv}/echo")
        t.eq(200, r.status, "the server answers")
"""

import base64
import http.client
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
import threading
import time


# Ports handed out in this run: a service which has finished may still be
# in TIME_WAIT, and another case binding the same port would fail for it.
_PORTS_TAKEN = set()


class Response:
    """A reply, or the reason there wasn't one."""

    def __init__(self, status=None, body=b"", headers=None, error=None):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.error = error

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    @property
    def length(self):
        return len(self.body)

    def header(self, name):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def __repr__(self):
        if self.error:
            return f"<no reply: {self.error}>"
        return f"<{self.status}, {len(self.body)} bytes>"


class Server:
    """A running 3proxy, with the configuration it was given."""

    def __init__(self, name, path, proc, logfile):
        self.name = name
        self.path = path
        self.proc = proc
        self.logfile = logfile

    def output(self):
        try:
            with open(self.logfile, "rb") as fp:
                return fp.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


class Certs:
    """A test CA, a certificate it signed, and somewhere to cache spoofed ones.

    Paths use forward slashes: they are written into configurations read by
    3proxy, and ssl_certcache insists on a trailing separator.
    """

    def __init__(self, directory):
        self.dir = directory.replace("\\", "/")
        self.ca = self.dir + "/ca.pem"
        self.ca_key = self.dir + "/ca.key"
        self.server = self.dir + "/server.pem"
        self.server_key = self.dir + "/server.key"
        # a second CA nothing is signed by, for the cases that must fail
        self.other = self.dir + "/other.pem"
        self.other_key = self.dir + "/other.key"
        self.cache = self.dir + "/cache/"
        self.verified = False
        self.verify_output = ""


class Failure(Exception):
    """Raised when a case cannot go on, e.g. a server refused to start."""


class Tester:
    """The API a case runs against: start servers, make requests, assert."""

    def __init__(self, binary, tmpdir, case):
        self.binary = binary
        self.tmpdir = tmpdir
        self.case = case
        self.servers = []
        self.checks = []
        self.timeout = 10
        self._raw_kept = []
        self._skipped = 0
        self._certs = None
        self.logs = []
        self.udp_servers = []

    # ---- servers -----------------------------------------------------

    def has_ipv6(self):
        """Whether this machine can use the IPv6 loopback at all."""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            return False
        try:
            sock.bind(("::1", 0))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def free_port(self):
        """A port nothing is listening on, and nothing is likely to take.

        Asking the system for an ephemeral port hands back one out of the
        range it also draws outgoing connections from - 32768 up on Linux,
        49152 up on Windows - so between the check here and the bind in the
        service, a connection somewhere else in the suite can take it. That
        shows up as a service which never listens, or a bind() error deep in
        a case which has nothing to do with ports. Ports are taken from below
        both ranges instead, and none is handed out twice in a run.
        """
        for _ in range(200):
            port = random.randint(10000, 19999)
            if port in _PORTS_TAKEN:
                continue
            sock = socket.socket()
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            finally:
                sock.close()
            _PORTS_TAKEN.add(port)
            return port
        raise RuntimeError("no free port in the range the suite uses")

    def write_config(self, name, config):
        path = os.path.join(self.tmpdir, name + ".cfg")
        text = textwrap.dedent(config).strip() + "\n"
        # newline="" keeps the line endings as written, rather than letting
        # Windows turn them into CRLF behind the parser's back
        with open(path, "w", newline="") as fp:
            fp.write(text)
        return path

    def start(self, name, config, ports=()):
        """Write a configuration, run it, and wait for its ports to open.

        A port may be given as a number, or as (address, port) for a service
        bound somewhere other than 127.0.0.1.
        """
        path = self.write_config(name, config)
        logfile = os.path.join(self.tmpdir, name + ".out")
        with open(logfile, "wb") as out:
            proc = subprocess.Popen([self.binary, path], stdout=out,
                                    stderr=subprocess.STDOUT)
        server = Server(name, path, proc, logfile)
        self.servers.append(server)

        for entry in ports:
            host, port = entry if isinstance(entry, tuple) else ("127.0.0.1", entry)
            if not self.wait_port(port, host=host):
                code = proc.poll()
                if code is None:
                    died = "the process is still running"
                else:
                    died = f"the process exited with code {code}"
                    if os.name == "nt" and code is not None and code & 0xFFFFFFFF == 0xC0000135:
                        died += " (a DLL it needs was not found)"
                raise Failure(
                    f"{name} never listened on port {port}: {died}\n"
                    f"--- configuration ---\n{open(path).read()}"
                    f"--- output ---\n{server.output()}")
        return server

    def run_config(self, name, config):
        """Run a configuration expected to be rejected; return its output."""
        path = self.write_config(name, config)
        done = subprocess.run([self.binary, path], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=15)
        return done.stdout.decode("utf-8", "replace")

    def wait_port(self, port, timeout=5.0, host="127.0.0.1"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), 0.25):
                    return True
            except OSError:
                time.sleep(0.02)
        return False

    def wait_output(self, server, needle, timeout=5.0, since=0):
        """Wait for a server to log something.

        A record is written when the connection it describes finishes, not
        when the reply reaches the client, so reading straight after a
        request usually finds nothing yet.
        """
        deadline = time.time() + timeout
        while True:
            text = server.output()[since:]
            if needle in text or time.time() > deadline:
                return text
            time.sleep(0.05)

    def stop_all(self):
        """Stop the servers, keeping what they printed for the report."""
        for sock in self.udp_servers:
            sock.close()
        self.udp_servers = []
        for server in self.servers:
            server.stop()
            self.logs.append((server.name, server.output()))
        self.servers = []

    # ---- requests ----------------------------------------------------

    def http(self, url, proxy=None, socks=None, socks4=False,
             remote_dns=False, method="GET", body=None, headers=None,
             auth=None, proxy_auth=None, tunnel=False, conn=None):
        """Make a request, directly or through a proxy, and read the reply.

        proxy       "host:port" of an HTTP proxy
        socks       "host:port" of a SOCKS proxy
        tunnel      reach the origin with CONNECT rather than an absolute URI
        conn        reuse a connection returned by connection()
        """
        host, port, path = self._split(url)
        headers = dict(headers or {})
        if auth:
            headers["Authorization"] = self._basic(auth)
        if proxy_auth:
            headers["Proxy-Authorization"] = self._basic(proxy_auth)

        own = conn is None
        try:
            if own:
                conn = self.connection(host, port, proxy=proxy, socks=socks,
                                       socks4=socks4, remote_dns=remote_dns,
                                       tunnel=tunnel)
            target = path
            if proxy and not tunnel:
                # an address with colons goes back in brackets, or the
                # absolute URI cannot be read
                authority = f"[{host}]" if ":" in host else host
                target = f"http://{authority}:{port}{path}"
            if body is not None and not isinstance(body, bytes):
                body = body.encode()
            conn.request(method, target, body=body, headers=headers)
            reply = conn.getresponse()
            data = reply.read()
            return Response(reply.status, data, dict(reply.getheaders()))
        except (OSError, http.client.HTTPException) as exc:
            return Response(error=f"{type(exc).__name__}: {exc}")
        finally:
            if own and conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    def connection(self, host, port, proxy=None, socks=None, socks4=False,
                   remote_dns=False, tunnel=False):
        """A connection to an origin, kept open for reuse."""
        if socks:
            shost, sport = self._hostport(socks)
            sock = self._socks_connect(shost, sport, host, port,
                                       socks4=socks4, remote_dns=remote_dns)
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.sock = sock
            return conn
        if proxy:
            phost, pport = self._hostport(proxy)
            conn = http.client.HTTPConnection(phost, pport, timeout=self.timeout)
            if tunnel:
                conn.set_tunnel(host, port)
            return conn
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def raw(self, port, request, host="127.0.0.1"):
        """Send bytes as they are and return whatever comes back."""
        if not isinstance(request, bytes):
            request = request.encode("latin-1")
        try:
            with socket.create_connection((host, port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(request)
                chunks = []
                while True:
                    try:
                        piece = sock.recv(65536)
                    except OSError:
                        # a timeout, or a reset once the server is done:
                        # either way keep whatever already arrived
                        break
                    if not piece:
                        break
                    chunks.append(piece)
                return b"".join(chunks).decode("utf-8", "replace")
        except OSError as exc:
            return f"<no reply: {exc}>"

    def raw_session(self, port, request, host="127.0.0.1", quiet=0.5):
        """Send bytes and read until the server closes or goes quiet.

        Returns (text, closed). closed says the server ended the connection
        rather than leaving it open for another request, which is the whole
        question a keep-alive test asks.
        """
        if not isinstance(request, bytes):
            request = request.encode("latin-1")
        closed = False
        chunks = []
        try:
            with socket.create_connection((host, port), self.timeout) as sock:
                try:
                    sock.sendall(request)
                except OSError:
                    # the server answered and closed before taking all of it,
                    # which is an answer in itself
                    closed = True
                sock.settimeout(quiet)
                while True:
                    try:
                        piece = sock.recv(65536)
                    except socket.timeout:
                        break               # quiet: the connection is still open
                    except OSError:
                        closed = True       # reset: it is not
                        break
                    if not piece:
                        closed = True
                        break
                    chunks.append(piece)
        except OSError as exc:
            return f"<no reply: {exc}>", True
        return b"".join(chunks).decode("utf-8", "replace"), closed

    def raw_proxy_request(self, proxy, url, extra="", body="", method=None):
        """Send one absolute-URI request through a proxy, headers and all.

        For the requests a client library will not send: an oversized header
        block, or one whose exact bytes matter.
        """
        phost, pport = self._hostport(proxy)
        host, port, path = self._split(url)
        method = method or ("POST" if body else "GET")
        request = (f"{method} http://{host}:{port}{path} HTTP/1.1\r\n"
                   f"Host: {host}:{port}\r\n" + extra)
        if body:
            request += f"Content-Length: {len(body)}\r\n"
        request += "\r\n" + body
        text, _ = self.raw_session(pport, request, host=phost, quiet=2)
        return text

    def raw_server(self, port, reply, close_after=True, host="127.0.0.1",
                   drain=False):
        """Answer every connection with fixed bytes. Returns a stop function.

        For the shapes a real server would have to be talked into: an answer
        whose body is delimited by the close, or one which promises to stay
        and does not. drain reads the whole request first, however large,
        which is what a test of the sending side needs.
        """
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(8)
        running = [True]

        def serve():
            while running[0]:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    break
                try:
                    conn.settimeout(0.5 if drain else self.timeout)
                    while True:
                        try:
                            if not conn.recv(65536) or not drain:
                                break
                        except socket.timeout:
                            break       # it has stopped sending
                    conn.sendall(reply)
                    if close_after:
                        conn.close()
                    else:
                        self._raw_kept.append(conn)
                except OSError:
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        def stop():
            running[0] = False
            try:
                sock.close()
            except OSError:
                pass

        return stop

    # ---- UDP ---------------------------------------------------------

    def udp_echo(self, prefix=b"echo:"):
        """Start a UDP server that echoes what it receives, and give its port.

        Something has to be on the far side of a port mapper or a SOCKS
        association for the data path to be visible at all.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        def serve():
            while True:
                try:
                    data, peer = sock.recvfrom(65536)
                except OSError:
                    return
                try:
                    sock.sendto(prefix + data, peer)
                except OSError:
                    return

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.udp_servers.append(sock)
        return port

    def udp_exchange(self, port, payload, host="127.0.0.1"):
        """Send one datagram and return the reply, or None."""
        if not isinstance(payload, bytes):
            payload = payload.encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (host, port))
            return sock.recvfrom(65536)[0]
        except OSError:
            return None
        finally:
            sock.close()

    def wait_udp(self, port, payload=b"ping", timeout=5.0):
        """Wait until a UDP service answers.

        There is no socket to connect to, so readiness can only be found
        out by asking; a datagram sent before the service is up is simply
        lost.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.udp_exchange(port, payload) is not None:
                return True
            time.sleep(0.05)
        return False

    def socks_udp(self, socks, host, port, payload, keep=None):
        """Relay a datagram through a SOCKS5 association.

        Returns (reply payload, association port), or (None, port) if
        nothing came back. The control connection has to stay open for the
        association to live, so it is closed only on the way out.
        """
        if not isinstance(payload, bytes):
            payload = payload.encode()
        shost, sport = self._hostport(socks)
        ctrl = None
        udp = None
        try:
            ctrl = socket.create_connection((shost, sport), self.timeout)
            ctrl.settimeout(self.timeout)
            ctrl.sendall(b"\x05\x01\x00")
            if self._recvall(ctrl, 2) != b"\x05\x00":
                return None, None
            ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00" + struct.pack("!H", 0))
            reply = self._recvall(ctrl, 4)
            if len(reply) < 4 or reply[1] != 0:
                return None, None
            _, bound = self._read_socks_addr(ctrl, reply[3])

            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(self.timeout)
            header = (b"\x00\x00\x00\x01" + socket.inet_aton(host) +
                      struct.pack("!H", port))
            udp.sendto(header + payload, (shost, bound))
            try:
                data = udp.recvfrom(65536)[0]
            except OSError:
                return None, bound
            # the reply carries the same kind of header, which is not payload
            if len(data) < 10 or data[3] != 1:
                return None, bound
            return data[10:], bound
        except OSError:
            return None, None
        finally:
            if udp:
                udp.close()
            if ctrl:
                ctrl.close()

    # ---- DNS ---------------------------------------------------------

    def dns_query(self, port, name, host="127.0.0.1", timeout=2.0):
        """Ask for an A record and return the addresses in the answer.

        The default timeout is short: a name server on the loopback answers
        at once or not at all, and waiting the full request timeout on every
        attempt turns a server that answers nothing into a very slow run.
        """
        query = struct.pack("!HHHHHH", 0x2A2A, 0x0100, 1, 0, 0, 0)
        for label in name.split("."):
            query += bytes([len(label)]) + label.encode()
        query += b"\x00" + struct.pack("!HH", 1, 1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (host, port))
            data = sock.recvfrom(65536)[0]
        except OSError:
            return None
        finally:
            sock.close()

        if len(data) < 12 or data[:2] != query[:2]:
            return None
        answers = struct.unpack("!H", data[6:8])[0]
        addresses = []
        pos = 12
        while pos < len(data) and data[pos]:      # skip the question
            pos += data[pos] + 1
        pos += 5
        for _ in range(answers):
            if pos + 12 > len(data):
                break
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos]:
                    pos += data[pos] + 1
                pos += 1
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                addresses.append(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
        return addresses

    # ---- SOCKS -------------------------------------------------------

    def _socks_connect(self, shost, sport, host, port, socks4=False,
                       remote_dns=False, auth=None):
        sock = socket.create_connection((shost, sport), self.timeout)
        sock.settimeout(self.timeout)
        try:
            if socks4:
                addr = socket.inet_aton(socket.gethostbyname(host))
                sock.sendall(b"\x04\x01" + struct.pack("!H", port) + addr + b"\x00")
                reply = self._recvall(sock, 8)
                if len(reply) < 2 or reply[1] != 0x5a:
                    raise OSError("SOCKS4 request refused")
                return sock

            if auth:
                sock.sendall(b"\x05\x02\x00\x02")
            else:
                sock.sendall(b"\x05\x01\x00")
            reply = self._recvall(sock, 2)
            if len(reply) < 2 or reply[0] != 5:
                raise OSError("SOCKS5 handshake failed")
            if reply[1] == 0x02:
                if not auth:
                    raise OSError("SOCKS5 server demands credentials")
                user, password = auth
                sock.sendall(b"\x01" + bytes([len(user)]) + user.encode() +
                             bytes([len(password)]) + password.encode())
                status = self._recvall(sock, 2)
                if len(status) < 2 or status[1] != 0:
                    raise OSError("SOCKS5 credentials refused")
            elif reply[1] != 0x00:
                raise OSError("SOCKS5 offered no acceptable method")

            if remote_dns:
                target = b"\x03" + bytes([len(host)]) + host.encode()
            elif ":" in host:
                target = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
            else:
                target = b"\x01" + socket.inet_aton(socket.gethostbyname(host))
            sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", port))
            reply = self._recvall(sock, 4)
            if len(reply) < 4 or reply[1] != 0:
                raise OSError("SOCKS5 request refused")
            self._read_socks_addr(sock, reply[3])
            return sock
        except Exception:
            sock.close()
            raise

    def socks_connect(self, socks, host, port, socks4=False, remote_dns=False,
                      auth=None):
        """Open a SOCKS connection, reporting failure rather than raising."""
        shost, sport = self._hostport(socks)
        try:
            sock = self._socks_connect(shost, sport, host, port, socks4=socks4,
                                       remote_dns=remote_dns, auth=auth)
            sock.close()
            return None
        except OSError as exc:
            return str(exc)

    def socks_http(self, socks, url, auth=None, **kwargs):
        """A request through SOCKS, with optional SOCKS credentials."""
        host, port, path = self._split(url)
        shost, sport = self._hostport(socks)
        try:
            sock = self._socks_connect(shost, sport, host, port, auth=auth,
                                       **kwargs)
        except OSError as exc:
            return Response(error=str(exc))
        conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        conn.sock = sock
        try:
            conn.request("GET", path)
            reply = conn.getresponse()
            return Response(reply.status, reply.read(), dict(reply.getheaders()))
        except (OSError, http.client.HTTPException) as exc:
            return Response(error=str(exc))
        finally:
            conn.close()

    def socks_udp_associate(self, port, host="127.0.0.1"):
        """Ask for a UDP association and report the port handed back.

        That socket is allocated per association, which is where an intport
        range has to take effect.
        """
        try:
            with socket.create_connection((host, port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(b"\x05\x01\x00")
                if self._recvall(sock, 2) != b"\x05\x00":
                    return None
                sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00" +
                             struct.pack("!H", 0))
                reply = self._recvall(sock, 4)
                if len(reply) < 4 or reply[1] != 0:
                    return None
                _, bound = self._read_socks_addr(sock, reply[3])
                return bound
        except OSError:
            return None

    def _read_socks_addr(self, sock, atyp):
        if atyp == 1:
            addr = socket.inet_ntoa(self._recvall(sock, 4))
        elif atyp == 3:
            length = self._recvall(sock, 1)[0]
            addr = self._recvall(sock, length).decode()
        elif atyp == 4:
            addr = self._recvall(sock, 16).hex()
        else:
            raise OSError(f"unknown SOCKS address type {atyp}")
        port = struct.unpack("!H", self._recvall(sock, 2))[0]
        return addr, port

    @staticmethod
    def _recvall(sock, count):
        data = b""
        while len(data) < count:
            piece = sock.recv(count - len(data))
            if not piece:
                break
            data += piece
        return data

    # ---- TLS ---------------------------------------------------------

    def certs(self):
        """A CA and a certificate for 127.0.0.1, generated once per run.

        Returns None when openssl is unavailable, so a case can skip rather
        than fail on a machine that cannot make key material.
        """
        if self._certs is not None:
            return self._certs or None
        if not shutil.which("openssl"):
            self._certs = False
            return None

        c = Certs(os.path.join(self.tmpdir, "certs"))
        os.makedirs(c.cache, exist_ok=True)
        csr = c.dir + "/server.csr"
        ext = c.dir + "/server.ext"
        ca_ext = c.dir + "/ca.ext"
        # The key identifiers are spelled out because LibreSSL does not add
        # them for a signed certificate the way OpenSSL 3 does, and Python
        # rejects a chain with no Authority Key Identifier from 3.13.
        with open(ext, "w") as fp:
            fp.write("subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:sni.test\n"
                     "subjectKeyIdentifier=hash\n"
                     "authorityKeyIdentifier=keyid,issuer\n")
        # A CA without these is not usable as one. They go in a file rather
        # than in -addext, which LibreSSL - the openssl on a stock macOS -
        # does not apply the same way.
        with open(ca_ext, "w") as fp:
            fp.write("basicConstraints=critical,CA:TRUE\n"
                     "keyUsage=critical,keyCertSign,cRLSign\n"
                     "subjectKeyIdentifier=hash\n")

        def ca_steps(key, csr_path, out, name):
            return [
                ["openssl", "genrsa", "-out", key, "2048"],
                ["openssl", "req", "-new", "-nodes", "-key", key,
                 "-subj", "/CN=" + name, "-out", csr_path],
                ["openssl", "x509", "-req", "-in", csr_path, "-signkey", key,
                 "-days", "3650", "-sha256", "-extfile", ca_ext, "-out", out],
            ]

        steps = (
            ca_steps(c.ca_key, c.dir + "/ca.csr", c.ca, "3proxy-test-ca") +
            ca_steps(c.other_key, c.dir + "/other.csr", c.other,
                     "3proxy-test-other-ca") +
            [
                ["openssl", "genrsa", "-out", c.server_key, "2048"],
                ["openssl", "req", "-new", "-key", c.server_key,
                 "-subj", "/CN=127.0.0.1", "-out", csr],
                ["openssl", "x509", "-req", "-in", csr, "-CA", c.ca,
                 "-CAkey", c.ca_key, "-CAcreateserial", "-out", c.server,
                 "-days", "3650", "-sha256", "-extfile", ext],
            ])
        for step in steps:
            done = subprocess.run(step, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=60)
            if done.returncode:
                self._certs = False
                return None

        # If the chain does not verify, the fault is in the generation, not
        # in whatever is about to present it.
        # -x509_strict is what a current client applies, so check that here
        # rather than discovering it in a handshake.
        check = subprocess.run(["openssl", "verify", "-x509_strict",
                                "-CAfile", c.ca, c.server],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=60)
        c.verified = check.returncode == 0
        c.verify_output = check.stdout.decode("utf-8", "replace").strip()

        self._certs = c
        return c

    def _context(self, ca=None, strict=True, verify_name=True):
        """A client context.

        strict=False drops the RFC 5280 checks Python turns on by default
        from 3.13, which reject a certificate with no Authority Key
        Identifier. verify_name=False keeps the chain check but ignores
        which host the certificate names, for the intercepted connections
        where that is the upstream identity rather than the one asked for.
        """
        if ca:
            context = ssl.create_default_context(cafile=ca)
            if not strict:
                context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
            if not verify_name:
                context.check_hostname = False
            return context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def tls_proxy_http(self, proxy, url, ca=None, strict=True, method="GET",
                       body=None, headers=None):
        """A request to a proxy that is itself wrapped in TLS (ssl_serv)."""
        host, port, path = self._split(url)
        phost, pport = self._hostport(proxy)
        try:
            raw = socket.create_connection((phost, pport), self.timeout)
            sock = self._context(ca, strict).wrap_socket(raw, server_hostname=phost)
        except (OSError, ssl.SSLError) as exc:
            return Response(error=f"{type(exc).__name__}: {exc}")

        conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        conn.sock = sock
        try:
            if body is not None and not isinstance(body, bytes):
                body = body.encode()
            authority = f"[{host}]" if ":" in host else host
            conn.request(method, f"http://{authority}:{port}{path}", body=body,
                         headers=headers or {})
            reply = conn.getresponse()
            return Response(reply.status, reply.read(), dict(reply.getheaders()))
        except (OSError, http.client.HTTPException) as exc:
            return Response(error=f"{type(exc).__name__}: {exc}")
        finally:
            conn.close()

    def https(self, url, proxy=None, ca=None, strict=True, verify_name=True,
              method="GET", headers=None, connect_to=None):
        """An https:// request, optionally tunnelled through a proxy.

        connect_to sends the handshake somewhere other than the name in the
        URL, which is how a name-directed proxy is reached: the name still
        goes out in the handshake and is what the certificate is checked
        against.
        """
        host, port, path = self._split(url, default_port=443)
        context = self._context(ca, strict, verify_name)
        try:
            if connect_to:
                raw = socket.create_connection(connect_to, self.timeout)
                conn = http.client.HTTPSConnection(host, port, context=context,
                                                   timeout=self.timeout)
                conn.sock = context.wrap_socket(raw, server_hostname=host)
                conn.request(method, path, headers=headers or {})
                reply = conn.getresponse()
                return Response(reply.status, reply.read(),
                                dict(reply.getheaders()))
            if proxy:
                phost, pport = self._hostport(proxy)
                conn = http.client.HTTPSConnection(phost, pport, context=context,
                                                   timeout=self.timeout)
                conn.set_tunnel(host, port)
            else:
                conn = http.client.HTTPSConnection(host, port, context=context,
                                                   timeout=self.timeout)
            conn.request(method, path, headers=headers or {})
            reply = conn.getresponse()
            return Response(reply.status, reply.read(), dict(reply.getheaders()))
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            return Response(error=f"{type(exc).__name__}: {exc}")
        finally:
            try:
                conn.close()
            except (OSError, NameError, UnboundLocalError):
                pass

    # ---- helpers -----------------------------------------------------

    @staticmethod
    def _basic(credentials):
        user, password = credentials
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return "Basic " + token

    @staticmethod
    def _hostport(value):
        if value.startswith("["):
            host, _, rest = value[1:].partition("]")
            return host, int(rest[1:])
        host, _, port = value.rpartition(":")
        return host or "127.0.0.1", int(port)

    @staticmethod
    def _split(url, default_port=80):
        """Split a URL, understanding an address in brackets.

        The brackets are dropped: they belong to the URL, not to the address
        a socket call or a certificate check wants.
        """
        for prefix in ("http://", "https://"):
            if url.startswith(prefix):
                url = url[len(prefix):]
                break
        authority, _, path = url.partition("/")
        if authority.startswith("["):
            host, _, rest = authority[1:].partition("]")
            port = rest[1:] if rest.startswith(":") else default_port
        elif ":" in authority:
            host, _, port = authority.rpartition(":")
        else:
            host, port = authority, default_port
        return host or "127.0.0.1", int(port), "/" + path

    # ---- assertions --------------------------------------------------

    def _record(self, passed, label, expected=None, actual=None):
        self.checks.append((passed, label, expected, actual))
        return passed

    def ok(self, label):
        return self._record(True, label)

    def fail(self, label, expected=None, actual=None):
        return self._record(False, label, expected, actual)

    def eq(self, expected, actual, label):
        return self._record(expected == actual, label, expected, actual)

    def ne(self, unexpected, actual, label):
        return self._record(unexpected != actual, label,
                            f"anything but {unexpected!r}", actual)

    @staticmethod
    def _as_text(value):
        """A reply that never arrived has no text, so report the reason."""
        if isinstance(value, Response):
            if value.error:
                return f"<no reply: {value.error}>"
            if not value.body and value.status is not None:
                return f"<{value.status}, empty body>"
            return value.text
        return value

    def contains(self, haystack, needle, label):
        haystack = self._as_text(haystack)
        return self._record(needle in haystack, label,
                            f"text containing {needle!r}", self._clip(haystack))

    def not_contains(self, haystack, needle, label):
        haystack = self._as_text(haystack)
        return self._record(needle not in haystack, label,
                            f"text without {needle!r}", self._clip(haystack))

    def in_range(self, value, low, high, label):
        good = isinstance(value, int) and low <= value <= high
        return self._record(good, label, f"between {low} and {high}", value)

    def not_in_range(self, value, low, high, label):
        good = isinstance(value, int) and not (low <= value <= high)
        return self._record(good, label, f"outside {low}-{high}", value)

    def skip(self, label):
        self._skipped += 1
        self.checks.append((None, label, None, None))

    @staticmethod
    def _clip(text, limit=200):
        text = str(text).replace("\r\n", " ").replace("\n", " ")
        return text[:limit] + ("..." if len(text) > limit else "")


def field(response, name):
    """Pull one 'key=value' line out of an echo reply."""
    text = response.text if isinstance(response, Response) else response
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key == name:
            return value
    return None


def int_field(response, name):
    value = field(response, name)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
