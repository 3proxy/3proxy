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
import socket
import struct
import subprocess
import sys
import textwrap
import time


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
        self._skipped = 0

    # ---- servers -----------------------------------------------------

    def free_port(self):
        """A port nothing is listening on. Closed again before it is used,
        which is racy in principle and reliable enough in practice."""
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
        finally:
            s.close()

    def write_config(self, name, config):
        path = os.path.join(self.tmpdir, name + ".cfg")
        text = textwrap.dedent(config).strip() + "\n"
        # newline="" keeps the line endings as written, rather than letting
        # Windows turn them into CRLF behind the parser's back
        with open(path, "w", newline="") as fp:
            fp.write(text)
        return path

    def start(self, name, config, ports=()):
        """Write a configuration, run it, and wait for its ports to open."""
        path = self.write_config(name, config)
        logfile = os.path.join(self.tmpdir, name + ".out")
        with open(logfile, "wb") as out:
            proc = subprocess.Popen([self.binary, path], stdout=out,
                                    stderr=subprocess.STDOUT)
        server = Server(name, path, proc, logfile)
        self.servers.append(server)

        for port in ports:
            if not self.wait_port(port):
                raise Failure(
                    f"{name} never listened on port {port}\n"
                    f"--- configuration ---\n{open(path).read()}"
                    f"--- output ---\n{server.output()}")
        return server

    def run_config(self, name, config):
        """Run a configuration expected to be rejected; return its output."""
        path = self.write_config(name, config)
        done = subprocess.run([self.binary, path], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=15)
        return done.stdout.decode("utf-8", "replace")

    def wait_port(self, port, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), 0.25):
                    return True
            except OSError:
                time.sleep(0.02)
        return False

    def stop_all(self):
        for server in self.servers:
            server.stop()
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
                target = f"http://{host}:{port}{path}"
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

    # ---- helpers -----------------------------------------------------

    @staticmethod
    def _basic(credentials):
        user, password = credentials
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return "Basic " + token

    @staticmethod
    def _hostport(value):
        host, _, port = value.rpartition(":")
        return host or "127.0.0.1", int(port)

    @staticmethod
    def _split(url):
        prefix = "http://"
        if url.startswith(prefix):
            url = url[len(prefix):]
        authority, _, path = url.partition("/")
        host, _, port = authority.rpartition(":")
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

    def contains(self, haystack, needle, label):
        if isinstance(haystack, Response):
            haystack = haystack.text
        return self._record(needle in haystack, label,
                            f"text containing {needle!r}", self._clip(haystack))

    def not_contains(self, haystack, needle, label):
        if isinstance(haystack, Response):
            haystack = haystack.text
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
