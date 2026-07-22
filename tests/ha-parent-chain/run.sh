#!/bin/sh
# Regression: HTTP -> ha + SOCKS5 parent -> socks -H must negotiate SOCKS
# after the PROXY v1 header and preserve the original client address.
#
# Topology:
#   curl -> proxy1 HTTP :18628
#     parent ha 0.0.0.0 0
#     parent socks5 127.0.0.1:18183
#   -> proxy2 SOCKS -H :18183 -> HTTPS dest :19443
#
# Also runs a wiretap on :18181 to assert byte order:
#   PROXY -> SOCKS5 greeting/auth/CONNECT -> payload
# and a no-HA baseline via SOCKS without -H on :18184.
#
# Usage:
#   ./tests/ha-parent-chain/run.sh [path-to-3proxy]
# Default binary: ../../bin/3proxy relative to this script.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PROXYBIN=${1:-"$ROOT_DIR/bin/3proxy"}
WORKDIR=${TMPDIR:-/tmp}/3proxy-ha-parent-chain-$$
PROXY1_IP=127.0.0.1
# Prefer a distinct loopback client address so proxy2's restored IP
# cannot be confused with proxy1's TCP peer. Fall back to 127.0.0.1.
CLIENT_IP=127.0.0.1
CURL_IFACE_ARGS=

if [ ! -x "$PROXYBIN" ]; then
	echo "FAIL: 3proxy binary not found or not executable: $PROXYBIN" >&2
	echo "Build first, e.g. make -f Makefile.unix or Makefile.FreeBSD" >&2
	exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "FAIL: python3 is required" >&2
	exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
	echo "FAIL: curl is required" >&2
	exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
	echo "FAIL: openssl is required" >&2
	exit 1
fi

if python3 - <<'PY'
import socket
s = socket.socket()
try:
    s.bind(("127.0.0.2", 0))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
raise SystemExit(0)
PY
then
	CLIENT_IP=127.0.0.2
	CURL_IFACE_ARGS="--interface 127.0.0.2"
fi

cleanup() {
	for f in proxy1.pid proxy1b.pid proxy1-noha.pid proxy2.pid proxy2-noha.pid wiretap.pid dest.pid; do
		if [ -f "$WORKDIR/$f" ]; then
			kill "$(cat "$WORKDIR/$f")" 2>/dev/null || true
		fi
	done
	# Best-effort cleanup if pidfiles were not written
	pkill -f "$WORKDIR" 2>/dev/null || true
	rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$WORKDIR"
cd "$WORKDIR"

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes \
	-subj "/CN=127.0.0.1" >/dev/null 2>&1

cat > dest_server.py <<'PY'
#!/usr/bin/env python3
import argparse, ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"OK-DEST\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="127.0.0.1")
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--cert", required=True)
ap.add_argument("--key", required=True)
args = ap.parse_args()
httpd = HTTPServer((args.host, args.port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(args.cert, args.key)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("ready", flush=True)
httpd.serve_forever()
PY

cat > wiretap_socks.py <<'PY'
#!/usr/bin/env python3
import argparse, socket, struct, threading, sys

def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf

def handle(conn, addr, logf):
    order = []
    client_ip = addr[0]
    try:
        line = b""
        while not line.endswith(b"\n"):
            b = conn.recv(1)
            if not b:
                break
            line += b
        if not line.startswith(b"PROXY "):
            logf.write("ORDER=NO_PROXY FIRST=%r\n" % (line[:32],))
            logf.flush()
            return
        order.append("PROXY")
        parts = line.decode("latin1", "replace").strip().split()
        if len(parts) >= 6:
            client_ip = parts[2]
        ver = conn.recv(1)
        if ver != b"\x05":
            more = ver + conn.recv(16)
            order.append("PAYLOAD")
            logf.write("ORDER=%s FIRST_PAYLOAD=%r client_ip=%s FAIL_NO_SOCKS\n" %
                       ("->".join(order), more, client_ip))
            logf.flush()
            return
        order.append("SOCKS5")
        nmethods = conn.recv(1)[0]
        methods = list(conn.recv(nmethods))
        if 2 in methods:
            conn.sendall(b"\x05\x02")
            auth = recv_exact(conn, 2)
            user = recv_exact(conn, auth[1])
            plen = recv_exact(conn, 1)[0]
            _ = recv_exact(conn, plen)
            order.append("SOCKS5_AUTH")
            conn.sendall(b"\x01\x00")
            logf.write("SOCKS5_AUTH user=%r client_ip=%s\n" % (user, client_ip))
        elif 0 in methods:
            conn.sendall(b"\x05\x00")
        else:
            conn.sendall(b"\x05\xff")
            return
        hdr = recv_exact(conn, 4)
        atyp = hdr[3]
        if atyp == 1:
            host = socket.inet_ntoa(recv_exact(conn, 4))
        elif atyp == 3:
            ln = recv_exact(conn, 1)[0]
            host = recv_exact(conn, ln).decode()
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
        else:
            return
        port = struct.unpack("!H", recv_exact(conn, 2))[0]
        order.append("SOCKS5_CONNECT")
        rem = socket.create_connection((host, port), timeout=10)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        order.append("PAYLOAD")
        logf.write("ORDER=%s SUCCESS client_ip=%s target=%s:%s\n" %
                   ("->".join(order), client_ip, host, port))
        logf.flush()

        def pump(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except Exception:
                pass
            try:
                b.shutdown(socket.SHUT_WR)
            except Exception:
                pass

        t1 = threading.Thread(target=pump, args=(conn, rem), daemon=True)
        t2 = threading.Thread(target=pump, args=(rem, conn), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
    except Exception as e:
        logf.write("ERROR=%r ORDER=%s\n" % (e, "->".join(order)))
        logf.flush()
    finally:
        try:
            conn.close()
        except Exception:
            pass

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--log", required=True)
args = ap.parse_args()
logf = open(args.log, "a", buffering=1)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", args.port))
srv.listen(50)
print("ready", flush=True)
while True:
    c, a = srv.accept()
    threading.Thread(target=handle, args=(c, a, logf), daemon=True).start()
PY

python3 dest_server.py --port 19443 --cert cert.pem --key key.pem > dest.out 2>&1 &
echo $! > dest.pid
python3 wiretap_socks.py --port 18181 --log wire.log > wiretap.out 2>&1 &
echo $! > wiretap.pid

# Wait until helpers are listening
i=0
while [ "$i" -lt 50 ]; do
	if grep -q ready dest.out 2>/dev/null && grep -q ready wiretap.out 2>/dev/null; then
		break
	fi
	i=$((i + 1))
	sleep 0.1
done

# Real SOCKS -H parent. Use iponly here so the test is not coupled to
# unrelated cleartext password-table comparison behavior; username/password
# SOCKS auth is exercised against the wiretap parent below.
cat > proxy2.cfg <<EOF
nserver 8.8.8.8
log $WORKDIR/proxy2.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %T"
auth iponly
allow *
socks -H -p18183
EOF

# Baseline SOCKS parent without -H (must not share the -H listener)
cat > proxy2-noha.cfg <<EOF
nserver 8.8.8.8
log $WORKDIR/proxy2-noha.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %T"
auth iponly
allow *
socks -p18184
EOF

cat > proxy1.cfg <<EOF
nserver 8.8.8.8
log $WORKDIR/proxy1.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %T"
auth iponly
allow *
parent 1000 ha 0.0.0.0 0
parent 1000 socks5 127.0.0.1 18183
proxy -p18628
EOF

# Wire-order probe: same HA chain, parent is the Python wiretap with user/pass
cat > proxy1b.cfg <<EOF
nserver 8.8.8.8
log $WORKDIR/proxy1b.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %T"
auth iponly
allow *
parent 1000 ha 0.0.0.0 0
parent 1000 socks5 127.0.0.1 18181 upstream upstreampassword
proxy -p18630
EOF

cat > proxy1-noha.cfg <<EOF
nserver 8.8.8.8
log $WORKDIR/proxy1-noha.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %T"
auth iponly
allow *
parent 1000 socks5 127.0.0.1 18184
proxy -p18629
EOF

"$PROXYBIN" proxy2.cfg > proxy2.out 2>&1 &
echo $! > proxy2.pid
"$PROXYBIN" proxy2-noha.cfg > proxy2-noha.out 2>&1 &
echo $! > proxy2-noha.pid
"$PROXYBIN" proxy1.cfg > proxy1.out 2>&1 &
echo $! > proxy1.pid
"$PROXYBIN" proxy1b.cfg > proxy1b.out 2>&1 &
echo $! > proxy1b.pid
"$PROXYBIN" proxy1-noha.cfg > proxy1-noha.out 2>&1 &
echo $! > proxy1-noha.pid
sleep 0.4

# shellcheck disable=SC2086
NOHA_BODY=$(curl -sk --max-time 15 $CURL_IFACE_ARGS \
	--proxy "http://${PROXY1_IP}:18629" \
	"https://127.0.0.1:19443/" || true)

# shellcheck disable=SC2086
BODY=$(curl -sk --max-time 15 $CURL_IFACE_ARGS \
	--proxy "http://${PROXY1_IP}:18628" \
	"https://127.0.0.1:19443/" || true)

# shellcheck disable=SC2086
WIRE_BODY=$(curl -sk --max-time 15 $CURL_IFACE_ARGS \
	--proxy "http://${PROXY1_IP}:18630" \
	"https://127.0.0.1:19443/" || true)

# Stop proxies so request logs are flushed to disk
for f in proxy1.pid proxy1b.pid proxy1-noha.pid proxy2.pid proxy2-noha.pid; do
	if [ -f "$f" ]; then
		kill "$(cat "$f")" 2>/dev/null || true
		wait "$(cat "$f")" 2>/dev/null || true
		rm -f "$f"
	fi
done
sleep 0.1

echo "=== proxy1.log ==="
cat proxy1.log 2>/dev/null || true
echo "=== proxy1-noha.log ==="
cat proxy1-noha.log 2>/dev/null || true
echo "=== proxy2.log ==="
cat proxy2.log 2>/dev/null || true
echo "=== proxy2-noha.log ==="
cat proxy2-noha.log 2>/dev/null || true
echo "=== wire.log ==="
cat wire.log 2>/dev/null || true
echo "=== curl body (no-HA) ==="
printf '%s\n' "$NOHA_BODY"
echo "=== curl body (HA -> real proxy2) ==="
printf '%s\n' "$BODY"
echo "=== curl body (HA -> wiretap) ==="
printf '%s\n' "$WIRE_BODY"

fail=0

if [ "$NOHA_BODY" != "OK-DEST" ]; then
	echo "FAIL: baseline HTTPS through socks5 parent (no HA) did not return OK-DEST (got: $NOHA_BODY)" >&2
	fail=1
fi

if [ "$BODY" != "OK-DEST" ]; then
	echo "FAIL: HTTPS through ha->socks5->socks -H did not return OK-DEST (got: $BODY)" >&2
	fail=1
fi

if [ "$WIRE_BODY" != "OK-DEST" ]; then
	echo "FAIL: HTTPS through ha->wiretap socks did not return OK-DEST (got: $WIRE_BODY)" >&2
	fail=1
fi

if ! grep -q "ORDER=PROXY->SOCKS5->SOCKS5_AUTH->SOCKS5_CONNECT->PAYLOAD SUCCESS" wire.log; then
	echo "FAIL: wire order was not PROXY -> SOCKS5 -> AUTH -> CONNECT -> PAYLOAD" >&2
	fail=1
fi

if ! grep -q "client_ip=$CLIENT_IP" wire.log; then
	echo "FAIL: PROXY header did not carry original client IP $CLIENT_IP" >&2
	fail=1
fi

# proxy2 must complete SOCKS CONNECT (not UNKNOWN) and reach the HTTPS destination
if ! grep -E " 00000 +- +${CLIENT_IP}:[0-9]+ +127\\.0\\.0\\.1:19443 " proxy2.log >/dev/null; then
	echo "FAIL: proxy2 did not complete SOCKS CONNECT from restored client $CLIENT_IP to :19443" >&2
	fail=1
fi

if grep -E " 0040[0-9] +- +${CLIENT_IP}:.*UNKNOWN" proxy2.log >/dev/null; then
	echo "FAIL: proxy2 still saw UNKNOWN after PROXY (parent negotiation skipped)" >&2
	fail=1
fi

# Wiretap must have completed username/password SOCKS5 authentication
if ! grep -q "SOCKS5_AUTH user=b'upstream'" wire.log; then
	echo "FAIL: SOCKS5 username/password authentication was not completed" >&2
	fail=1
fi

# PROXY restoration: proxy2's logged client port must match proxy1's client port.
# The TCP peer port on proxy2 would be proxy1's outbound ephemeral port instead.
CLIENT_PORT=$(awk '/CONNECT 127\.0\.0\.1:19443/ && / 00000 / {
  for (i = 1; i <= NF; i++) if ($i ~ /^'"$CLIENT_IP"':[0-9]+$/) {
    split($i, a, ":"); print a[2]; exit
  }
}' proxy1.log)
PROXY2_PORT=$(awk '/CONNECT 127\.0\.0\.1:19443/ && / 00000 / {
  for (i = 1; i <= NF; i++) if ($i ~ /^'"$CLIENT_IP"':[0-9]+$/) {
    split($i, a, ":"); print a[2]; exit
  }
}' proxy2.log)
if [ -z "$CLIENT_PORT" ] || [ -z "$PROXY2_PORT" ] || [ "$CLIENT_PORT" != "$PROXY2_PORT" ]; then
	echo "FAIL: proxy2 client port ($PROXY2_PORT) does not match original client port on proxy1 ($CLIENT_PORT)" >&2
	fail=1
fi

# When a distinct client IP is available, restored address must not be proxy1's peer alone
if [ "$CLIENT_IP" != "127.0.0.1" ]; then
	if grep -E " 00000 +- +127\\.0\\.0\\.1:[0-9]+ +127\\.0\\.0\\.1:19443 " proxy2.log >/dev/null && \
	   ! grep -E " 00000 +- +${CLIENT_IP}:" proxy2.log >/dev/null; then
		echo "FAIL: proxy2 logged proxy1 address instead of original client $CLIENT_IP" >&2
		fail=1
	fi
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi

echo "PASS: ha parent chaining sends PROXY then completes SOCKS5 negotiation (client_ip=$CLIENT_IP)"
exit 0
