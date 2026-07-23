#!/bin/sh
# Regression: users NAME:CL:password must accept short cleartext passwords.
# Long passwords (>= pwl_table.recsize) use the BLAKE2 path and already worked.
#
# Cases:
#   1) short correct password  -> HTTP success through proxy (not 407 / error 6)
#   2) short wrong password    -> 407 and error 00006
#   3) long (>=64) correct password -> HTTP success
#
# Usage:
#   ./tests/cl-cleartext-auth/run.sh [path-to-3proxy]

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PROXYBIN=${1:-"$ROOT_DIR/bin/3proxy"}
WORKDIR=${TMPDIR:-/tmp}/3proxy-cl-cleartext-auth-$$
LONGPW=$(python3 -c 'print("L"*64)')

if [ ! -x "$PROXYBIN" ]; then
	echo "FAIL: 3proxy binary not found or not executable: $PROXYBIN" >&2
	exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
	echo "FAIL: curl is required" >&2
	exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "FAIL: python3 is required" >&2
	exit 1
fi

cleanup() {
	for f in short.pid wrong.pid long.pid dest.pid; do
		if [ -f "$WORKDIR/$f" ]; then
			kill "$(cat "$WORKDIR/$f")" 2>/dev/null || true
		fi
	done
	pkill -f "$WORKDIR" 2>/dev/null || true
	rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Local plain HTTP target (no external network dependency)
python3 - <<'PY' >dest.out 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"OK-AUTH\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
print("ready", flush=True)
HTTPServer(("127.0.0.1", 19460), H).serve_forever()
PY
echo $! > dest.pid

i=0
while [ "$i" -lt 50 ]; do
	grep -q ready dest.out 2>/dev/null && break
	i=$((i + 1))
	sleep 0.1
done

cat > short.cfg <<EOF
log $WORKDIR/short.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %T"
users admin:CL:testpassword
auth strong
allow admin
proxy -a -n -p18650
EOF

cat > wrong.cfg <<EOF
log $WORKDIR/wrong.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %T"
users admin:CL:testpassword
auth strong
allow admin
proxy -a -n -p18651
EOF

cat > long.cfg <<EOF
log $WORKDIR/long.log
logformat "%Y%m%d%H%M%S.%. %p %E %U %T"
users admin:CL:${LONGPW}
auth strong
allow admin
proxy -a -n -p18652
EOF

"$PROXYBIN" short.cfg > short.out 2>&1 &
echo $! > short.pid
"$PROXYBIN" wrong.cfg > wrong.out 2>&1 &
echo $! > wrong.pid
"$PROXYBIN" long.cfg > long.out 2>&1 &
echo $! > long.pid
sleep 0.4

SHORT_CODE=$(curl -s --max-time 10 -o /tmp/cl-short.body -w '%{http_code}' \
	-x http://admin:testpassword@127.0.0.1:18650 \
	http://127.0.0.1:19460/ || echo fail)
WRONG_CODE=$(curl -s --max-time 10 -o /tmp/cl-wrong.body -w '%{http_code}' \
	-x http://admin:wrongpassword@127.0.0.1:18651 \
	http://127.0.0.1:19460/ || echo fail)
LONG_CODE=$(curl -s --max-time 10 -o /tmp/cl-long.body -w '%{http_code}' \
	-x "http://admin:${LONGPW}@127.0.0.1:18652" \
	http://127.0.0.1:19460/ || echo fail)

for f in short.pid wrong.pid long.pid; do
	if [ -f "$f" ]; then
		kill "$(cat "$f")" 2>/dev/null || true
		wait "$(cat "$f")" 2>/dev/null || true
		rm -f "$f"
	fi
done
sleep 0.1

echo "=== short correct: http=$SHORT_CODE body=$(cat /tmp/cl-short.body 2>/dev/null || true) ==="
echo "=== short wrong:   http=$WRONG_CODE ==="
echo "=== long correct:  http=$LONG_CODE body=$(cat /tmp/cl-long.body 2>/dev/null || true) ==="
echo "=== short.log ==="; cat short.log 2>/dev/null || true
echo "=== wrong.log ==="; cat wrong.log 2>/dev/null || true
echo "=== long.log ==="; cat long.log 2>/dev/null || true

fail=0

if [ "$SHORT_CODE" != "200" ] || [ "$(cat /tmp/cl-short.body 2>/dev/null || true)" != "OK-AUTH" ]; then
	echo "FAIL: short correct CL password did not authenticate (http=$SHORT_CODE)" >&2
	fail=1
fi
if grep -E ' 00006 +admin ' short.log >/dev/null 2>&1; then
	echo "FAIL: short correct password logged error 00006" >&2
	fail=1
fi

if [ "$WRONG_CODE" != "407" ]; then
	echo "FAIL: short wrong password expected HTTP 407, got $WRONG_CODE" >&2
	fail=1
fi
if ! grep -E ' 00006 +admin ' wrong.log >/dev/null 2>&1; then
	echo "FAIL: short wrong password did not log error 00006" >&2
	fail=1
fi

if [ "$LONG_CODE" != "200" ] || [ "$(cat /tmp/cl-long.body 2>/dev/null || true)" != "OK-AUTH" ]; then
	echo "FAIL: long correct CL password did not authenticate (http=$LONG_CODE)" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi

echo "PASS: CL cleartext auth accepts short and long passwords; rejects wrong short password"
exit 0
