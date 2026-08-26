# Regression tests

    python3 tests/run.py                     # every case
    python3 tests/run.py httpsrv             # cases whose name matches
    python3 tests/run.py --bin build/bin/3proxy
    python3 tests/run.py -v                  # print every check
    python3 tests/run.py --keep              # keep the configurations and logs

Python 3.6 or later and a built 3proxy are the only requirements: the suite
is standard library throughout, so it runs wherever 3proxy builds. The TLS
case additionally wants `openssl` on PATH to generate its key material, and
skips itself when that is missing or the build has no TLS support. With no
`--bin` it looks in `bin/`, then `build/bin/`, then the per-configuration
directories a multi-configuration CMake generator uses.

The proxy under test is also the origin server the tests talk to: the `http`
command's `echo` operation reports back how a request arrived - method, path,
query, host, and the source port it came from - and `data` generates a body
of a requested size, framing, status and pace. So a case can state what a
proxy should do to a request and then read off what actually reached the
other side.

## Adding a case

A case is a module under `cases/` exporting `run(t)`. It writes the
configurations it needs, starts them, and says what it expects:

```python
def run(t):
    srv = t.free_port()
    t.start("my_case", f"""
        log
        auth iponly
        allow *
        http * /echo echo
        httpsrv -p{srv}
    """, ports=[srv])

    r = t.http(f"http://127.0.0.1:{srv}/echo")
    t.eq(200, r.status, "the server answers")
    t.contains(r, "method=GET", "the method is reported")
```

Servers are stopped for you when the case ends, whether or not it passed.

`t` offers `http()` (direct, through an HTTP proxy, or over a CONNECT
tunnel), `socks_http()` and `socks_connect()` for SOCKS4 and SOCKS5,
`socks_udp_associate()`, `raw()` for bytes a real client would never send,
and `run_config()` for configurations that are meant to be rejected.
Assertions are `eq`, `ne`, `contains`, `not_contains`, `in_range`,
`not_in_range`, plus `ok`, `fail` and `skip`. `harness.field()` and
`int_field()` pull a single line out of an `echo` reply.

For services with no TCP port to connect to, `t.udp_echo()` starts an echo
server, `t.udp_exchange()` sends a datagram, `t.wait_udp()` waits for a UDP
service to start answering, `t.socks_udp()` carries one through a SOCKS
association, and `t.dns_query()` asks a DNS server for an A record.

`t.certs()` generates a CA, a second unrelated CA, and a certificate for
127.0.0.1, once per run and inside the run's temporary directory, so no key
material lives in the tree. `t.https()`, `t.tls_proxy_http()` and
`t.socks_http()` reach a server through TLS, a TLS-wrapped proxy, or SOCKS.
Log records are written when a connection finishes rather than when the
reply arrives, so assert on them through `t.wait_output(server, text)`.

Note that access rules accumulate until `flush`, so a service section that
means to stand on its own should start with one - otherwise an earlier
`allow *` matches first and the rule under test is never reached.
