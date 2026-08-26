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

## What is not covered yet

41 of the 112 configuration commands appear in a test. What follows is
roughly the order worth working through: how much of the product a gap
covers, and how much of a fixture it needs.

### Traffic limits and accounting

`bandlimin` `bandlimout` `nobandlimin` `nobandlimout` `connlim` `noconnlim`
`countin` `countout` `countall` and the `no*` forms, `maxconn`.

Cheap and worth doing first: `data?size=` and a stopwatch measure a
bandwidth limit, and the admin counters page already shows what a counter
holds. `countin` appears in a configuration today but nothing checks that it
counts. `connlim` and `maxconn` need concurrent connections.

### The mail proxies

`pop3p` `smtpp` `imapp`, and `ftppr`.

The largest gap by volume: four protocol implementations with no coverage at
all. Each needs a scripted server that speaks enough of the protocol,
including the multi-line and challenge forms - a POP3 or IMAP server that
only answers `+OK` will not exercise the interesting paths. Worth the
fixture: this is also where known parent-chaining trouble lives, since
`clientnegotiate()` has no case for R_POP3, R_SMTP or R_FTP.

### Access rules and chaining

`redirect` `weight` `parentretries` `force` `noforce` `include` `nolog`.

Also the parts of an ACE never exercised: source addresses and masks, port
ranges, time and weekday fields, and operation lists beyond the single
`HTTP_CONNECT` used today. `weight` needs several parents and enough
requests to see the split.

### IPv6

Not one test binds or connects over `::1`, though the tree is full of
`#ifndef NOIPV6` and `extip` has an IPv6 CIDR-randomisation path of its own.
Most existing cases would work over IPv6 with the address parameterised.

### Authentication

`authcache` `radius` `authnserver`, and the auth methods beyond `iponly` and
`strong`: `none`, `nbname`, `dnsname`. `radius` needs a server to answer.

### Plugins

`plugin`. Nothing loads one, though `StringsPlugin`, `TrafficPlugin`,
`TransparentPlugin` and `FilePlugin` are built in CI. StringsPlugin matters
most: the admin string table is kept byte-compatible for it deliberately,
and nothing proves that.

### Logging

`logformat` `rotate` `archiver` `logdump`.

Tests read the log as free text, so a reordered field would pass every check
here and break every downstream parser. `rotate` and `archiver` need control
of the clock or a long run.

### TLS options

About 25 `ssl_client_*` and `ssl_server_*` commands: SNI, ALPN, protocol
versions, cipher lists, `ssl_client_cert` and `ssl_client_key` for mTLS,
`ssl_*_verify` and `ssl_*_no_verify`. The certificate fixture exists, so
these are mostly a matter of writing them.

### Process and lifecycle

`daemon` `chroot` `setuid` `setgid` `pidfile` `stacksize` `backlog` `monitor`
`system` `include` `timeouts` `maxseg` `external` `delimchar`
`filtermaxsize`. Several need root or change the process in ways a test
runner has to survive; `include`, `timeouts` and `pidfile` do not, and are
easy.

Reload is worth a case of its own: the admin page returns "Reload scheduled"
and nothing checks that the configuration is re-read, that a changed rule
takes effect, or that services come back.

### DNS

`fakeresolve` `nscache6` `dialer`.

### Known limitations, deliberately not asserted

A request rewrite that changes the method or the authority is ignored, and
the manual says so; a test that pinned the current behaviour would have to
change when that does. Certificates 3proxy generates for MITM carry no
Authority Key Identifier, so `tests/cases/ssl.py` verifies the chain without
strict checking - if that is fixed, the test should tighten rather than stay
as it is.
