# Benchmark results

3proxy against nginx, haproxy, squid, tinyproxy, dante and stunnel on two
machines, as an HTTP proxy, through CONNECT and SOCKSv5 tunnels, as a TCP
relay, ending or beginning TLS, and with 20000 connections open at once; and
devel against 1.0.1. The current figures are from 13 October 2026, for devel
with 16 KB buffers, the automatic splice() mode by default and the thread
pool; the sessions before them are at the end. How the benchmark works is in
[README.md](README.md); the measurements are in [data/](data/), and
`bench/report.py` turns them into the tables below.

## In short

Ranges are over the two machines, ARM and Intel; the tables give each.

* **Bulk data:** devel splices 29-42 Gbit/s through every service (HTTP,
  CONNECT, SOCKS, `tcppm`), the fastest everywhere: 2-2.9 times squid, 2-4.2
  times dante, and 2.6-5.6 times nginx and haproxy copying 1 MB HTTP answers.
  haproxy `splice-auto` is level with it as a relay on Intel and behind on
  ARM. Copying with its 16 KB buffers (`-s0`) devel does 9.4-13.4 Gbit/s,
  level with nginx and haproxy; the automatic mode, the default, is what
  makes 16 KB enough.
* **Small requests:** nginx and haproxy answer 1.5-2.2 times more 1 KB
  requests as relays and 1.9-2.8 times as HTTP proxies; squid 1.2-2 times
  more through CONNECT; through SOCKS dante leads on ARM, devel on Intel.
  3proxy runs a thread per connection; splice() cannot change that.
* **A new connection per request:** nginx and haproxy do 1.2-1.5 times more
  as relays, 2.2-2.9 times as HTTP proxies, where they keep their connections
  to the origin and a forward proxy cannot.
* **2000 clients, 50 KB answers:** on Intel devel leads as an HTTP proxy,
  through CONNECT and through SOCKS; on ARM nginx, squid and dante are 13-47%
  ahead of it. As a relay haproxy `splice-auto` leads on both.
* **HTTPS:** with TLS ended or begun in the proxy devel moves bulk data as
  fast as nginx, ahead of haproxy and stunnel, with the least memory; envoy
  (BoringSSL) leads, by 30-50% on ARM. devel answers half to two thirds of
  nginx's 1 KB requests and does 60-95% of its handshakes. See
  [HTTPS](#https-tls-in-the-proxy).
* **20000 connections:** devel keeps up with nginx and haproxy within 5-25% in
  throughput and CPU, but needs 65-130 KB per connection against their 8-30
  KB. See [the mix scenarios](#many-connections-the-mix-scenarios).
* **Memory with few connections:** 3proxy needs the least, 5-20 MB against
  30-50 MB for nginx and haproxy.

## Setup

| | M4 | Skylake |
|---|---|---|
| host | Apple M4 Pro laptop, UTM (Apple Virtualization) | OpenStack virtual machine, KVM |
| virtual machine | 8 CPUs, 8 GB | 8 CPUs (Intel Xeon, Skylake, 2.0 GHz), 8 GB |
| system | Ubuntu 24.04, Linux 6.8, aarch64 | AlmaLinux 10, Linux 6.12, x86_64 |
| nginx | 1.24.0 | 1.26.3 |
| haproxy | 2.8.16 | 3.0.5 |
| squid | 6.14 | 6.10 |
| tinyproxy | 1.11.1 | 1.11.2 |
| dante | 1.4.3 | 1.4.4 |
| wrk, iperf3 | 4.1.0, 3.16 | 4.2.0, 3.17.1 |
| proxychains-ng | 4.17 | 4.17 |
| stunnel, OpenSSL | 5.72, 3.0.13 | 5.72, 3.5.8 |

### How the client, the proxy and the origin were kept apart

* **Network:** each runs in a network namespace of its own, linked by veth
  pairs (client 10.0.1.2 - 10.0.1.1 proxy 10.0.2.1 - 10.0.2.2 origin), so they
  share no loopback and every proxy is crossed by the same path. MTU 1500.
* **CPU:** each runs in a cgroup pinned to CPUs of its own: the client
  (wrk, iperf3) on CPUs 0-3, the proxy on CPU 4, the origin (nginx serving
  files from tmpfs, iperf3 -s) on CPUs 5-7. RPS steers what each veth receives
  to the receiving side's CPUs, so the kernel's network work for a role is
  done on its own CPUs too. The proxy has the fewest CPUs on purpose: it has to
  be what runs out first.
* **Every proxy gets the same CPU:** one nginx worker, one haproxy thread, and
  3proxy's thread per connection, squid's, tinyproxy's and dante's processes
  all confined to the same CPU.
* **CPU time** is the busy time of the role's CPUs from `/proc/stat`, its own
  processes plus the interrupts and softirqs handled there (a quarter of a
  proxy's time here), so a proxy is also charged for the kernel's work on its
  connections - which is where splice() moves the copying.
* **Which side set the pace** is recorded for every run: the role whose CPUs,
  or one thread of it, were busy at least 90% of the time.
* **Repetitions:** three runs of 10 seconds per proxy and scenario, the order
  of the proxies rotated between repetitions; the tables give medians.
* **Tunnels:** wrk and iperf3 run under proxychains-ng, which opens a CONNECT
  or SOCKSv5 tunnel for each connection they make, blocking in `connect()`
  until the proxy has answered. This costs the client CPU time per connection,
  so wrk gets more threads there (16 against 4).

### Proxies

| column | configuration |
|---|---|
| devel | devel as of 13 October: 16 KB buffers, the thread pool, splice() in its automatic mode, the default: each direction switched to splice() once two reads in a row fill 16 KB and back to copying after three small ones; an HTTP body of known length is spliced when 16 KB or more of it remain |
| devel -s0 | devel, no splice (TCP_NODELAY is on by default) |
| 1.0.1 | 1.0.1 as it starts by default: built without splice, 64 KB buffers, Nagle's algorithm on (no TCP_NODELAY, which devel sets by default) |
| nginx | `proxy_pass` to an upstream with `keepalive 1024`, `stream` for the TCP relay, `reuseport` |
| haproxy | `mode http` with `http-reuse always`, `mode tcp` for the TCP relay |
| haproxy splice-auto | `option splice-auto`: splices a direction once reads fill the buffer three times in a row |
| squid | no cache, no logs, `via off` |
| tinyproxy | `DisableViaHeader Yes`, critical messages only |
| dante | no authentication, one `sockd` process tree (`-N 1`) |
| stunnel | TLS scenarios only |

nginx has no splice() support. Neither nginx nor haproxy has CONNECT or SOCKS,
so they are measured as HTTP proxies and TCP relays only; squid and tinyproxy
only as HTTP proxies and through CONNECT, dante only through SOCKS. 3proxy
versions are built with the Makefile they shipped with (`-O3 -flto`). Logging
is off everywhere.

### Scenarios

| scenario | load |
|---|---|
| stream1, stream1-down | one iperf3 stream, upload and download |
| stream16 | 16 iperf3 streams, upload |
| ka-1k, http-ka-1k | 1 KB answers over 64 kept-alive connections |
| http-ka-1m | 1 MB answers over 16 kept-alive connections |
| ka-50k-2000, http-ka-50k-2000 | 2000 kept-alive connections, 50 KB answers |
| http-ka-2k-50k-2000 | the same, each request a POST with a 2 KB body |
| close-1k, http-close-1k | 64 connections, a new one for every request |

`http-*` go through the HTTP proxy (absolute URIs). The CONNECT, SOCKS and
relay tables run the same loads through a CONNECT tunnel, a SOCKSv5 tunnel or
a TCP relay to the origin (3proxy `tcppm`, nginx `stream`, haproxy
`mode tcp`): the HTTP requests are then plain HTTP inside the tunnel.

## How to read the tables

* A table for each machine, ARM (the M4) and Intel (the Skylake host): the
  two are different machines in different conditions, and an average of them
  would mean nothing. Each cell is the median of three runs; TCP streams and
  1 MB answers in Gbit/s, the other HTTP scenarios in thousands of requests
  per second. ‡: most runs were limited by the client or the origin rather
  than by the proxy, which can then do at least that much.
* Each table has the proxies copying through user space first, then, after
  `‖`, those using splice(): devel, whose automatic mode is its default, and
  haproxy with `splice-auto`.
* HTTP proxy and TCP relay: **bold** is the best median of its group
  (copying, or splice()) in the row, and any other of the group whose runs
  cannot be told apart from it: its fastest run reaches the best one's
  slowest.
  \* marks the best of the row over both groups, by the same rule.
* CONNECT and SOCKS, where devel is the only proxy using splice(): only the
  best of the row is marked, bold and with \*.
* CPU time per gigabyte or request and peak memory are in the data. CPU adds
  little: every proxy ran at its CPU limit, so its CPU per unit of work is the
  inverse of its throughput.

## HTTP proxy

Measured on 13 October 2026, as were the CONNECT, SOCKS and relay tables
([data/](data/) `*-16k-*.csv`).

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k, k req/s | 14.5 | 1.5 | **40.3** * | 33.1 | 3.9 | 19.4 | ‖ | 14.5 | **40.1** * |
| ka-1m, Gbit/s | **12.4** | 8.1 | 5.4 ‡ | 11.8 | 1.0 | 3.0 ‡ | ‖ | **30.2 ‡** * | 5.4 ‡ |
| ka-50k-2000, k req/s | 8.6 | 8.1 | 8.6 | **10.9** * | 1.6 | 4.1 | ‖ | **9.6** | 8.5 |
| ka-2k-50k-2000, k req/s | 7.8 | 6.7 | 7.9 | **9.6** * | 1.5 | 3.1 | ‖ | **8.7** | 8.1 |
| close-1k, k req/s | 5.4 | 4.1 | **15.6** * | 12.2 | 3.9 | 6.8 | ‖ | 5.4 | **15.7** * |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k, k req/s | 18.9 | 1.6 | **36.2** * | **35.6** * | 3.9 | 9.3 | ‖ | 18.6 | **35.8** * |
| ka-1m, Gbit/s | **9.4** | 7.8 | 7.9 | 5.9 | 1.1 | 2.2 | ‖ | **26.3 ‡** * | 24.8 ‡ |
| ka-50k-2000, k req/s | 8.6 | **9.6** | 7.6 | 9.1 | 1.6 | 2.1 | ‖ | **10.4** * | 7.4 |
| ka-2k-50k-2000, k req/s | 7.8 | **8.0** | 7.3 | **8.1** | 1.5 | 1.8 | ‖ | **9.5** * | 6.9 |
| close-1k, k req/s | 6.0 | 3.9 | **15.8** * | 13.3 | 3.7 | 4.0 | ‖ | 6.1 | **15.5** * |

* 1 MB answers: devel splices them at 30 Gbit/s on ARM and 26 on Intel, 2.6
  to 5.6 times nginx and haproxy copying. haproxy `splice-auto` keeps up on
  Intel (25) but hardly splices on ARM (5.4). Copying (`-s0`), devel is ahead
  of the other copying proxies too (12.4 and 9.4 Gbit/s).
* 2000 clients with 50 KB answers: nginx leads on ARM (10.9k requests a
  second against devel's 9.6k), devel on Intel (10.4k against 9.1k); haproxy
  is behind both on both. With a 2 KB POST each, the same order.
* nginx and haproxy answer 2.3-2.8 times more 1 KB requests over kept-alive
  connections on ARM, 1.9 times on Intel, and 2.2-2.9 times more with a new
  connection for each. That last gap is not the thread pool's: nginx
  (`keepalive 1024`) and haproxy (`http-reuse always`) keep their connections
  to the origin and only accept and close the client's, while a forward proxy
  such as 3proxy also opens and closes one to the server for every client
  connection. As a TCP relay, where every proxy does, the gap is 1.35-1.5
  times on ARM and 1.2-1.3 on Intel.
* 1.0.1 answers 1.5k 1 KB requests a second over kept-alive connections, held
  by a 10 ms sleep removed in devel.

## CONNECT tunnel

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | tinyproxy | squid | ‖ | devel |
|---|---:|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 13.3 | 20.5 | 1.2 | 14.3 | ‖ | **41.7 ‡** * |
| stream16, Gbit/s | 12.6 | 19.0 | 1.2 | 16.9 | ‖ | **33.6 ‡** * |
| ka-1k, k req/s | 17.4 | 17.5 | 15.4 | **35.0 ‡** * | ‖ | 17.5 |
| ka-50k-2000, k req/s | 8.4 | 10.0 | 2.1 | **15.0** * | ‖ | 10.2 |
| ka-2k-50k-2000, k req/s | 7.9 | 9.4 | 2.0 | **14.0** * | ‖ | 9.5 |
| close-1k, k req/s | 4.2 ‡ | 3.5 ‡ | 3.7 ‡ | **4.9 ‡** * | ‖ | 4.2 ‡ |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | tinyproxy | squid | ‖ | devel |
|---|---:|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 9.6 | 19.1 | 1.2 | 13.4 | ‖ | **31.0** * |
| stream16, Gbit/s | 9.7 | 18.7 | 1.3 | 13.1 | ‖ | **29.5** * |
| ka-1k, k req/s | 30.7 | 30.3 | 29.0 | **36.3** * | ‖ | 30.4 |
| ka-50k-2000, k req/s | 10.0 | 13.1 | 2.5 | 11.3 | ‖ | **15.4** * |
| ka-2k-50k-2000, k req/s | 9.7 | 12.3 | 2.5 | 11.0 | ‖ | **14.1** * |
| close-1k, k req/s | **5.2 ‡** * | 3.7 | 4.9 ‡ | 3.6 | ‖ | **5.2 ‡** * |

* With splice() devel moves 31-42 Gbit/s through a tunnel, 2-2.9 times squid;
  copying with 16 KB buffers (`-s0`) it does 10-13, below 1.0.1's 19-20 with
  its 64 KB buffers, which is what the automatic mode is for.
* squid answers 1 KB requests twice as fast as devel on ARM, 19% faster on
  Intel; with 2000 clients squid leads on ARM (15.0k against 10.2k), devel on
  Intel (15.4k against 11.3k).
* With a new tunnel per request proxychains on the client sets the pace on
  ARM; on Intel devel does 5.2k a second, squid 3.6k.

## SOCKSv5 tunnel

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | dante | ‖ | devel |
|---|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 12.9 | 19.7 | 10.6 | ‖ | **42.3 ‡** * |
| stream16, Gbit/s | 12.8 | 19.1 | 13.5 | ‖ | **33.9** * |
| ka-1k, k req/s | 17.5 | 17.6 | **25.1** * | ‖ | 17.5 |
| ka-50k-2000, k req/s | 8.5 | 10.1 | **13.3** * | ‖ | 10.2 |
| ka-2k-50k-2000, k req/s | 7.8 | 9.4 | **12.4** * | ‖ | 9.5 |
| close-1k, k req/s | **4.0** * | 3.4 | 3.6 | ‖ | **4.0** * |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | dante | ‖ | devel |
|---|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 9.7 | 19.4 | 8.0 | ‖ | **33.7** * |
| stream16, Gbit/s | 9.7 | 18.5 | 15.8 | ‖ | **31.2** * |
| ka-1k, k req/s | **29.6** * | **30.5** * | 25.0 | ‖ | **30.9** * |
| ka-50k-2000, k req/s | 10.0 | 12.9 | 11.7 | ‖ | **15.0** * |
| ka-2k-50k-2000, k req/s | 9.2 | 12.3 | 11.1 | ‖ | **14.5** * |
| close-1k, k req/s | **4.7** * | 3.9 | 1.5 | ‖ | **5.1** * |

* devel moves 31-42 Gbit/s with splice(), 2-4.2 times dante.
* On ARM dante answers 43% more 1 KB requests and 30% more with 2000 clients;
  on Intel devel leads both (by 24% and 28%).
* With a new tunnel per request devel manages 4.0-5.1k a second, dante 3.6k
  on ARM and 1.5k on Intel. With 2000 clients dante needs 0.8-1.4 GB, devel
  200 MB.

## TCP relay

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | haproxy | nginx | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|:-:|---:|---:|
| stream1-down, Gbit/s | 13.4 | **20.3** | 13.1 | 12.7 | ‖ | **41.0** * | 26.2 |
| stream16, Gbit/s | 12.8 | **19.2** | 8.1 ‡ | 12.7 | ‖ | **34.1 ‡** * | 14.3 ‡ |
| ka-1k, k req/s | 17.9 | 17.9 | **39.0** * | **37.5** | ‖ | 17.9 | **39.8** * |
| ka-50k-2000, k req/s | 9.4 | 11.1 | 10.3 | **12.8** | ‖ | 11.3 | **15.8** * |
| ka-2k-50k-2000, k req/s | 8.7 | 10.3 | 10.1 | **11.9** | ‖ | 10.3 | **15.5** * |
| close-1k, k req/s | 5.9 | 4.7 | **8.9** * | 8.0 | ‖ | 5.9 | **8.9** * |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | haproxy | nginx | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|:-:|---:|---:|
| stream1-down, Gbit/s | 9.6 | **19.0** | 9.4 | 9.6 | ‖ | **32.9** * | 31.5 |
| stream16, Gbit/s | 9.9 | **18.7** | 9.1 | 9.8 | ‖ | **31.5** * | **31.0 ‡** * |
| ka-1k, k req/s | 29.5 | 29.5 | 45.1 | **48.7** * | ‖ | 29.8 | **47.1** * |
| ka-50k-2000, k req/s | 11.0 | **14.4** | 9.8 | 11.9 | ‖ | 17.5 | **18.8** * |
| ka-2k-50k-2000, k req/s | 10.4 | **13.3** | 9.5 | 11.6 | ‖ | 15.3 | **17.9** * |
| close-1k, k req/s | 6.4 | 4.8 | 7.9 | **8.6** * | ‖ | 6.5 | **8.3** |

* On streams devel splices 32-41 Gbit/s; haproxy `splice-auto` is level on
  Intel with one stream (31.5) and sixteen (31.0), behind on ARM (26 and 14).
* nginx and haproxy answer 2.1-2.2 times more 1 KB requests on ARM, 1.5-1.6
  times on Intel.
* With 2000 clients and 50 KB answers haproxy `splice-auto` leads, 40% ahead
  of devel on ARM and 7% on Intel.

## HTTPS: TLS in the proxy

Measured on 13 October 2026 with devel as of the evening: 16 KB buffers,
splice() in its automatic mode, the thread pool, TLS read a record ahead and
relayed a full record per write ([data/](data/) `*-tls.csv`). Every proxy
relays TCP, ending TLS (`term`: TLS from the client, plain TCP to the origin)
or beginning it (`init`: plain TCP from the client, TLS to the origin): 3proxy
`tcppm` under `ssl_serv` / `ssl_cli`, nginx `stream` with `ssl` and
`proxy_ssl`, haproxy `mode tcp` with `ssl crt` and `server ... ssl`, envoy
`tcp_proxy` with TLS transport sockets, stunnel. ECDSA P-256 certificate,
TLS 1.3; envoy uses BoringSSL, the others OpenSSL (3.0.13 on ARM, 3.5.8 on
Intel). "no proxy" is the client speaking TLS to the origin itself. The
`*-ka-*` and `*-close-*` scenarios are wrk over HTTPS, the `*-stream*` ones
iperf3 wrapped in TLS by `bench/mix tls`; on one stream that wrapper, a Go
program on one core, can set the pace (‡).

### ARM (M4)

**throughput, Gbit/s (thousands of requests per second for HTTP)**

| scenario | no proxy | ‖ | devel | haproxy | nginx | envoy | stunnel |
|---|---:|:-:|---:|---:|---:|---:|---:|
| tls-term-ka-1k | 1.43 (139.2k/s) | ‖ | 0.17 (16.8k/s) | 0.33 (31.9k/s) | **0.34 (33.4k/s)** | 0.32 (30.9k/s) | 0.14 (13.9k/s) |
| tls-term-ka-1m | 29.81 (3.5k/s) | ‖ | 7.20 (0.9k/s) | 4.88 (0.6k/s) ‡ | 7.24 (0.9k/s) | **10.57 (1.3k/s) ‡** | 4.66 (0.6k/s) |
| tls-term-close-1k | 0.13 (12.3k/s) | ‖ | 0.03 (2.7k/s) ‡ | 0.03 (2.8k/s) ‡ | 0.03 (3.3k/s) ‡ | **0.04 (3.9k/s) ‡** | 0.02 (1.9k/s) ‡ |
| tls-term-stream1-down | 9.3 | ‖ | 9.2 ‡ | 8.8 ‡ | 8.6 ‡ | **9.6 ‡** | 4.7 |
| tls-term-stream16 | 19.3 | ‖ | 6.7 | 5.0 | 6.7 | **9.4** | 4.3 |
| tls-init-ka-1k | 1.43 (138.8k/s) | ‖ | 0.18 (17.2k/s) | 0.33 (32.4k/s) | **0.35 (33.7k/s)** | 0.32 (31.3k/s) | 0.15 (14.2k/s) |
| tls-init-ka-1m | 28.69 (3.4k/s) | ‖ | 6.14 (0.7k/s) | 4.63 (0.6k/s) | 5.84 (0.7k/s) | **8.59 (1.0k/s)** | 4.19 (0.5k/s) |
| tls-init-close-1k | 0.13 (12.2k/s) | ‖ | 0.02 (2.0k/s) | 0.03 (2.5k/s) | 0.03 (3.4k/s) | **0.06 (5.7k/s)** | 0.02 (1.9k/s) |
| tls-init-stream1-down | 9.2 | ‖ | 7.2 | 5.8 | 7.2 | **10.9** | 4.4 |
| tls-init-stream16 | 19.6 | ‖ | 8.3 ‡ | 5.9 ‡ | 7.8 ‡ | **11.0 ‡** | 5.2 ‡ |

**proxy CPU time per gigabyte or per request**

| scenario | no proxy | ‖ | devel | haproxy | nginx | envoy | stunnel |
|---|---:|:-:|---:|---:|---:|---:|---:|
| tls-term-ka-1k | – | ‖ | 60 µs/req | 31 µs/req | **30 µs/req** | 32 µs/req | 72 µs/req |
| tls-term-ka-1m | – | ‖ | 1.11 s/GB | 1.66 s/GB | 1.10 s/GB | **0.76 s/GB** | 1.72 s/GB |
| tls-term-close-1k | – | ‖ | 370 µs/req | 358 µs/req | 307 µs/req | **255 µs/req** | 514 µs/req |
| tls-term-stream1-down | – | ‖ | 0.85 s/GB | 0.87 s/GB | 0.91 s/GB | **0.77 s/GB** | 1.70 s/GB |
| tls-term-stream16 | – | ‖ | 1.20 s/GB | 1.60 s/GB | 1.20 s/GB | **0.85 s/GB** | 1.88 s/GB |
| tls-init-ka-1k | – | ‖ | 58 µs/req | 31 µs/req | **30 µs/req** | 32 µs/req | 71 µs/req |
| tls-init-ka-1m | – | ‖ | 1.31 s/GB | 1.75 s/GB | 1.37 s/GB | **0.93 s/GB** | 1.92 s/GB |
| tls-init-close-1k | – | ‖ | 499 µs/req | 408 µs/req | 297 µs/req | **176 µs/req** | 518 µs/req |
| tls-init-stream1-down | – | ‖ | 1.11 s/GB | 1.37 s/GB | 1.11 s/GB | **0.74 s/GB** | 1.81 s/GB |
| tls-init-stream16 | – | ‖ | 0.96 s/GB | 1.35 s/GB | 1.03 s/GB | **0.73 s/GB** | 1.53 s/GB |

**proxy peak memory, MB**

| scenario | no proxy | ‖ | devel | haproxy | nginx | envoy | stunnel |
|---|---:|:-:|---:|---:|---:|---:|---:|
| tls-term-ka-1k | – | ‖ | **12** | 36 | 32 | 18 | 13 |
| tls-term-ka-1m | – | ‖ | **15** | 43 | 44 | 41 | **13** |
| tls-term-close-1k | – | ‖ | **14** | 37 | 32 | 19 | 21 |
| tls-term-stream1-down | – | ‖ | 7 | 40 | 34 | 26 | **5** |
| tls-term-stream16 | – | ‖ | **26** | 55 | 53 | 66 | **21** |
| tls-init-ka-1k | – | ‖ | **13** | 37 | 33 | 17 | 14 |
| tls-init-ka-1m | – | ‖ | **16** | 49 | 44 | 41 | **18** |
| tls-init-close-1k | – | ‖ | **17** | 38 | 33 | **19** | **19** |
| tls-init-stream1-down | – | ‖ | **6** | 40 | 37 | 25 | **6** |
| tls-init-stream16 | – | ‖ | **62** | **59** | 72 | 122 | **56** |

### Intel (Skylake)

**throughput, Gbit/s (thousands of requests per second for HTTP)**

| scenario | no proxy | ‖ | devel | haproxy | nginx | envoy | stunnel |
|---|---:|:-:|---:|---:|---:|---:|---:|
| tls-term-ka-1k | 0.97 (95.0k/s) | ‖ | 0.23 (22.5k/s) | 0.33 (32.5k/s) | **0.34 (33.4k/s)** | 0.28 (27.1k/s) | 0.19 (18.2k/s) |
| tls-term-ka-1m | 19.50 (2.3k/s) | ‖ | **5.90 (0.7k/s)** | **5.48 (0.7k/s)** | **5.82 (0.7k/s)** | **5.80 (0.7k/s)** | 4.51 (0.5k/s) |
| tls-term-close-1k | 0.03 (3.3k/s) | ‖ | 0.01 (1.2k/s) ‡ | 0.01 (1.3k/s) ‡ | 0.01 (1.3k/s) ‡ | **0.02 (2.0k/s) ‡** | 0.01 (1.0k/s) ‡ |
| tls-term-stream1-down | 7.1 | ‖ | **5.6** | 6.1 | 5.9 | **6.9** | 5.1 |
| tls-term-stream16 | 16.2 | ‖ | 5.9 | 5.0 | 5.7 | **6.8** | 4.7 |
| tls-init-ka-1k | 0.97 (95.2k/s) | ‖ | 0.24 (23.1k/s) | **0.32 (31.1k/s)** | **0.31 (30.6k/s)** | **0.30 (29.3k/s)** | 0.19 (18.4k/s) |
| tls-init-ka-1m | 20.70 (2.5k/s) | ‖ | 5.22 (0.6k/s) | 4.85 (0.6k/s) | 5.34 (0.6k/s) | **6.35 (0.8k/s)** | 4.41 (0.5k/s) |
| tls-init-close-1k | 0.03 (3.3k/s) | ‖ | 0.01 (0.8k/s) | 0.01 (1.0k/s) | 0.01 (1.2k/s) | **0.03 (3.0k/s)** | 0.01 (0.9k/s) |
| tls-init-stream1-down | 7.5 | ‖ | 6.1 | 5.2 | 6.0 | **7.8** | 4.7 |
| tls-init-stream16 | 16.7 | ‖ | **7.1** | 5.9 ‡ | 6.8 | **7.3** | 5.6 |

**proxy CPU time per gigabyte or per request**

| scenario | no proxy | ‖ | devel | haproxy | nginx | envoy | stunnel |
|---|---:|:-:|---:|---:|---:|---:|---:|
| tls-term-ka-1k | – | ‖ | 44 µs/req | 31 µs/req | **30 µs/req** | 37 µs/req | 55 µs/req |
| tls-term-ka-1m | – | ‖ | **1.36 s/GB** | **1.47 s/GB** | **1.38 s/GB** | **1.38 s/GB** | 1.78 s/GB |
| tls-term-close-1k | – | ‖ | 821 µs/req | 774 µs/req | 781 µs/req | **510 µs/req** | 1,022 µs/req |
| tls-term-stream1-down | – | ‖ | **1.38 s/GB** | 1.28 s/GB | 1.32 s/GB | **1.08 s/GB** | 1.57 s/GB |
| tls-term-stream16 | – | ‖ | 1.35 s/GB | 1.61 s/GB | 1.40 s/GB | **1.18 s/GB** | 1.69 s/GB |
| tls-init-ka-1k | – | ‖ | 43 µs/req | **32 µs/req** | **33 µs/req** | **34 µs/req** | 55 µs/req |
| tls-init-ka-1m | – | ‖ | 1.53 s/GB | 1.67 s/GB | 1.50 s/GB | **1.26 s/GB** | 1.82 s/GB |
| tls-init-close-1k | – | ‖ | 1,187 µs/req | 1,041 µs/req | 828 µs/req | **336 µs/req** | 1,070 µs/req |
| tls-init-stream1-down | – | ‖ | 1.30 s/GB | 1.53 s/GB | 1.34 s/GB | **1.03 s/GB** | 1.71 s/GB |
| tls-init-stream16 | – | ‖ | **1.14 s/GB** | 1.37 s/GB | 1.17 s/GB | **1.11 s/GB** | 1.43 s/GB |

**proxy peak memory, MB**

| scenario | no proxy | ‖ | devel | haproxy | nginx | envoy | stunnel |
|---|---:|:-:|---:|---:|---:|---:|---:|
| tls-term-ka-1k | – | ‖ | **14** | 37 | 35 | 24 | 16 |
| tls-term-ka-1m | – | ‖ | **20** | 49 | 48 | 46 | **20** |
| tls-term-close-1k | – | ‖ | **24** | **38** | **34** | **26** | **34** |
| tls-term-stream1-down | – | ‖ | 8 | 39 | 36 | 33 | **8** |
| tls-term-stream16 | – | ‖ | 80 | **44** | 85 | 138 | 89 |
| tls-init-ka-1k | – | ‖ | **16** | 41 | 36 | 24 | 17 |
| tls-init-ka-1m | – | ‖ | **18** | 50 | 46 | 48 | 21 |
| tls-init-close-1k | – | ‖ | 59 | 40 | 35 | **27** | 34 |
| tls-init-stream1-down | – | ‖ | **11** | 39 | 35 | 32 | **10** |
| tls-init-stream16 | – | ‖ | 95 | **55** | 114 | 148 | 97 |

* **Bulk data:** devel is level with nginx and ahead of stunnel on both
  machines, and ahead of haproxy but for one stream ending TLS on Intel; envoy leads on ARM by 30-50% with a third less CPU per
  gigabyte, and on Intel by 0-30%. BoringSSL's ciphers on ARM are the likely
  difference: on Intel, ending TLS for 1 MB answers, the four are level.
* **1 KB requests over kept-alive connections:** devel answers half of what
  nginx, haproxy and envoy do on ARM and two thirds on Intel, the same share
  as without TLS: the thread per connection sets it, not TLS. stunnel, a
  thread per connection too, is below devel.
* **A handshake for every request:** ending TLS devel does 80-95% of nginx
  and haproxy, beginning it 60-80%; nginx and haproxy resume the session to
  the server, devel makes a full handshake each time. envoy does 1.2-1.5
  times nginx ending TLS and 1.7-2.5 times beginning it.
* **Memory:** with one connection or a few dozen, devel and stunnel need the
  least, mostly 6-24 MB (devel 59 MB beginning a TLS connection per request
  on Intel), against 32-50 MB for nginx and haproxy and 17-48 MB for
  envoy. With 16 streams on Intel haproxy needs the least (44-55 MB, devel
  80-95), and envoy the most everywhere (66-148 MB).

## Many connections: the mix scenarios

Measured on 13 October 2026 with the same devel ([data/](data/) `*-mix.csv`),
20000 connections open through the proxy, `--mix-active` 2000; `-3k` at a
fixed 3000 exchanges a second. dante is left out on Intel: with 20000
connections it needs more memory than the machine has (6.6 GB on ARM) and the
OOM killer ended the origin. ‡: limited by the client.

### ARM (M4)

**throughput, Gbit/s (thousands of requests per second for HTTP)**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | dante | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 1.80 (4.9k/s) | 1.42 (3.9k/s) | 1.83 (6.5k/s) ‡ | **2.76 (7.5k/s) ‡** | 0.59 (1.5k/s) | 0.92 (2.7k/s) ‡ | – (–k/s) | ‖ | **1.84 (5.0k/s)** | **1.81 (6.5k/s) ‡** |
| mix-connect | 2.08 (5.5k/s) | 2.07 (5.5k/s) ‡ | – (–k/s) | – (–k/s) | 0.74 (2.0k/s) | **2.76 (7.3k/s) ‡** | – (–k/s) | ‖ | **2.16 (5.7k/s) ‡** | – (–k/s) |
| mix-socks | 2.03 (5.5k/s) | **2.17 (5.8k/s) ‡** | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | 1.31 (3.5k/s) | ‖ | **2.13 (5.7k/s) ‡** | – (–k/s) |
| mix-relay | 2.07 (5.7k/s) | 2.12 (5.8k/s) ‡ | 2.31 (6.8k/s) ‡ | **2.72 (7.5k/s) ‡** | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | 2.16 (5.9k/s) ‡ | **2.50 (7.1k/s) ‡** |
| mix-http-3k | 1.09 (3.0k/s) | 1.08 (3.0k/s) | 1.08 (3.0k/s) | **1.09 (3.0k/s)** | 0.58 (1.5k/s) | **1.09 (3.0k/s) ‡** | – (–k/s) | ‖ | 1.08 (3.0k/s) | **1.08 (3.0k/s)** |
| mix-connect-3k | **1.09 (3.0k/s)** | 1.08 (3.0k/s) | – (–k/s) | – (–k/s) | 0.74 (2.0k/s) | 1.08 (3.0k/s) | – (–k/s) | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-socks-3k | 1.08 (3.0k/s) | 1.08 (3.0k/s) | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | **1.13 (3.1k/s)** | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-relay-3k | **1.08 (3.0k/s)** | 1.08 (3.0k/s) | **1.09 (3.0k/s)** | 1.08 (3.0k/s) | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | **1.08 (3.0k/s)** | **1.09 (3.0k/s)** |

**proxy CPU time per gigabyte or per request**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | dante | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 205 µs/req | 272 µs/req | 156 µs/req | **134 µs/req** | 675 µs/req | 375 µs/req | – µs/req | ‖ | 211 µs/req | **157 µs/req** |
| mix-connect | 190 µs/req | 187 µs/req | – µs/req | – µs/req | 507 µs/req | **139 µs/req** | – µs/req | ‖ | **182 µs/req** | – µs/req |
| mix-socks | 187 µs/req | **179 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | 298 µs/req | ‖ | **179 µs/req** | – µs/req |
| mix-relay | 186 µs/req | 182 µs/req | 151 µs/req | **136 µs/req** | – µs/req | – µs/req | – µs/req | ‖ | 177 µs/req | **143 µs/req** |
| mix-http-3k | 236 µs/req | 278 µs/req | **162 µs/req** | 169 µs/req | 678 µs/req | 326 µs/req | – µs/req | ‖ | 236 µs/req | **162 µs/req** |
| mix-connect-3k | 218 µs/req | 216 µs/req | – µs/req | – µs/req | 509 µs/req | **194 µs/req** | – µs/req | ‖ | **212 µs/req** | – µs/req |
| mix-socks-3k | **215 µs/req** | **211 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | 334 µs/req | ‖ | **210 µs/req** | – µs/req |
| mix-relay-3k | 215 µs/req | 212 µs/req | **179 µs/req** | **178 µs/req** | – µs/req | – µs/req | – µs/req | ‖ | 209 µs/req | **178 µs/req** |

**proxy peak memory, MB**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | dante | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 2,407 | 2,729 | 529 | **153** | 817 | 839 | – | ‖ | 2,438 | **556** |
| mix-connect | 2,725 | 3,220 | – | – | **1,033** | 1,768 | – | ‖ | **2,760** | – |
| mix-socks | **1,482** | 2,007 | – | – | – | – | 6,580 | ‖ | **1,506** | – |
| mix-relay | 1,246 | 1,767 | **293** | 608 | – | – | – | ‖ | 1,296 | **263** |
| mix-http-3k | 2,614 | 2,752 | 150 | **139** | 803 | 603 | – | ‖ | 2,627 | **154** |
| mix-connect-3k | 2,653 | 2,831 | – | – | **1,025** | 1,289 | – | ‖ | **2,670** | – |
| mix-socks-3k | **1,404** | 1,559 | – | – | – | – | 6,747 | ‖ | **1,422** | – |
| mix-relay-3k | 1,291 | 1,456 | **267** | 574 | – | – | – | ‖ | 1,306 | **264** |

### Intel (Skylake)

**throughput, Gbit/s (thousands of requests per second for HTTP)**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 2.39 (6.5k/s) | 1.98 (5.4k/s) | 2.29 (7.1k/s) | **2.87 (7.9k/s)** | 0.65 (1.7k/s) | 0.80 (2.2k/s) | ‖ | 2.54 (7.0k/s) | **3.02 (8.6k/s)** |
| mix-connect | **3.08 (8.2k/s)** | 2.72 (7.3k/s) | – (–k/s) | – (–k/s) | 1.02 (2.8k/s) | 2.72 (7.2k/s) | ‖ | **3.39 (9.1k/s) ‡** | – (–k/s) |
| mix-socks | 2.98 (8.0k/s) | **3.12 (8.4k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | **3.37 (9.0k/s)** | – (–k/s) |
| mix-relay | 2.97 (8.1k/s) | 3.11 (8.6k/s) | 2.54 (7.9k/s) ‡ | **3.61 (9.9k/s) ‡** | – (–k/s) | – (–k/s) | ‖ | **3.35 (9.2k/s)** | 3.00 (8.5k/s) |
| mix-http-3k | **1.10 (3.0k/s)** | **1.09 (3.0k/s)** | 1.08 (3.0k/s) | 1.09 (3.0k/s) | 0.64 (1.6k/s) | 0.63 (2.1k/s) | ‖ | **1.09 (3.0k/s)** | **1.09 (3.0k/s)** |
| mix-connect-3k | **1.08 (3.0k/s)** | 1.08 (3.0k/s) | – (–k/s) | – (–k/s) | 1.01 (2.8k/s) | 1.08 (3.0k/s) | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-socks-3k | **1.08 (3.0k/s)** | **1.08 (3.0k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-relay-3k | 1.08 (3.0k/s) | **1.08 (3.0k/s)** | **1.08 (3.0k/s)** | 1.08 (3.0k/s) | – (–k/s) | – (–k/s) | ‖ | **1.08 (3.0k/s)** | **1.08 (3.0k/s)** |

**proxy CPU time per gigabyte or per request**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 158 µs/req | 192 µs/req | 146 µs/req | **131 µs/req** | 623 µs/req | 462 µs/req | ‖ | 148 µs/req | **121 µs/req** |
| mix-connect | **125 µs/req** | **137 µs/req** | – µs/req | – µs/req | 372 µs/req | 145 µs/req | ‖ | **114 µs/req** | – µs/req |
| mix-socks | 129 µs/req | **123 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | ‖ | **115 µs/req** | – µs/req |
| mix-relay | 128 µs/req | **122 µs/req** | 131 µs/req | **105 µs/req** | – µs/req | – µs/req | ‖ | **113 µs/req** | 123 µs/req |
| mix-http-3k | 217 µs/req | 238 µs/req | **168 µs/req** | 187 µs/req | 647 µs/req | 489 µs/req | ‖ | 201 µs/req | **160 µs/req** |
| mix-connect-3k | **175 µs/req** | **172 µs/req** | – µs/req | – µs/req | 358 µs/req | 189 µs/req | ‖ | **171 µs/req** | – µs/req |
| mix-socks-3k | **181 µs/req** | **171 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | ‖ | **176 µs/req** | – µs/req |
| mix-relay-3k | 174 µs/req | 170 µs/req | 166 µs/req | **162 µs/req** | – µs/req | – µs/req | ‖ | 171 µs/req | **159 µs/req** |

**proxy peak memory, MB**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 2,432 | 2,828 | 486 | **222** | 786 | 639 | ‖ | 2,440 | **428** |
| mix-connect | 2,657 | 3,293 | – | – | **1,066** | 1,812 | ‖ | **2,692** | – |
| mix-socks | **1,412** | 1,985 | – | – | – | – | ‖ | **1,445** | – |
| mix-relay | 1,298 | 1,794 | **479** | 648 | – | – | ‖ | 1,328 | **334** |
| mix-http-3k | 2,644 | 2,820 | 179 | **154** | 765 | 868 | ‖ | 2,659 | **180** |
| mix-connect-3k | 2,648 | 2,834 | – | – | **1,038** | 1,371 | ‖ | **2,660** | – |
| mix-socks-3k | **1,398** | 1,574 | – | – | – | – | ‖ | **1,410** | – |
| mix-relay-3k | 1,358 | 1,531 | **314** | 604 | – | – | ‖ | 1,376 | **318** |

* Copying many small exchanges devel does 75-80% of nginx and haproxy on ARM
  and 85-95% on Intel, where it is first through CONNECT and SOCKS; at a fixed rate it takes 3-8% more CPU than they do as a relay, 7-25%
  more as an HTTP proxy, with the same p99.
* Memory is where a thread per connection shows: about 65 KB a connection for
  a relay or a SOCKS tunnel (the thread's stack and two 16 KB buffers), about
  130 KB for an HTTP proxy or CONNECT connection, against 8-30 KB for nginx and
  haproxy.
* nginx relays fail exchanges whose client shuts down its sending side first
  (`proxy_half_close` is off by default), 350-470 a run; with it on
  (`nginx::halfclose`, [data/](data/) `*-halfclose.csv`) there are none and
  nothing else changes: 7.47k against 7.44k on ARM, 9.83k against 9.71k on
  Intel.
* devel itself lost 2-11 exchanges a run in the tunnels and relays, every
  one half-closed by the client with a large answer, cut short. Once the
  server had answered and closed, `sockmap()` took the hang-up poll() reported
  on its socket for the end of it while the rest of the answer was still
  unread there, if its buffer was full at the time; fixed since.

## Earlier sessions

The session of 11-12 October, devel with 64 KB buffers, splice() by direction
(`-s1`, `-s3`) and the automatic mode as an option, against 0.9.4, 1.0.1 and
the same proxies, is in [data/](data/) (`*-auto-http.csv`, `*-tunnels.csv`).

The tables below are older still: from devel before the automatic mode, whose `-s` then
spliced both directions always, making a pair of pipes for each mapping
(`sockmap()` call), and before squid, tinyproxy and dante were added. In the
first table "devel" is `-s0` and "devel splice" `-s3` of today. The haproxy
splice columns there come from a second session an hour later, with plain
haproxy run again to see how far the conditions moved: by 2.5% or less on the
M4 and 7.5% or less on the Skylake host, except for one origin-bound case
(-9.7%).

* A few results were limited by the client or the origin rather than by the
  proxy, which can then do more than shown: on the M4, devel splice with single
  and 16 streams (the receiving iperf3 thread at a full core), haproxy with 16
  streams, and several of the 1 MB HTTP runs. The per-run `bound` column in
  [data/](data/) has the detail; `bench/report.py` on one machine's files marks
  them.
* http-ka-50k-2000: every proxy but haproxy leaves some requests waiting longer
  than wrk's 2 second limit (counted as timeouts in the data, 140-540 a run);
  haproxy serves the 2000 connections more evenly, with none over 2 seconds but
  a median wait 2 to 3 times longer.

### Throughput

| scenario (M4 / Intel / average) | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|
| stream1, Gbit/s | 62.0 / 44.4 / 53.2 | ‖ | 8.3 / 5.5 / 6.9 | 22.1 / 19.1 / 20.6 | **22.0 / 19.9 / 21.0** | 13.5 / 9.8 / 11.6 | 13.6 / 9.7 / 11.7 | ‖ | 25.1 / 29.2 / 27.1 | **45.7 / 31.4 / 38.6** * | 29.5 / 30.6 / 30.1 |
| stream16, Gbit/s | 141.2 / 150.5 / 145.9 | ‖ | 8.7 / 5.6 / 7.2 | **20.9 / 18.9 / 19.9** | **20.9 / 18.8 / 19.8** | 13.5 / 9.9 / 11.7 | 9.5 / 9.2 / 9.3 | ‖ | 24.5 / 28.3 / 26.4 | **37.8 / 31.2 / 34.5** * | 15.9 / 30.3 / 23.1 |
| stream1-down, Gbit/s | 61.8 / 43.1 / 52.5 | ‖ | 8.8 / 5.6 / 7.2 | **22.4 / 18.8 / 20.6** | **22.1 / 19.4 / 20.8** | 13.6 / 9.7 / 11.7 | 13.6 / 9.3 / 11.5 | ‖ | **47.9 / 34.4 / 41.1** * | 47.4 / 32.0 / 39.7 | 30.4 / 31.0 / 30.7 |
| http-ka-1k, k req/s | 120.3 / 127.1 / 123.7 | ‖ | 14.1 / 19.2 / 16.7 | 6.0 / 6.1 / 6.1 | 15.8 / 18.1 / 17.0 | 37.0 / 36.5 / 36.8 | **44.3 / 37.3 / 40.8** * | ‖ | 13.4 / 14.6 / 14.0 | 14.9 / 13.8 / 14.4 | **44.1 / 37.2 / 40.7** * |
| http-ka-1m, Gbit/s | 71.6 / 67.5 / 69.5 | ‖ | 8.3 / 5.8 / 7.1 | 12.5 / 12.4 / 12.4 | **21.9 / 18.3 / 20.1** | 12.6 / 5.8 / 9.2 | 6.0 / 7.6 / 6.8 | ‖ | **33.0 / 26.6 / 29.8** * | **35.3 / 23.9 / 29.6** * | 5.9 / 24.2 / 15.1 |
| http-ka-50k-2000, k req/s | 84.5 / 85.7 / 85.1 | ‖ | 7.6 / 7.0 / 7.3 | 9.0 / 10.3 / 9.6 | **10.4 / 10.5 / 10.5** * | 11.0 / 9.2 / 10.1 | 9.6 / 7.3 / 8.4 | ‖ | 9.1 / 9.4 / 9.3 | 9.9 / 9.0 / 9.4 | 9.6 / 7.7 / 8.6 |
| http-close-1k, k req/s | 48.7 / 52.1 / 50.4 | ‖ | 5.0 / 4.8 / 4.9 | 4.4 / 4.0 / 4.2 | 5.2 / 4.8 / 5.0 | 13.3 / 12.9 / 13.1 | **16.6 / 15.1 / 15.9** * | ‖ | 4.8 / 4.4 / 4.6 | 5.0 / 4.4 / 4.7 | **16.7 / 15.1 / 15.9** * |


### Grace delay with splice

`-s1` without grace delay, with the setting suggested in the documentation
(`-g8000,3,10`: wait 10 ms before reading once 3 reads in a row averaged 8 KB or
less), and with one meant to wait on answers only (`-g65536,2,10`: any 2 reads
in a row; an HTTP request body is read at once, an answer of 50 KB or more is
not). Measured in a session of their own ([data/](data/) `*-grace.csv`).

| scenario (M4 / Intel / average) | -s1, no grace delay | -s1 -g8000,3,10 | -s1 -g65536,2,10 |
|---|---:|---:|---:|
| stream1, Gbit/s | **22.0 / 20.0 / 21.0** * | **22.1 / 19.7 / 20.9** * | **22.4 / 20.1 / 21.3** * |
| stream16, Gbit/s | **20.8 / 19.5 / 20.2** * | **20.9 / 18.4 / 19.7** * | **20.7 / 19.1 / 19.9** * |
| stream1-down, Gbit/s | **48.1 / 32.7 / 40.4** * | 28.6 / 33.0 / 30.8 | 18.3 / 32.5 / 25.4 |
| http-ka-1k, k req/s | 15.4 / 15.4 / 15.4 | **15.5 / 16.4 / 16.0** * | **15.5 / 16.6 / 16.0** * |
| http-ka-1m, Gbit/s | **35.6 / 25.5 / 30.5** * | **35.5 / 25.2 / 30.3** * | **36.1 / 25.4 / 30.8** * |
| http-ka-2k-50k-2000, k req/s | **9.0 / 8.3 / 8.6** * | **9.0 / 8.3 / 8.7** * | **9.1 / 8.5 / 8.8** * |
| http-close-1k, k req/s | **5.1 / 4.5 / 4.8** * | **5.1 / 4.6 / 4.8** * | **5.1 / 4.7 / 4.9** * |


* Grace delay makes little difference here: 4% more 1 KB requests over
  kept-alive connections, nothing elsewhere - except on the M4 with a single
  download stream, where it costs 40% (`-g8000,3,10`) to 60% (`-g65536,2,10`)
  of the throughput. These links are fast and local: reads are rarely small,
  so the delay seldom applies, and when it does it mostly adds waiting. It is
  meant for slow links carrying small packets, which this benchmark does not
  have.

## Caveats

* Both machines are virtual: their CPUs cannot be pinned to physical cores, so
  absolute figures move between sessions; compare within a table.
* The roles have CPUs of their own but share the memory, and memory bandwidth,
  which copying proxies use most, cannot be split. On the Skylake host it may
  well be the limit; a CPU waiting for memory counts as busy, so this shows as
  less work per busy second rather than as idle time.
* wrk measures in a closed loop: a slower proxy is offered less load, so
  latencies compare only between runs of similar throughput, and requests over
  2 seconds are left out of its latency figures.
* The haproxy versions differ between the machines (2.8 and 3.0), and so,
  slightly, do squid, tinyproxy and dante.
* In the tunnel scenarios proxychains-ng's work is done in the client: with a
  new tunnel for every request it sets the pace on the M4. Runs with a new
  tunnel per request or 2000 clients count a few failed requests (at most 34
  in a run of 40,000 or more), every proxy alike.

