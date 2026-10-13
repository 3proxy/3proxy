# Benchmark results

3proxy against nginx, haproxy, squid, tinyproxy and dante on two machines,
as an HTTP proxy, through CONNECT and SOCKSv5 tunnels and as a TCP relay; and
3proxy's own versions against each other: 0.9.4, 1.0.1 and devel, with and
without splice(). The current figures are from 11-12 October 2026, for devel
with splice() by direction, pipes kept per connection and the automatic mode
(`-s`); the sessions before them, for the earlier devel, are at the end. How
the benchmark works is in [README.md](README.md); the measurements are in
[data/](data/), and `bench/report.py` turns them into the tables below.

## In short

* **HTTPS (13 October):** with TLS ended or begun in the proxy, devel moves
  1 MB answers as fast as haproxy and nginx beginning TLS (5.4 Gbit/s), and
  needs a third of their memory; it answers 59% of nginx's 1 KB requests and
  does 60-94% of its handshakes. See [HTTPS](#https-tls-in-the-proxy).
* **20000 connections (13 October):** devel keeps up with nginx and haproxy
  within 5-25% in throughput and CPU, but needs 65-130 KB per connection
  against their 8-30 KB. See [the mix scenarios](#many-connections-the-mix-scenarios).

* **Bulk data, copying:** devel moves 19-21 Gbit/s per CPU core through any
  of its services (HTTP, CONNECT, SOCKS, `tcppm`), as 1.0.1 does: 1.4 times
  squid, 1.3 to 2.2 times dante, 1.7 to 2.3 times nginx and haproxy as TCP
  relays, 2.5 to 2.9 times 0.9.4 copying and 17 times tinyproxy.
* **Bulk data, splice():** about 40 Gbit/s on one stream through every
  service, level with 0.9.4 and with haproxy splicing every connection; with
  16 streams devel gets 33-35 Gbit/s, ahead of 0.9.4 (25-26) and haproxy
  (27). 1 MB HTTP answers go 65% faster than copied (31 against 19 Gbit/s),
  15% faster than haproxy splicing.
* **The automatic mode, `-s`,** came within 5% of the best fixed mode in
  every scenario measured: it splices the bulk streams in both directions and
  copies small requests. Forcing splice() (`-s3`, and 0.9.4 by default) costs
  1 KB requests through tunnels and relays 12-21%.
* **Small requests:** squid (CONNECT) and dante (SOCKS) answer 1 KB requests
  over kept-alive tunnels 8-45% faster than devel; nginx and haproxy answer
  1.9 times more as TCP relays and 2.2 to 2.4 times more as HTTP proxies, and
  1.6 to 3 times more when each request opens a new connection. 3proxy runs
  a thread per connection; splice() cannot change that.
* **2000 clients, 50 KB answers:** devel is level with squid and dante in
  tunnels (13.1-13.6k requests per second), with nginx and haproxy splicing
  as an HTTP proxy (10-11k), ahead of haproxy copying (8.5k), and with nginx as a TCP relay copying (13.5k); haproxy
  relaying with splice() is the fastest there, 21.9k against devel's 15.2k.
* **1.0.1** is level with devel in tunnels and relays, but held to 6k
  requests per second as an HTTP proxy over kept-alive connections by a 10 ms
  sleep removed in devel (see the earlier sessions).
* **16 KB buffers (`-b16384`)** save devel 17-22% of its memory with 2000
  connections and cost 20-40% of the copying throughput; with `-s` they cost
  nothing. Since 13 October 16 KB is the default, and so is `-s`. The whole
suite run again with those defaults, against 1.0.1, nginx, haproxy, squid,
tinyproxy and dante, is in [data/](data/) `*-16k-*.csv`.
* **Memory:** with few connections 3proxy needs the least (8-17 MB against
  30-54 MB for nginx and haproxy); with 2000 connections at once, a thread for
  each costs it 150-200 MB against nginx's 90-115 MB and haproxy's 160-180 MB.

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
| devel -s0 | devel, no splice (TCP_NODELAY is on by default) |
| devel -s1 (download) | splices what the server sends: answers, downloads |
| devel -s3 (both) | splices both directions |
| devel -s (auto) | both directions, each switched to splice() once two reads in a row fill 16 KB and back to copying after three small ones; an HTTP body of known length is spliced when 16 KB or more of it remain |
| devel -b16384 | devel with 16 KB buffers instead of 64 KB |
| 0.9.4 | 0.9.4, `-s0` (no splice) `-ocTCP_NODELAY -osTCP_NODELAY` |
| 0.9.4 splice | 0.9.4, which splices both directions by default, `-ocTCP_NODELAY -osTCP_NODELAY` |
| 1.0.1 | 1.0.1, `-ocTCP_NODELAY -osTCP_NODELAY` (built without splice) |
| nginx | `proxy_pass` to an upstream with `keepalive 1024`, `stream` for the TCP relay, `reuseport` |
| haproxy | `mode http` with `http-reuse always`, `mode tcp` for the TCP relay |
| haproxy splice-response (download) | `option splice-response` |
| haproxy splice (both) | `option splice-request` and `option splice-response` |
| haproxy splice-auto | `option splice-auto`: splices a direction once reads fill the buffer three times in a row |
| squid | no cache, no logs, `via off` |
| tinyproxy | `DisableViaHeader Yes`, critical messages only |
| dante | no authentication, one `sockd` process tree (`-N 1`) |

nginx has no splice() support. Neither nginx nor haproxy has CONNECT or SOCKS,
so they are measured as HTTP proxies and TCP relays only; squid and tinyproxy
only through CONNECT, dante only through SOCKS. 3proxy versions are built with
the Makefile they shipped with (`-O3 -flto` for 1.0.1 and devel, `-O2` for
0.9.4, which on gcc 14 also needs `-fpermissive`). Logging is off everywhere.

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

* Each cell: the median on the M4 / on the Skylake host / their average. TCP
  streams and 1 MB HTTP answers in Gbit/s, the other HTTP scenarios in
  thousands of requests per second.
* Each kind of proxying has two tables: the proxies copying through user
  space (after "no proxy", the client talking to the origin with only the
  kernel forwarding, for reference), then the proxies using splice().
* **Bold**: the best average of its table in the row, and any other whose runs
  cannot be told apart from it: the range of its average (from the average of
  each machine's slowest run to that of the fastest) reaches the best one's.
* \*: the best of the row, copying and splice tables together, by the same
  rule - whether copying or splice() wins the scenario.
* CPU time per gigabyte or request and peak memory are in the data. CPU adds
  little: every proxy ran at its CPU limit, so its CPU per unit of work is the
  inverse of its throughput.

## HTTP proxy

Measured in one session on each machine ([data/](data/) `*-auto-http.csv`).

| scenario (M4 / Intel / average) | no proxy | ‖ | devel -s0 | devel -s0 -b16384 | nginx | haproxy |
|---|---:|:-:|---:|---:|---:|---:|
| http-ka-1k, k req/s | 120.8 / 129.3 / 125.0 | ‖ | 16.0 / 18.2 / 17.1 | 16.0 / 18.4 / 17.2 | 37.1 / 36.5 / 36.8 | **44.7 / 36.2 / 40.4** * |
| http-ka-1m, Gbit/s | 71.2 / 65.5 / 68.3 | ‖ | **22.4 / 15.7 / 19.1** | 13.7 / 9.4 / 11.6 | 12.8 / 5.6 / 9.2 | 5.8 / 7.3 / 6.6 |
| http-ka-50k-2000, k req/s | 86.1 / 85.2 / 85.7 | ‖ | **10.5 / 11.2 / 10.9** * | 9.2 / 8.2 / 8.7 | 11.3 / 9.0 / 10.1 | 9.8 / 7.2 / 8.5 |
| http-ka-2k-50k-2000, k req/s | 73.7 / 64.8 / 69.2 | ‖ | **9.6 / 9.6 / 9.6** * | 8.4 / 8.2 / 8.3 | 10.3 / 8.2 / 9.3 | 8.9 / 6.7 / 7.8 |
| http-close-1k, k req/s | 48.5 / 46.8 / 47.6 | ‖ | 5.2 / 4.7 / 4.9 | 5.2 / 4.7 / 5.0 | 13.5 / 13.2 / 13.3 | **16.7 / 14.7 / 15.7** |

| scenario (M4 / Intel / average) | devel -s1 (download) | devel -s3 (both) | devel -s (auto) | devel -s -b16384 | haproxy splice-response (download) | haproxy splice (both) |
|---|---:|---:|---:|---:|---:|---:|
| http-ka-1k, k req/s | 16.0 / 18.6 / 17.3 | 16.0 / 19.1 / 17.6 | 15.8 / 17.8 / 16.8 | 15.9 / 18.2 / 17.0 | **44.2 / 35.3 / 39.8** * | **44.9 / 34.6 / 39.7** * |
| http-ka-1m, Gbit/s | **36.2 / 27.1 / 31.6** * | **36.2 / 26.7 / 31.5** * | **36.3 / 25.4 / 30.9** * | **35.3 / 26.3 / 30.8** * | 27.9 / 26.6 / 27.3 | 27.3 / 27.3 / 27.3 |
| http-ka-50k-2000, k req/s | **10.4 / 10.2 / 10.3** * | **10.4 / 11.1 / 10.8** * | **10.5 / 10.5 / 10.5** * | **10.2 / 10.1 / 10.2** * | **12.0 / 9.2 / 10.6** * | **12.0 / 9.4 / 10.7** * |
| http-ka-2k-50k-2000, k req/s | **9.6 / 9.6 / 9.6** * | 9.6 / 9.4 / 9.5 | 9.4 / 9.8 / 9.6 | **9.4 / 9.7 / 9.6** * | **11.4 / 8.7 / 10.1** * | **11.3 / 8.4 / 9.9** * |
| http-close-1k, k req/s | 5.2 / 4.8 / 5.0 | 5.2 / 4.4 / 4.8 | 5.2 / 4.8 / 5.0 | 5.3 / 4.6 / 4.9 | **16.8 / 15.3 / 16.1** * | **16.9 / 15.1 / 16.0** * |

* splice() pays off for 1 MB answers, in any mode: 31 against 19 Gbit/s
  copied, ahead of haproxy splicing (27). With 50 KB answers splicing neither
  gains nor loses; with 1 KB answers or a new connection per request the mode
  makes no difference.
* Since pipes are made when first needed and kept for the connection, `-s1`
  no longer loses with 50 KB answers (9.6k against 8.7k requests per second
  in the earlier session, against 9.6k copying).
* nginx and haproxy answer 2.2-2.4 times more 1 KB requests, 2.7-3.2 times
  more when every request opens a new connection.

## CONNECT tunnel

Measured in one session on each machine, as were the SOCKS and relay tables
([data/](data/) `*-tunnels.csv`).

| scenario (M4 / Intel / average) | devel -s0 | 0.9.4 | 1.0.1 | tinyproxy | squid |
|---|---:|---:|---:|---:|---:|
| stream1-down, Gbit/s | **22.1 / 20.2 / 21.1** | 9.1 / 5.8 / 7.4 | **22.8 / 19.8 / 21.3** | 1.2 / 1.2 / 1.2 | 15.1 / 13.0 / 14.0 |
| stream16, Gbit/s | **21.1 / 18.9 / 20.0** | 8.7 / 6.0 / 7.3 | **21.1 / 19.1 / 20.1** | 1.3 / 1.2 / 1.2 | 17.6 / 12.1 / 14.8 |
| ka-1k, k req/s | 19.6 / 30.7 / 25.2 | 19.7 / 29.1 / 24.4 | 19.6 / 30.9 / 25.3 | 17.0 / 24.1 / 20.6 | **36.6 / 36.4 / 36.5** * |
| ka-50k-2000, k req/s | 11.2 / 11.5 / 11.3 | 8.3 / 8.2 / 8.3 | 11.2 / 12.7 / 12.0 | 2.3 / 2.4 / 2.3 | **16.3 / 11.0 / 13.6** * |
| close-1k, k req/s | **4.1 / 4.4 / 4.3** * | **4.2 / 4.6 / 4.4** * | 3.8 / 3.7 / 3.7 | **4.1 / 4.8 / 4.4** * | **5.3 / 3.4 / 4.4** * |

| scenario (M4 / Intel / average) | devel -s1 (download) | devel -s3 (both) | devel -s (auto) | 0.9.4 splice |
|---|---:|---:|---:|---:|
| stream1-down, Gbit/s | **47.5 / 32.0 / 39.8** * | **47.1 / 32.1 / 39.6** * | **47.5 / 31.6 / 39.5** * | **47.4 / 32.5 / 39.9** * |
| stream16, Gbit/s | 20.9 / 18.7 / 19.8 | 37.6 / 28.7 / 33.1 | **38.3 / 31.2 / 34.7** * | 24.1 / 27.7 / 25.9 |
| ka-1k, k req/s | 17.8 / 28.3 / 23.0 | 16.1 / 23.8 / 20.0 | **19.6 / 28.7 / 24.1** | 16.1 / 26.1 / 21.1 |
| ka-50k-2000, k req/s | **11.5 / 15.4 / 13.4** | 10.6 / 14.5 / 12.5 | **11.4 / 15.4 / 13.4** * | 10.6 / 15.0 / 12.8 |
| close-1k, k req/s | 4.0 / 4.2 / 4.1 | 3.8 / 3.8 / 3.8 | **4.1 / 4.4 / 4.3** * | 3.9 / 4.1 / 4.0 |

* tinyproxy stays at 1.2 Gbit/s whatever the load; squid manages 14-15 Gbit/s, devel 20 copying and 34-40 with
  splice().
* With 16 upload streams `-s1` copies, as it should; `-s3` and `-s` splice
  them. 0.9.4 splicing is level with devel on one stream but 25% behind it with
  16.
* squid answers 1 KB requests 45% faster than devel and is level with it with
  2000 clients (ahead on the M4, behind on the Skylake host).
* With a new tunnel per request the client is the limit on the M4
  (proxychains does its work there): every proxy shows 4-5k requests per
  second.

## SOCKSv5 tunnel

| scenario (M4 / Intel / average) | devel -s0 | 0.9.4 | 1.0.1 | dante |
|---|---:|---:|---:|---:|
| stream1-down, Gbit/s | **22.5 / 18.9 / 20.7** | 10.6 / 5.7 / 8.2 | **22.6 / 19.7 / 21.2** | 11.2 / 7.8 / 9.5 |
| stream16, Gbit/s | **21.1 / 18.5 / 19.8** | 8.7 / 5.8 / 7.3 | **21.0 / 19.2 / 20.1** | 14.5 / 15.2 / 14.8 |
| ka-1k, k req/s | 19.7 / 28.5 / 24.1 | 19.6 / 29.5 / 24.6 | 19.6 / 29.9 / 24.7 | **26.8 / 25.3 / 26.0** * |
| ka-50k-2000, k req/s | 10.9 / 13.1 / 12.0 | 8.2 / 7.3 / 7.8 | 11.0 / 12.6 / 11.8 | **14.7 / 11.6 / 13.1** * |
| close-1k, k req/s | 3.9 / 4.3 / 4.1 | **3.9 / 4.4 / 4.2** * | 3.6 / 3.8 / 3.7 | 3.8 / 1.5 / 2.7 |

| scenario (M4 / Intel / average) | devel -s1 (download) | devel -s3 (both) | devel -s (auto) | 0.9.4 splice |
|---|---:|---:|---:|---:|
| stream1-down, Gbit/s | **47.3 / 32.2 / 39.8** * | **47.7 / 32.7 / 40.2** * | **47.0 / 31.7 / 39.4** * | **47.5 / 31.3 / 39.4** * |
| stream16, Gbit/s | 20.9 / 17.8 / 19.4 | **37.5 / 29.4 / 33.5** * | **38.3 / 29.2 / 33.7** * | 24.2 / 26.8 / 25.5 |
| ka-1k, k req/s | 17.8 / 27.3 / 22.5 | 16.1 / 25.1 / 20.6 | **19.6 / 29.2 / 24.4** | 16.1 / 27.2 / 21.7 |
| ka-50k-2000, k req/s | **11.4 / 14.4 / 12.9** * | 10.5 / 14.4 / 12.5 | **11.4 / 15.1 / 13.2** * | **10.6 / 14.9 / 12.7** * |
| close-1k, k req/s | 3.7 / 3.7 / 3.7 | 3.6 / 3.8 / 3.7 | **3.9 / 4.1 / 4.0** | 3.7 / 4.0 / 3.8 |

* dante is 8% faster than devel with 1 KB requests and level with it with 2000
  clients; devel moves 1.3-2.2 times dante's bulk data copying (20 against
  9.5-15 Gbit/s) and 2.3-4.2 times with splice(). With a new tunnel per
  request on the Skylake host dante manages 1.5k requests per second, devel
  4.3k.

## TCP relay

| scenario (M4 / Intel / average) | devel -s0 | 0.9.4 | 1.0.1 | nginx | haproxy |
|---|---:|---:|---:|---:|---:|
| stream1-down, Gbit/s | **22.4 / 19.5 / 20.9** | 10.2 / 5.7 / 8.0 | **22.0 / 19.3 / 20.6** | 13.5 / 9.0 / 11.3 | 13.2 / 8.7 / 11.0 |
| stream16, Gbit/s | **20.9 / 19.0 / 20.0** | 8.8 / 5.8 / 7.3 | **20.9 / 18.3 / 19.6** | 13.5 / 9.7 / 11.6 | 8.9 / 8.7 / 8.8 |
| ka-1k, k req/s | 20.1 / 30.2 / 25.1 | 20.1 / 31.1 / 25.6 | 20.1 / 30.4 / 25.2 | **44.0 / 49.6 / 46.8** * | **45.6 / 46.8 / 46.2** * |
| ka-50k-2000, k req/s | **12.3 / 14.9 / 13.6** | 9.1 / 8.4 / 8.7 | **12.2 / 14.9 / 13.5** | **14.4 / 12.5 / 13.5** | 11.3 / 9.8 / 10.5 |
| close-1k, k req/s | 5.6 / 5.1 / 5.4 | 5.6 / 5.5 / 5.6 | 5.1 / 4.8 / 5.0 | 8.8 / 8.4 / 8.6 | **9.7 / 8.1 / 8.9** |

| scenario (M4 / Intel / average) | devel -s1 (download) | devel -s3 (both) | devel -s (auto) | 0.9.4 splice | haproxy splice (both) | haproxy splice-response (download) | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|
| stream1-down, Gbit/s | 46.2 / 27.7 / 36.9 | **48.1 / 31.9 / 40.0** * | **47.8 / 32.1 / 39.9** * | **47.5 / 30.1 / 38.8** * | **46.9 / 31.2 / 39.1** * | **47.1 / 27.4 / 37.3** * | 30.2 / 30.7 / 30.5 |
| stream16, Gbit/s | 20.8 / 19.1 / 20.0 | **38.1 / 32.2 / 35.2** * | **38.3 / 30.5 / 34.4** * | 24.3 / 28.5 / 26.4 | 23.0 / 31.5 / 27.3 | 8.8 / 8.4 / 8.6 | 15.7 / 30.0 / 22.9 |
| ka-1k, k req/s | 18.1 / 28.1 / 23.1 | 16.3 / 27.4 / 21.9 | 20.0 / 29.7 / 24.9 | 16.5 / 26.4 / 21.4 | 32.7 / 37.2 / 35.0 | 39.6 / 41.5 / 40.5 | **46.4 / 46.3 / 46.4** * |
| ka-50k-2000, k req/s | 12.6 / 17.9 / 15.2 | 11.5 / 17.7 / 14.6 | 12.5 / 17.6 / 15.0 | 11.6 / 17.0 / 14.3 | 20.3 / 21.9 / 21.1 | **24.3 / 19.4 / 21.9** * | 17.5 / 19.3 / 18.4 |
| close-1k, k req/s | 5.2 / 4.9 / 5.0 | 5.1 / 4.9 / 5.0 | 5.6 / 5.3 / 5.4 | 5.2 / 4.7 / 5.0 | **10.1 / 8.8 / 9.4** * | **10.1 / 8.8 / 9.5** * | 9.6 / 8.1 / 8.9 |

* As a relay devel copies 1.7-2.3 times what nginx and haproxy do; with splice()
  it is level with haproxy splicing on one stream and 26-29% ahead with 16.
  haproxy's `splice-auto` reaches 30 Gbit/s on one stream, the others 37-40.
* nginx and haproxy answer 1.9 times more 1 KB requests, 1.6 times more with
  a new connection for each.
* With 2000 clients and 50 KB answers devel and nginx are level copying
  (13.5k); splice() takes devel to 15.2k and haproxy from 10.5k to 21.9k. With
  2000 connections devel runs 2000 threads on one CPU, haproxy one event loop.
* Where splice() is forced, 1 KB requests lose 13-24% (devel `-s3`, 0.9.4,
  haproxy `splice`); `-s` and `splice-auto` lose nothing.

## 16 KB buffers

`-b16384` against the default 64 KB, from the HTTP proxy session:

| | devel -s0 | devel -s0 -b16384 | devel -s | devel -s -b16384 |
|---|---:|---:|---:|---:|
| http-ka-1m, Gbit/s (average) | 19.1 | 11.6 | 30.9 | 30.8 |
| http-ka-50k-2000, k req/s (average) | 10.9 | 8.7 | 10.5 | 10.2 |
| peak memory with 2000 clients (POST + 50 KB), MB, M4 / Skylake | 199 / 156 | 166 / 128 | 192 / 155 | 150 / 128 |
| peak memory with 16 streams, MB, M4 | 72 | 34 | | |

Copying with 16 KB buffers takes four times as many system calls for the same
data, which costs 20-40% of the throughput; with splice() the bulk of the data
goes through the pipe and the buffer size hardly matters. The memory saved
with 2000 clients, 17-22%, is far less than the buffers' size would suggest. A smaller buffer also limits what data filters see of a body, and
`tlspr` needs more than 16 KB.

## HTTPS: TLS in the proxy

Measured on 13 October 2026 with devel as of then: 16 KB buffers, `-s` by
default, the thread pool ([data/](data/) `*-tls.csv`). Every proxy relays
TCP, ending TLS (`term`: HTTPS from wrk, plain TCP to the origin) or
beginning it (`init`: plain HTTP from wrk, HTTPS to the origin): 3proxy
`tcppm` under `ssl_serv` / `ssl_cli`, nginx `stream` with `ssl` and
`proxy_ssl`, haproxy `mode tcp` with `ssl crt` and `server ... ssl`, stunnel.
ECDSA P-256 certificate, TLS 1.3, OpenSSL in every proxy; "no proxy" is wrk
speaking HTTPS to the origin itself. Every proxy ran at its CPU limit.

| scenario (M4 / Intel / average) | no proxy | ‖ | devel | nginx | haproxy | stunnel |
|---|---:|:-:|---:|---:|---:|---:|
| tls-term-ka-1k, k req/s | 140.5 / 107.2 / 123.8 | ‖ | 16.4 / 24.4 / 20.4 | **33.1 / 35.6 / 34.3** | 31.8 / 33.7 / 32.8 | 13.8 / 20.2 / 17.0 |
| tls-term-ka-1m, Gbit/s | 31.53 / 22.68 / 27.10 | ‖ | 5.95 / 4.92 / 5.44 | **6.84 / 6.05 / 6.44** | 5.00 / 5.90 / 5.45 | 4.48 / 5.13 / 4.80 |
| tls-term-close-1k, k req/s | 12.4 / 4.2 / 8.3 | ‖ | 2.7 / 1.2 / 2.0 | **3.3 / 1.4 / 2.4** | 2.9 / 1.4 / 2.1 | 2.0 / 1.1 / 1.5 |
| tls-init-ka-1k, k req/s | 140.4 / 105.9 / 123.1 | ‖ | 16.4 / 24.0 / 20.2 | **34.0 / 36.2 / 35.1** | 32.5 / 33.1 / 32.8 | 14.0 / 20.2 / 17.1 |
| tls-init-ka-1m, Gbit/s | 31.87 / 20.96 / 26.41 | ‖ | **5.60 / 5.16 / 5.38** | **5.80 / 5.43 / 5.61** | 4.58 / 5.12 / 4.85 | 4.15 / 4.56 / 4.35 |
| tls-init-close-1k, k req/s | 12.4 / 3.8 / 8.1 | ‖ | 2.0 / 0.9 / 1.4 | **3.4 / 1.3 / 2.3** | 2.5 / 1.0 / 1.7 | 2.0 / 1.0 / 1.5 |

The proxy's CPU per request (per gigabyte for 1 MB answers), its p99
latency and its peak memory, M4 / Intel:

| scenario | devel | nginx | haproxy | stunnel |
|---|---:|---:|---:|---:|
| tls-term-ka-1k, µs | 61 / 41 | **30 / 28** | 31 / 30 | 72 / 50 |
| tls-term-ka-1m, s/GB | 1.35 / 1.63 | **1.17 / 1.33** | 1.62 / 1.37 | 1.79 / 1.57 |
| tls-term-close-1k, µs | 370 / 809 | **302 / 699** | 347 / 721 | 503 / 930 |
| tls-init-ka-1m, s/GB | 1.43 / 1.55 | **1.38 / 1.48** | 1.77 / 1.58 | 1.93 / 1.76 |
| tls-init-close-1k, µs | 501 / 1159 | **293 / 796** | 401 / 1010 | 495 / 1055 |
| tls-term-close-1k, p99 ms | 9 / 44 | **2 / 4** | 16 / 41 | 26 / 57 |
| tls-init-close-1k, p99 ms | 46 / 122 | **20 / 71** | 27 / 89 | 49 / 180 |
| peak memory, MB | **12-18 / 14-77** | 31-44 / 32-48 | 36-48 / 38-53 | 13-21 / 16-34 |

* **1 MB answers:** devel is level with nginx beginning TLS and with haproxy
  ending it, 13-25% ahead of stunnel; nginx is fastest ending it. With TLS the
  cost is the cipher, so the threads matter little.
* **1 KB requests over kept-alive connections:** devel answers 59% of what
  nginx does, the same share as without TLS (`relay-ka-1k`); the thread per
  connection, not TLS, sets it. stunnel, a thread per connection too, is
  below devel.
* **A handshake for every request:** ending TLS devel does 82-94% of nginx and
  haproxy, 30% more than stunnel; beginning it 60-68% of nginx. nginx
  (`proxy_ssl_session_reuse`) and haproxy resume the session to the server, so
  most of their handshakes there are short; devel and stunnel make a full one
  for every connection.
* Handshakes cost two to three times more on the Skylake host than on the M4,
  with or without a proxy.

## Many connections: the mix scenarios

Measured on 13 October 2026 with the same devel ([data/](data/) `*-mix.csv`),
20000 connections open through the proxy, `--mix-active` 2000; `-3k` at a
fixed 3000 exchanges a second. dante is left out on the Skylake host: with
20000 connections it needs more memory than the machine has (6.6 GB on the
M4) and the OOM killer ended the origin. ‡: limited by the client.

| scenario (M4 / Intel), k exchanges/s | devel | devel -s0 | 1.0.1 | nginx | haproxy | haproxy splice-auto | squid | tinyproxy | dante |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| mix-http | 5.0 / 7.0 | 4.9 / 6.5 | 3.9 / 5.4 | **7.5‡ / 7.9** | 6.5‡ / 7.1 | 6.5‡ / **8.6** | 2.7‡ / 2.2 | 1.5 / 1.7 | |
| mix-connect | 5.7‡ / **9.1‡** | 5.5 / 8.2 | 5.5‡ / 7.3 | | | | **7.3‡** / 7.2 | 2.0 / 2.8 | |
| mix-socks | **5.7‡ / 9.0** | 5.5 / 8.0 | 5.8‡ / 8.4 | | | | | | 3.5 / - |
| mix-relay | 5.9‡ / 9.2 | 5.7 / 8.1 | 5.8‡ / 8.6 | **7.5‡ / 9.9‡** | 6.8‡ / 7.9‡ | 7.1‡ / 8.5 | | | |

| at 3000 a second (M4 / Intel) | devel | devel -s0 | 1.0.1 | nginx | haproxy | haproxy splice-auto | squid | tinyproxy | dante |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CPU per exchange, µs: mix-http-3k, mix-relay-3k | 236 / 201, 209 / 171 | 236 / 217, 215 / 174 | 278 / 238, 212 / 170 | 169 / 187, 178 / 162 | 162 / 168, 179 / 166 | **162 / 160, 178 / 159** | 326 / 489 | 678 / 647 | |
| peak memory, MB: mix-http-3k | 2627 / 2659 | 2614 / 2644 | 2752 / 2820 | **139 / 154** | 150 / 179 | 154 / 180 | 603 / 868 | 803 / 765 | |
| peak memory, MB: mix-connect-3k, mix-socks-3k | 2670 / 2660, 1422 / 1410 | 2653 / 2648, 1404 / 1398 | 2831 / 2834, 1559 / 1574 | | | | 1289 / 1371 | **1025 / 1038** | 6747 / - (socks) |
| peak memory, MB: mix-relay-3k | 1306 / 1376 | 1291 / 1358 | 1456 / 1531 | 574 / 604 | **267 / 314** | **264 / 318** | | | |

* Copying many small exchanges devel does 75-80% of nginx and haproxy on the
  M4 and 85-95% on the Skylake host, where it is first through CONNECT and
  SOCKS; at a fixed rate it takes 3-8% more CPU than they do as a relay, 7-25%
  more as an HTTP proxy, with the same p99.
* Memory is where a thread per connection shows: about 65 KB a connection for
  a relay or a SOCKS tunnel (the thread's stack and two 16 KB buffers), about
  130 KB for an HTTP proxy or CONNECT connection, against 8-30 KB for nginx and
  haproxy.
* nginx relays fail exchanges whose client shuts down its sending side first
  (`proxy_half_close` is off by default), 350-470 a run; with it on
  (`nginx::halfclose`, [data/](data/) `*-halfclose.csv`) there are none and
  nothing else changes: 7.47k against 7.44k on the M4, 9.83k against 9.71k on
  the Skylake host.

## Earlier sessions

The tables below are from devel before the automatic mode, whose `-s` then
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

| scenario (M4 / Intel / average) | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1, Gbit/s | 62.0 / 44.4 / 53.2 | ‖ | 8.3 / 5.5 / 6.9 | 22.1 / 19.1 / 20.6 | **22.0 / 19.9 / 21.0** | 13.5 / 9.8 / 11.6 | 13.6 / 9.7 / 11.7 | ‖ | 25.1 / 29.2 / 27.1 | **45.7 / 31.4 / 38.6** * | 29.5 / 30.6 / 30.1 | **44.7 / 32.3 / 38.5** * |
| stream16, Gbit/s | 141.2 / 150.5 / 145.9 | ‖ | 8.7 / 5.6 / 7.2 | **20.9 / 18.9 / 19.9** | **20.9 / 18.8 / 19.8** | 13.5 / 9.9 / 11.7 | 9.5 / 9.2 / 9.3 | ‖ | 24.5 / 28.3 / 26.4 | **37.8 / 31.2 / 34.5** * | 15.9 / 30.3 / 23.1 | 22.1 / 31.5 / 26.8 |
| stream1-down, Gbit/s | 61.8 / 43.1 / 52.5 | ‖ | 8.8 / 5.6 / 7.2 | **22.4 / 18.8 / 20.6** | **22.1 / 19.4 / 20.8** | 13.6 / 9.7 / 11.7 | 13.6 / 9.3 / 11.5 | ‖ | **47.9 / 34.4 / 41.1** * | 47.4 / 32.0 / 39.7 | 30.4 / 31.0 / 30.7 | **47.6 / 33.7 / 40.6** * |
| http-ka-1k, k req/s | 120.3 / 127.1 / 123.7 | ‖ | 14.1 / 19.2 / 16.7 | 6.0 / 6.1 / 6.1 | 15.8 / 18.1 / 17.0 | 37.0 / 36.5 / 36.8 | **44.3 / 37.3 / 40.8** * | ‖ | 13.4 / 14.6 / 14.0 | 14.9 / 13.8 / 14.4 | **44.1 / 37.2 / 40.7** * | **44.1 / 38.0 / 41.1** * |
| http-ka-1m, Gbit/s | 71.6 / 67.5 / 69.5 | ‖ | 8.3 / 5.8 / 7.1 | 12.5 / 12.4 / 12.4 | **21.9 / 18.3 / 20.1** | 12.6 / 5.8 / 9.2 | 6.0 / 7.6 / 6.8 | ‖ | **33.0 / 26.6 / 29.8** * | **35.3 / 23.9 / 29.6** * | 5.9 / 24.2 / 15.1 | 28.0 / 26.7 / 27.4 |
| http-ka-50k-2000, k req/s | 84.5 / 85.7 / 85.1 | ‖ | 7.6 / 7.0 / 7.3 | 9.0 / 10.3 / 9.6 | **10.4 / 10.5 / 10.5** * | 11.0 / 9.2 / 10.1 | 9.6 / 7.3 / 8.4 | ‖ | 9.1 / 9.4 / 9.3 | 9.9 / 9.0 / 9.4 | 9.6 / 7.7 / 8.6 | **11.9 / 9.0 / 10.4** * |
| http-close-1k, k req/s | 48.7 / 52.1 / 50.4 | ‖ | 5.0 / 4.8 / 4.9 | 4.4 / 4.0 / 4.2 | 5.2 / 4.8 / 5.0 | 13.3 / 12.9 / 13.1 | **16.6 / 15.1 / 15.9** * | ‖ | 4.8 / 4.4 / 4.6 | 5.0 / 4.4 / 4.7 | **16.7 / 15.1 / 15.9** * | **16.8 / 15.5 / 16.1** * |


### Splice by direction

devel splices what the server sends with `-s1` (downloads), what the client
sends with `-s2` (uploads), both with `-s3`; haproxy's matching settings are
`option splice-response`, `option splice-request` and both. The 2000 client
scenario here sends a 2 KB POST body with each request and gets 50 KB back
(`http-ka-2k-50k-2000`). Same setup and markings as above; measured in a
session of their own ([data/](data/) `*-splice-direction.csv`).

| scenario (M4 / Intel / average) | no proxy | ‖ | devel -s0 | haproxy | ‖ | devel -s1 | devel -s3 | haproxy splice-response | haproxy splice |
|---|---:|:-:|---:|---:|:-:|---:|---:|---:|---:|
| stream1, Gbit/s | 61.6 / 45.5 / 53.6 | ‖ | **22.4 / 19.0 / 20.7** | 13.1 / 9.5 / 11.3 | ‖ | 22.4 / 19.5 / 21.0 | **44.1 / 31.9 / 38.0** * | 13.6 / 9.7 / 11.7 | **46.3 / 30.7 / 38.5** * |
| stream16, Gbit/s | 140.6 / 147.1 / 143.8 | ‖ | **21.1 / 19.2 / 20.2** | 9.0 / 8.9 / 8.9 | ‖ | 20.9 / 18.7 / 19.8 | **38.2 / 32.3 / 35.2** * | 9.2 / 9.1 / 9.2 | 23.2 / 33.3 / 28.3 |
| stream1-down, Gbit/s | 63.7 / 47.0 / 55.3 | ‖ | **22.3 / 19.5 / 20.9** | 13.8 / 9.5 / 11.7 | ‖ | **47.9 / 33.0 / 40.5** * | **46.3 / 30.7 / 38.5** * | **46.9 / 32.3 / 39.6** * | **47.4 / 32.6 / 40.0** * |
| http-ka-1k, k req/s | 120.0 / 127.6 / 123.8 | ‖ | 15.9 / 19.5 / 17.7 | **44.2 / 37.1 / 40.7** * | ‖ | 15.3 / 17.0 / 16.1 | 15.0 / 14.9 / 14.9 | **44.0 / 37.0 / 40.5** * | **44.1 / 35.0 / 39.5** * |
| http-ka-1m, Gbit/s | 71.0 / 67.2 / 69.1 | ‖ | **22.3 / 17.5 / 19.9** | 5.8 / 7.7 / 6.8 | ‖ | **35.6 / 24.7 / 30.2** * | **34.6 / 24.5 / 29.5** * | 26.4 / 27.7 / 27.1 | 26.5 / 25.9 / 26.2 |
| http-ka-2k-50k-2000, k req/s | 73.7 / 64.7 / 69.2 | ‖ | **9.5 / 9.7 / 9.6** | 8.8 / 7.2 / 8.0 | ‖ | 9.0 / 8.4 / 8.7 | 8.7 / 7.6 / 8.1 | **11.2 / 8.7 / 10.0** * | **11.2 / 9.0 / 10.1** * |
| http-close-1k, k req/s | 49.0 / 43.4 / 46.2 | ‖ | 5.1 / 4.9 / 5.0 | **16.5 / 15.9 / 16.2** * | ‖ | 5.0 / 4.7 / 4.9 | 5.0 / 4.2 / 4.6 | **16.7 / 15.0 / 15.8** * | **16.8 / 15.5 / 16.2** * |


* Each option splices the direction it names: with `-s1` an upload stream
  goes at the copying speed and a download stream at the splicing one, as with
  haproxy's `splice-response`.
* For bulk downloads `-s1` gets all of splice()'s gain; `-s3` is needed only
  for bulk uploads (stream1, stream16).
* Small requests and 50 KB answers gain nothing from splicing in 3proxy, in
  either direction: devel `-s0` stays ahead of `-s1` and `-s3`. haproxy gains
  25% with 2000 clients from splicing the answers; there it is ahead of devel by
  4-5%.

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

