# Benchmark results

3proxy against nginx, haproxy, envoy, squid, tinyproxy, dante and stunnel on two
machines, as an HTTP proxy, through CONNECT and SOCKSv5 tunnels, as a TCP
relay, ending or beginning TLS, and with 20000 connections open at once; and
devel against 1.0.1. The current figures are from the evening of 13 October
2026, for devel with 16 KB buffers, the automatic splice() mode by default,
the thread pool and the half-close fix; the sessions before them are at the
end. How the benchmark works is in [README.md](README.md); the measurements
are in [data/](data/), and `bench/report.py` turns them into the tables
below.

## In short

Ranges are over the two machines, ARM and Intel; the tables give each.

* **Bulk data:** devel splices 32-48 Gbit/s through CONNECT, SOCKS and
  `tcppm` and 25-35 in 1 MB HTTP answers, the fastest everywhere: 2.2-3.1
  times squid, 2-4.3 times dante, 2.7-6.1 times nginx and haproxy copying 1 MB
  answers and 1.5-2.2 times envoy, the fastest copying proxy. haproxy
  `splice-auto` is level with it as a relay on Intel and behind on ARM.
  Copying with its 16 KB buffers (`-s0`) devel does 9.4-14.4 Gbit/s, level
  with nginx and haproxy; the automatic mode, the default, is what makes 16
  KB enough.
* **Small requests:** nginx and haproxy answer 1.5-2.3 times more 1 KB
  requests as relays and 1.8-2.9 times as HTTP proxies; squid 1.2-1.85 times
  more through CONNECT; through SOCKS dante leads on ARM, devel on Intel.
  3proxy runs a thread per connection; splice() cannot change that.
* **A new connection per request:** nginx and haproxy do 1.35-1.5 times more
  as relays, 2.3-2.8 times as HTTP proxies, where they keep their connections
  to the origin and a forward proxy cannot.
* **2000 clients, 50 KB answers:** on Intel devel leads as an HTTP proxy,
  through CONNECT and through SOCKS; on ARM nginx and envoy are 12% ahead of
  it as HTTP proxies, squid 41% through CONNECT, dante 29% through SOCKS. As
  a relay haproxy `splice-auto` leads on both.
* **HTTPS:** with TLS ended or begun in the proxy devel moves bulk data as
  fast as nginx, ahead of haproxy and stunnel, with the least memory; envoy
  (BoringSSL) leads, by 30-50% on ARM. devel answers half to two thirds of
  nginx's 1 KB requests and does 60-95% of its handshakes. See
  [HTTPS](#https-tls-in-the-proxy).
* **20000 connections:** devel does 63-95% of the best as an HTTP proxy and
  a relay and leads through CONNECT and SOCKS on Intel, with no failed
  exchange; it needs 65-90 KB per connection against 8-36 KB for nginx,
  haproxy and envoy. See [the mix scenarios](#many-connections-the-mix-scenarios).
* **Memory with few connections:** 3proxy needs 4-23 MB, envoy 16-31 MB,
  nginx and haproxy 28-44 MB.

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
| envoy | 1.34.1 (BoringSSL) | 1.34.1 (BoringSSL) |
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
| devel | devel as of the evening of 13 October (98fd0f3): 16 KB buffers, the thread pool, splice() in its automatic mode, the default: each direction switched to splice() once two reads in a row fill 16 KB and back to copying after three small ones; an HTTP body of known length is spliced when 16 KB or more of it remain; a half-closed connection relays the rest of the answer; an idle kept-alive connection gives up its request buffer |
| devel -s0 | devel, no splice (TCP_NODELAY is on by default) |
| 1.0.1 | 1.0.1 built without splice, 64 KB buffers, with TCP_NODELAY on both sides (`-ocTCP_NODELAY -osTCP_NODELAY`) as devel sets it by default |
| nginx | `proxy_pass` to an upstream with `keepalive 1024`, `stream` with `proxy_half_close on` for the TCP relay, `reuseport` |
| haproxy | `mode http` with `http-reuse always`, `mode tcp` for the TCP relay |
| haproxy splice-auto | `option splice-auto`: splices a direction once reads fill the buffer three times in a row |
| envoy | one worker (`--concurrency 1`), `http_connection_manager` with the router filter as an HTTP proxy for the origin, `tcp_proxy` for the TCP relay |
| squid | no cache, no logs, `via off` |
| tinyproxy | `DisableViaHeader Yes`, critical messages only |
| dante | no authentication, one `sockd` process tree (`-N 1`) |
| stunnel | TLS scenarios only |

nginx and envoy have no splice() support. None of nginx, haproxy and envoy has
CONNECT or SOCKS, so they are measured as HTTP proxies and TCP relays only; squid and tinyproxy
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
* Latency tables: each cell the medians over the runs of their 50th and
  99th percentile, in ms; bold is the lowest 99th percentile of its group
  and any other whose runs overlap it, \* the lowest of the row. iperf3
  streams have none. wrk runs a closed loop, each connection sending its
  next request once the answer is in, so a proxy answering fewer requests
  shows a longer median by that alone (64 connections at 16k requests a
  second are 4 ms each); what compares is the 99th percentile against the
  median, how evenly a proxy serves its connections, which matters most with
  2000 clients. wrk leaves requests over 2 seconds out (they are counted as
  timeouts). The mix `-3k` runs are an open loop at a fixed rate, the ones
  where latency compares directly; mix counts in steps of a sixteenth of a
  power of two (16.4 means 16.4-17.4 ms).
* CPU time per gigabyte or request and peak memory are in the data. CPU adds
  little: every proxy ran at its CPU limit, so its CPU per unit of work is the
  inverse of its throughput.

## HTTP proxy

Measured on the evening of 13 October 2026, as were the CONNECT, SOCKS and
relay tables ([data/](data/) `*-full-*.csv`).

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k, k req/s | 15.3 | 5.9 | **45.1** * | 37.3 | 24.1 | 4.1 | 21.3 | ‖ | 15.4 | **44.8** * |
| ka-1m, Gbit/s | 13.5 | 12.3 | 5.7 ‡ | 12.8 | **23.9 ‡** | 1.1 | 3.2 ‡ | ‖ | **35.0 ‡** * | 5.9 ‡ |
| ka-50k-2000, k req/s | 8.9 | 9.2 | 9.6 | **11.3** * | **11.2** * | 1.7 | 4.6 | ‖ | **10.0** | 9.8 |
| ka-2k-50k-2000, k req/s | 8.1 | 7.8 | 8.8 | 10.3 | **11.3** * | 1.6 | 3.5 | ‖ | **9.0** | 8.8 |
| close-1k, k req/s | 5.9 | 4.5 | **16.8** * | 13.4 | 15.3 | 4.0 | 7.2 | ‖ | 5.9 | **16.7** * |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k, k req/s | 17.2 | 6.1 | **32.7** * | **31.6** * | 9.9 | 3.8 | 8.8 | ‖ | 17.9 | **33.9** * |
| ka-1m, Gbit/s | 9.4 | **12.4** | 7.3 | 5.8 | **11.8** | 1.1 | 2.1 | ‖ | **25.3 ‡** * | **22.5 ‡** * |
| ka-50k-2000, k req/s | 8.1 | **9.4** * | 7.1 | **8.9** * | 6.1 | 1.6 | 2.1 | ‖ | **9.6** * | 7.1 |
| ka-2k-50k-2000, k req/s | **7.5** | **8.8** * | 7.3 | **8.3** | 4.9 | 1.6 | 1.8 | ‖ | **9.4** * | 7.1 |
| close-1k, k req/s | 5.8 | 3.9 | **14.8** * | 12.9 | 5.8 | 3.6 | 3.9 | ‖ | 5.5 | **15.0** * |

Latency, the 50th / 99th percentile in ms:

**ARM (M4)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k | 3.99 / 8.25 | 10.7 / 12.4 | **1.36 / 2.06** * | 1.68 / 2.18 * | 2.60 / 3.82 | 15.2 / 24.8 | 2.93 / 3.62 | ‖ | 3.98 / 8.14 | **1.37 / 2.05** * |
| ka-1m | 9.75 / 16.0 | 10.9 / 11.8 | 23.1 / 27.6 | 10.3 / 15.9 | **5.58 / 8.26** * | 123 / 148 | 39.7 / 48.1 | ‖ | **3.62 / 7.92** * | 22.5 / 25.2 |
| ka-50k-2000 | 67.9 / 256 | 69.5 / 226 | 196 / 539 | **83.4 / 96.9** * | 172 / 394 | 625 / 1,490 | 224 / 367 | ‖ | **52.2 / 165** | 194 / 640 |
| ka-2k-50k-2000 | 79.9 / 176 | 89.9 / 211 | 218 / 726 | **77.2 / 96.9** * | 172 / 261 | 634 / 1,680 | 266 / 369 | ‖ | **68.1 / 171** | 217 / 700 |
| close-1k | 10.7 / 16.9 | 13.9 / 21.9 | **3.66 / 4.33** * | 4.64 / 5.31 | 3.96 / 5.68 | 15.4 / 25.2 | 8.70 / 9.54 | ‖ | 10.7 / 17.1 | **3.69 / 4.34** * |

**Intel (Skylake)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k | 3.51 / 7.53 | 10.4 / 11.9 | **1.90 / 3.12** * | **1.86 / 2.90** * | 6.05 / 10.2 | 16.2 / 26.9 | 6.94 / 10.5 | ‖ | 3.40 / 7.01 | **1.74 / 2.96** * |
| ka-1m | 13.6 / 31.0 | **10.7 / 12.1** | 19.5 / 26.2 | 22.6 / 36.3 | 11.1 / 16.6 | 117 / 157 | 60.0 / 81.7 | ‖ | 5.01 / 11.9 | **5.62 / 9.29** * |
| ka-50k-2000 | 67.8 / 139 | **49.2 / 101** * | 266 / 710 | 124 / 166 | 314 / 540 | 646 / 1,700 | 485 / 578 | ‖ | **60.4 / 127** * | 261 / 673 |
| ka-2k-50k-2000 | 76.4 / 150 | **56.3 / 101** * | 262 / 658 | 130 / 174 | 383 / 608 | 657 / 1,680 | 560 / 631 | ‖ | **56.4 / 108** * | 268 / 728 |
| close-1k | 10.5 / 19.6 | 15.5 / 27.5 | **3.94 / 5.99** * | 4.56 / 6.71 | 10.7 / 16.9 | 16.6 / 28.1 | 15.6 / 21.2 | ‖ | 10.8 / 22.1 | **3.99 / 5.86** * |

* 1 MB answers: devel splices them at 35 Gbit/s on ARM and 25 on Intel, 2.7
  to 6.1 times nginx and haproxy copying and 1.5-2.1 times envoy, the fastest
  of the copying proxies here. haproxy `splice-auto` keeps up on Intel (22.5)
  but hardly splices on ARM (5.9).
* 2000 clients with 50 KB answers: nginx and envoy lead on ARM (11.3k
  requests a second against devel's 10.0k), devel on Intel (9.6k against
  nginx's 8.9k); haproxy is behind both on both. With a 2 KB POST each, the
  same order, envoy first on ARM.
* nginx and haproxy answer 2.4-2.9 times more 1 KB requests over kept-alive
  connections on ARM, 1.8-1.9 times on Intel, and 2.3-2.8 times more with a
  new connection for each. That last gap is not the thread pool's: nginx
  (`keepalive 1024`) and haproxy (`http-reuse always`) keep their connections
  to the origin and only accept and close the client's, while a forward proxy
  such as 3proxy also opens and closes one to the server for every client
  connection. As a TCP relay, where every proxy does, the gap is 1.5 times on
  ARM and 1.35 on Intel.
* envoy is close to nginx on ARM and well behind it on Intel (9.9k 1 KB
  requests against 31.6k, 5.8k new connections a second against 12.9k).
* 1.0.1, with TCP_NODELAY set this time, answers 6k 1 KB requests a second
  over kept-alive connections (1.5k without it): one every 10.6 ms on each of
  the 64 connections, held by a 10 ms sleep removed in devel.
* Latency: with 2000 clients devel's 99th percentile is 108-171 ms, nginx's
  97-174 ms and the closest to its median, haproxy's 540-730 ms and envoy's
  260-610 ms. With 1 KB requests devel's is 7-8 ms against 2-3 for nginx and
  haproxy, which answer twice as many.

## CONNECT tunnel

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | tinyproxy | squid | ‖ | devel |
|---|---:|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 14.4 | 22.7 | 1.3 | 15.2 | ‖ | **47.3 ‡** * |
| stream16, Gbit/s | 13.7 | 21.1 | 1.3 | 17.7 | ‖ | **38.5 ‡** * |
| ka-1k, k req/s | 19.7 | 19.7 | 17.1 | **36.4 ‡** * | ‖ | 19.7 |
| ka-50k-2000, k req/s | 9.5 | 11.2 | 2.2 | **16.1** * | ‖ | 11.4 |
| ka-2k-50k-2000, k req/s | 8.7 | 10.4 | 2.2 | **15.1** * | ‖ | 10.6 |
| close-1k, k req/s | 4.6 ‡ | 3.7 ‡ | 4.1 ‡ | **5.3 ‡** * | ‖ | 4.6 ‡ |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | tinyproxy | squid | ‖ | devel |
|---|---:|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 10.0 | 20.3 | 1.2 | 13.9 | ‖ | **33.9** * |
| stream16, Gbit/s | 10.1 | 19.6 | 1.3 | 13.2 | ‖ | **32.4** * |
| ka-1k, k req/s | 31.6 | 31.8 | 30.2 | **37.0** * | ‖ | 30.8 |
| ka-50k-2000, k req/s | 10.5 | 13.3 | 2.5 | 11.7 | ‖ | **15.8** * |
| ka-2k-50k-2000, k req/s | 9.8 | 12.8 | 2.4 | 11.4 | ‖ | **14.6** * |
| close-1k, k req/s | 5.3 ‡ | 3.7 | 5.1 ‡ | 3.7 | ‖ | **5.3 ‡** * |

Latency, the 50th / 99th percentile in ms:

**ARM (M4)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | tinyproxy | squid | ‖ | devel |
|---|---:|---:|---:|---:|:-:|---:|
| ka-1k | 3.04 / 6.80 | 3.04 / 6.78 | 3.59 / 6.71 | **1.74 / 2.13** * | ‖ | **3.04 / 6.74** |
| ka-50k-2000 | 178 / 354 | 147 / 320 | 757 / 1,120 | **118 / 130** * | ‖ | **145 / 318** |
| ka-2k-50k-2000 | 195 / 367 | 157 / 326 | 750 / 1,190 | **126 / 136** * | ‖ | **159 / 321** |
| close-1k | 5.49 / 13.6 | 6.34 / 15.7 | 5.99 / 15.0 | **5.34 / 10.5** * | ‖ | **5.20 / 13.3** |

**Intel (Skylake)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | tinyproxy | squid | ‖ | devel |
|---|---:|---:|---:|---:|:-:|---:|
| ka-1k | 1.94 / 3.42 | 1.92 / 3.54 | 2.03 / 3.55 | **1.63 / 2.63** * | ‖ | **1.97 / 3.54** |
| ka-50k-2000 | 135 / 253 | 109 / 223 | 477 / 1,390 | **160 / 185** * | ‖ | **82.4 / 213** |
| ka-2k-50k-2000 | 118 / 270 | 110 / 203 | 463 / 1,380 | **163 / 177** * | ‖ | **86.0 / 176** * |
| close-1k | **3.75 / 11.8** * | 5.29 / 16.0 | **3.70 / 11.0** * | 6.80 / 15.2 | ‖ | **3.31 / 11.3** * |

* With splice() devel moves 32-47 Gbit/s through a tunnel, 2.2-3.1 times
  squid; copying with 16 KB buffers (`-s0`) it does 10-14, below 1.0.1's
  20-23 with its 64 KB buffers, which is what the automatic mode is for.
* squid answers 1 KB requests 1.85 times as fast as devel on ARM, 20% faster
  on Intel; with 2000 clients squid leads on ARM (16.1k against 11.4k), devel
  on Intel (15.8k against 11.7k).
* With a new tunnel per request proxychains on the client sets the pace on
  ARM; on Intel devel does 5.3k a second, squid 3.7k.
* Latency: squid serves 2000 clients the most evenly, its 99th percentile
  130-185 ms against devel's 210-320.

## SOCKSv5 tunnel

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | dante | ‖ | devel |
|---|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 13.9 | 22.8 | 11.2 | ‖ | **48.1 ‡** * |
| stream16, Gbit/s | 14.2 | 21.0 | 14.6 | ‖ | **38.5 ‡** * |
| ka-1k, k req/s | 19.7 | 19.7 | **28.5** * | ‖ | 19.7 |
| ka-50k-2000, k req/s | 9.4 | 11.1 | **14.7** * | ‖ | 11.4 |
| ka-2k-50k-2000, k req/s | 8.7 | 10.3 | **13.9** * | ‖ | 10.5 |
| close-1k, k req/s | **4.4** * | 3.6 | 3.8 | ‖ | **4.4** * |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | dante | ‖ | devel |
|---|---:|---:|---:|:-:|---:|
| stream1-down, Gbit/s | 10.2 | 20.7 | 8.2 | ‖ | **33.3** * |
| stream16, Gbit/s | 10.2 | 19.3 | 15.9 | ‖ | **31.9** * |
| ka-1k, k req/s | **31.4** * | **31.2** * | 25.6 | ‖ | **30.4** * |
| ka-50k-2000, k req/s | 10.4 | 13.4 | 12.5 | ‖ | **15.8** * |
| ka-2k-50k-2000, k req/s | 10.1 | 12.7 | 11.5 | ‖ | **14.7** * |
| close-1k, k req/s | **5.3** * | 3.9 | 1.6 | ‖ | **5.1** * |

Latency, the 50th / 99th percentile in ms:

**ARM (M4)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | dante | ‖ | devel |
|---|---:|---:|---:|:-:|---:|
| ka-1k | 3.03 / 6.75 | 3.03 / 6.75 | **1.15 / 4.34** * | ‖ | **3.03 / 6.73** |
| ka-50k-2000 | 183 / 355 | 144 / 610 | **185 / 198** * | ‖ | **150 / 321** |
| ka-2k-50k-2000 | 203 / 367 | 163 / 331 | **186 / 201** * | ‖ | **164 / 322** |
| close-1k | **5.48 / 14.0** * | 5.91 / 15.8 | 6.11 / 17.8 | ‖ | **5.40 / 14.0** * |

**Intel (Skylake)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | dante | ‖ | devel |
|---|---:|---:|---:|:-:|---:|
| ka-1k | **1.93 / 3.62** * | **1.97 / 3.48** * | 1.46 / 5.66 | ‖ | **1.98 / 3.72** * |
| ka-50k-2000 | 137 / 257 | **118 / 221** | 2.25 / 328 | ‖ | **82.0 / 186** * |
| ka-2k-50k-2000 | 152 / 267 | **119 / 218** | 2.35 / 331 | ‖ | **101 / 195** * |
| close-1k | **3.49 / 11.2** * | 4.81 / 15.0 | 14.1 / 40.0 | ‖ | **3.75 / 12.2** * |

* devel moves 32-48 Gbit/s with splice(), 2-4.3 times dante.
* On ARM dante answers 45% more 1 KB requests and 29% more with 2000 clients;
  on Intel devel leads both (by 19% and 26%).
* With a new tunnel per request devel manages 4.4-5.3k a second, dante 3.8k
  on ARM and 1.6k on Intel.
* Latency: with 2000 clients dante's 99th percentile is 200-330 ms, devel's
  190-320.

## TCP relay

**ARM (M4)**

| scenario (ARM) | devel -s0 | 1.0.1 | haproxy | nginx | envoy | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|:-:|---:|---:|
| stream1-down, Gbit/s | 14.0 | 22.5 | 13.4 | 13.4 | **29.2** | ‖ | **48.0 ‡** * | 30.4 |
| stream16, Gbit/s | 13.8 | **21.0** | 9.7 ‡ | 13.7 | 20.3 | ‖ | **38.3 ‡** * | 16.4 ‡ |
| ka-1k, k req/s | 20.3 | 20.1 | **46.2** * | 44.2 | 35.5 | ‖ | 20.2 | **43.9** * |
| ka-50k-2000, k req/s | 10.4 | 12.2 | 11.2 | 14.5 | **15.1** | ‖ | 12.6 | **17.4** * |
| ka-2k-50k-2000, k req/s | 9.7 | 11.3 | 11.3 | 13.4 | **13.9** | ‖ | 11.6 | **17.1** * |
| close-1k, k req/s | 6.4 | 5.1 | **9.7** * | 8.8 | **9.6** * | ‖ | 6.4 | **9.7** * |

**Intel (Skylake)**

| scenario (Intel) | devel -s0 | 1.0.1 | haproxy | nginx | envoy | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|:-:|---:|---:|
| stream1-down, Gbit/s | 10.1 | **19.3** | 9.8 | 9.4 | 18.2 | ‖ | **33.2** * | **32.7** * |
| stream16, Gbit/s | 9.7 | **19.2** | 9.2 | 9.7 | 14.7 | ‖ | **32.3** * | 30.7 ‡ |
| ka-1k, k req/s | 29.8 | 30.9 | **48.3** * | **49.3** * | 36.6 | ‖ | 30.6 | **46.8** |
| ka-50k-2000, k req/s | 11.0 | **15.0** | 10.2 | 12.3 | 12.8 | ‖ | 18.1 | **19.9** * |
| ka-2k-50k-2000, k req/s | 10.5 | **13.8** | 9.7 | 12.1 | 12.4 | ‖ | 16.4 | **18.6** * |
| close-1k, k req/s | 6.8 | 4.8 | **8.8** * | **8.6** * | 5.4 | ‖ | 6.5 | **8.7** * |

Latency, the 50th / 99th percentile in ms:

**ARM (M4)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | haproxy | nginx | envoy | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k | 2.96 / 6.86 | 2.98 / 6.92 | 1.33 / 1.98 | **1.41 / 1.89** * | 1.72 / 2.70 | ‖ | 2.97 / 6.97 | **1.38 / 2.13** |
| ka-50k-2000 | 55.3 / 169 | 47.8 / 162 | 177 / 1,010 | **55.8 / 77.5** * | 130 / 219 | ‖ | **43.8 / 309** | 82.5 / 932 |
| ka-2k-50k-2000 | 58.6 / 156 | 52.1 / 153 | 172 / 1,110 | **65.5 / 81.0** * | 140 / 234 | ‖ | **50.1 / 260** | 82.5 / 1,180 |
| close-1k | 9.71 / 16.3 | 12.3 / 19.5 | **6.49 / 7.28** * | 7.11 / 7.99 | 6.34 / 9.16 | ‖ | 9.72 / 16.3 | **6.47 / 7.29** * |

**Intel (Skylake)**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | haproxy | nginx | envoy | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|:-:|---:|---:|
| ka-1k | 2.02 / 4.14 | 1.98 / 3.99 | **1.28 / 1.84** * | **1.24 / 1.82** * | 1.64 / 2.87 | ‖ | 1.98 / 3.98 | **1.29 / 1.87** * |
| ka-50k-2000 | **36.3 / 86.2** | **28.9 / 65.7** | 190 / 978 | 79.8 / 105 | 150 / 348 | ‖ | **23.4 / 49.9** * | 90.8 / 744 |
| ka-2k-50k-2000 | **40.5 / 94.5** | **32.6 / 68.7** * | 196 / 1,110 | 80.9 / 100 | 154 / 386 | ‖ | **25.4 / 47.5** * | 97.2 / 750 |
| close-1k | 9.16 / 16.6 | 12.7 / 24.0 | **6.99 / 9.78** * | **7.09 / 10.2** * | 11.3 / 16.8 | ‖ | 9.33 / 17.7 | **7.08 / 10.0** * |

* On streams devel splices 32-48 Gbit/s; haproxy `splice-auto` is level on
  Intel (32.7 and 30.7), behind on ARM (30 and 16). Of the copying proxies
  envoy is level with 1.0.1 and its 64 KB buffers on one stream (18-29),
  devel splicing 1.6-2.2 times either.
* nginx and haproxy answer 2.2-2.3 times more 1 KB requests on ARM, 1.5-1.6
  times on Intel.
* With 2000 clients and 50 KB answers haproxy `splice-auto` leads, 38% ahead
  of devel on ARM and 10% on Intel.
* nginx runs with `proxy_half_close on` (`nginx::halfclose`), off by default,
  without which its relays cut short the exchanges whose client shuts down
  its sending side first.
* Latency: with 2000 clients nginx's 99th percentile is 78-105 ms; devel's
  is 48-50 ms on Intel, the lowest, and 260-310 ms on ARM; haproxy's about a
  second, with or without splice().

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

## Kernel TLS

Measured on 14 October 2026 on Intel only, whose OpenSSL (3.5.8) and nginx
are built with kernel TLS and whose kernel has the tls module; the ARM
machine's OpenSSL (Ubuntu 24.04) is not. devel with `ssl_ktls` (bench option
`3proxy:<binary>:ktls`) and without, nginx with `ssl_conf_command Options
KTLS` / `proxy_ssl_conf_command Options KTLS` (`nginx::ktls`) and without, in
the TLS scenarios of the HTTPS section; `/proc/net/tls_stat` confirmed the
sessions in the kernel. Each cell is throughput and the CPU busy time per
gigabyte or per request.

**devel splicing over kernel TLS** ([data/](data/) `skylake-ktls-splice.csv`):
a connection whose TLS sockets the kernel took both ways is spliced as a
plain one is.

| scenario (Intel) | 3proxy | 3proxy ssl_ktls | nginx | nginx KTLS |
|---|---:|---:|---:|---:|
| tls-term-ka-1k | 23.5k/s, 43 µs | 21.2k/s, 47 µs | 34.5k/s, 29 µs | 32.3k/s, 31 µs |
| tls-term-ka-1m | 5.82 Gbit/s, 1.38 s/GB | 6.80 Gbit/s, 1.18 s/GB | 5.77 Gbit/s, 1.39 s/GB | 5.59 Gbit/s, 1.43 s/GB |
| tls-term-close-1k | 1.3k/s, 782 µs | 1.2k/s, 820 µs | 1.3k/s, 781 µs | 1.3k/s, 783 µs |
| tls-term-stream1-down | 6.56 Gbit/s, 1.20 s/GB | 7.49 Gbit/s, 0.79 s/GB | 6.27 Gbit/s, 1.26 s/GB | 6.01 Gbit/s, 1.30 s/GB |
| tls-term-stream16 | 6.31 Gbit/s, 1.27 s/GB | 6.94 Gbit/s, 1.15 s/GB | 6.20 Gbit/s, 1.29 s/GB | 5.63 Gbit/s, 1.43 s/GB |
| tls-init-ka-1k | 24.6k/s, 41 µs | 22.0k/s, 45 µs | 32.7k/s, 31 µs | 31.5k/s, 32 µs |
| tls-init-ka-1m | 5.59 Gbit/s, 1.43 s/GB | 5.90 Gbit/s, 1.36 s/GB | 5.44 Gbit/s, 1.47 s/GB | 5.03 Gbit/s, 1.59 s/GB |
| tls-init-close-1k | 0.8k/s, 1243 µs | 0.8k/s, 1265 µs | 1.3k/s, 798 µs | 1.2k/s, 861 µs |
| tls-init-stream1-down | 6.09 Gbit/s, 1.31 s/GB | 6.91 Gbit/s, 1.16 s/GB | 6.15 Gbit/s, 1.30 s/GB | 5.59 Gbit/s, 1.43 s/GB |
| tls-init-stream16 | 7.03 Gbit/s, 1.14 s/GB | 7.65 Gbit/s, 1.05 s/GB | 6.24 Gbit/s, 1.29 s/GB | 6.01 Gbit/s, 1.33 s/GB |

* With splice() kernel TLS pays for bulk data: 3proxy moves 6-17% more at
  5-34% less CPU per gigabyte (ending TLS for one stream it is no longer
  held by its CPU: 7.5 Gbit/s at 0.79 s/GB against 6.6 at 1.20), ahead of
  nginx with or without it by 8-23%.
* Small requests, which are not spliced, are 0-11% slower with it: the
  kernel does the same encryption with a layer more for every record.
* nginx, which relays TLS through user space with or without it, is 0-9%
  slower with kernel TLS.

**Before splice() over kernel TLS** ([data/](data/) `skylake-ktls.csv`), the
same with devel copying TLS connections:

| scenario (Intel) | 3proxy | 3proxy ssl_ktls | nginx | nginx KTLS |
|---|---:|---:|---:|---:|
| tls-term-ka-1k | 24.1k/s, 42 µs | 22.9k/s, 44 µs | 35.1k/s, 29 µs | 33.5k/s, 30 µs |
| tls-term-ka-1m | 6.20 Gbit/s, 1.29 s/GB | 5.48 Gbit/s, 1.46 s/GB | 5.86 Gbit/s, 1.37 s/GB | 5.75 Gbit/s, 1.39 s/GB |
| tls-term-close-1k | 1.3k/s, 785 µs | 1.2k/s, 814 µs | 1.4k/s, 712 µs | 1.3k/s, 782 µs |
| tls-term-stream1-down | 7.11 Gbit/s, 1.06 s/GB | 6.00 Gbit/s, 1.32 s/GB | 5.98 Gbit/s, 1.32 s/GB | 6.70 Gbit/s, 1.16 s/GB |
| tls-term-stream16 | 6.57 Gbit/s, 1.22 s/GB | 5.00 Gbit/s, 1.61 s/GB | 6.31 Gbit/s, 1.27 s/GB | 5.74 Gbit/s, 1.40 s/GB |
| tls-init-ka-1k | 25.7k/s, 39 µs | 22.6k/s, 44 µs | 35.9k/s, 28 µs | 33.3k/s, 30 µs |
| tls-init-ka-1m | 5.66 Gbit/s, 1.42 s/GB | 4.58 Gbit/s, 1.75 s/GB | 5.62 Gbit/s, 1.43 s/GB | 5.07 Gbit/s, 1.58 s/GB |
| tls-init-close-1k | 0.9k/s, 1124 µs | 0.8k/s, 1197 µs | 1.3k/s, 796 µs | 1.2k/s, 834 µs |
| tls-init-stream1-down | 6.43 Gbit/s, 1.24 s/GB | 5.00 Gbit/s, 1.60 s/GB | 6.17 Gbit/s, 1.30 s/GB | 5.58 Gbit/s, 1.43 s/GB |
| tls-init-stream16 | 7.20 Gbit/s, 1.11 s/GB | 6.37 Gbit/s, 1.26 s/GB | 6.43 Gbit/s, 1.25 s/GB | 6.14 Gbit/s, 1.31 s/GB |

* Without splice() kernel TLS did not pay: 3proxy did 5-24% less, at 4-32%
  more CPU per gigabyte or request.

## Many connections: the mix scenarios

Measured on the evening of 13 October 2026 with the same devel
([data/](data/) `*-full-mix.csv`), 20000 connections open through the proxy,
`--mix-active` 2000; `-3k` at a fixed 3000 exchanges a second. dante is left
out on Intel: with 20000 connections it needs more memory than the machine
has (6.5 GB on ARM) and the OOM killer ended the origin. ‡: limited by the
client.

### ARM (M4)

**throughput, Gbit/s (thousands of requests per second for HTTP)**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | dante | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 1.72 (4.7k/s) | 1.48 (4.1k/s) | 2.02 (6.8k/s) ‡ | **2.92 (8.0k/s) ‡** | 2.52 (6.9k/s) ‡ | 0.62 (1.6k/s) | 0.99 (2.9k/s) ‡ | – (–k/s) | ‖ | 1.84 (5.0k/s) | **2.06 (7.0k/s) ‡** |
| mix-connect | 2.25 (6.0k/s) | 2.02 (5.4k/s) | – (–k/s) | – (–k/s) | – (–k/s) | 0.78 (2.2k/s) | **2.78 (7.4k/s) ‡** | – (–k/s) | ‖ | **2.13 (5.7k/s) ‡** | – (–k/s) |
| mix-socks | **2.11 (5.7k/s)** | **2.07 (5.5k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | 1.34 (3.6k/s) | ‖ | **2.21 (6.0k/s) ‡** | – (–k/s) |
| mix-relay | 2.17 (6.0k/s) | 2.15 (5.9k/s) | 2.49 (7.2k/s) ‡ | **2.86 (7.8k/s) ‡** | 2.77 (7.6k/s) ‡ | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | 2.28 (6.3k/s) ‡ | **2.66 (7.6k/s) ‡** |
| mix-http-3k | 1.08 (3.0k/s) | 1.08 (3.0k/s) | 1.08 (3.0k/s) | **1.09 (3.0k/s)** | **1.09 (3.0k/s)** | 0.63 (1.6k/s) | **1.09 (3.0k/s)** | – (–k/s) | ‖ | **1.08 (3.0k/s)** | **1.08 (3.0k/s)** |
| mix-connect-3k | **1.08 (3.0k/s)** | **1.09 (3.0k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | 0.78 (2.1k/s) | 1.08 (3.0k/s) | – (–k/s) | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-socks-3k | 1.08 (3.0k/s) | 1.08 (3.0k/s) | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | **1.14 (3.0k/s)** | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-relay-3k | **1.09 (3.0k/s)** | 1.09 (3.0k/s) | 1.08 (3.0k/s) | **1.09 (3.0k/s)** | **1.09 (3.0k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | **1.08 (3.0k/s)** | **1.08 (3.0k/s)** |

**proxy CPU time per gigabyte or per request**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | dante | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 215 µs/req | 257 µs/req | 150 µs/req | **127 µs/req** | 147 µs/req | 660 µs/req | 351 µs/req | – µs/req | ‖ | 210 µs/req | **146 µs/req** |
| mix-connect | 173 µs/req | 189 µs/req | – µs/req | – µs/req | – µs/req | 477 µs/req | **139 µs/req** | – µs/req | ‖ | **184 µs/req** | – µs/req |
| mix-socks | **180 µs/req** | **191 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | – µs/req | 294 µs/req | ‖ | **172 µs/req** | – µs/req |
| mix-relay | 172 µs/req | 179 µs/req | 140 µs/req | **130 µs/req** | **139 µs/req** | – µs/req | – µs/req | – µs/req | ‖ | 164 µs/req | **134 µs/req** |
| mix-http-3k | 224 µs/req | 255 µs/req | **154 µs/req** | 162 µs/req | 184 µs/req | 631 µs/req | 295 µs/req | – µs/req | ‖ | 230 µs/req | **155 µs/req** |
| mix-connect-3k | **201 µs/req** | **211 µs/req** | – µs/req | – µs/req | – µs/req | 482 µs/req | **193 µs/req** | – µs/req | ‖ | **202 µs/req** | – µs/req |
| mix-socks-3k | **212 µs/req** | **206 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | – µs/req | 343 µs/req | ‖ | **201 µs/req** | – µs/req |
| mix-relay-3k | 205 µs/req | 207 µs/req | 170 µs/req | **167 µs/req** | 174 µs/req | – µs/req | – µs/req | – µs/req | ‖ | 206 µs/req | **167 µs/req** |

**proxy peak memory, MB**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | dante | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 1,613 | 2,730 | 531 | **151** | 587 | 819 | 839 | – | ‖ | 1,681 | **548** |
| mix-connect | 1,494 | 3,220 | – | – | – | **1,007** | 1,774 | – | ‖ | **1,774** | – |
| mix-socks | **1,462** | 1,948 | – | – | – | – | – | 6,518 | ‖ | **1,496** | – |
| mix-relay | 1,248 | 1,789 | **292** | 617 | 645 | – | – | – | ‖ | 1,284 | **269** |
| mix-http-3k | 1,564 | 2,756 | 150 | **144** | 386 | 800 | 609 | – | ‖ | 1,592 | **156** |
| mix-connect-3k | 1,412 | 2,835 | – | – | – | **1,027** | 1,292 | – | ‖ | **1,428** | – |
| mix-socks-3k | **1,405** | 1,559 | – | – | – | – | – | 6,627 | ‖ | **1,422** | – |
| mix-relay-3k | 1,293 | 1,462 | **268** | 576 | 598 | – | – | – | ‖ | 1,308 | **268** |

**latency, 50th / 99th percentile, ms**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | dante | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 19.5 / 6,291 | 12.8 / 8,126 | 8.70 / 3,146 | 4.35 / 3,932 | **262 / 393** * | 65.5 / 6,291 | 262 / 5,243 | – | ‖ | 17.4 / 6,291 | **8.19 / 3,146** |
| mix-connect | 47.1 / 4,456 | 38.9 / 5,505 | – | – | – | 98.3 / 6,816 | **13.8 / 3,670** * | – | ‖ | **57.3 / 4,719** | – |
| mix-socks | **69.6 / 4,456** * | 36.9 / 5,243 | – | – | – | – | – | **131 / 5,243** * | ‖ | **45.1 / 4,456** * | – |
| mix-relay | 13.8 / 5,243 | 7.42 / 5,243 | 34.8 / 3,277 | 4.10 / 3,801 | **246 / 393** * | – | – | – | ‖ | 13.8 / 4,719 | **30.7 / 3,277** |
| mix-http-3k | **1.47 / 16.4** * | 1.86 / 21.5 | **1.15 / 16.4** * | **1.22 / 16.4** * | **1.28 / 16.4** * | 1,507 / 6,291 | 2.18 / 26.6 | – | ‖ | **1.47 / 16.4** * | **1.15 / 16.4** * |
| mix-connect-3k | **1.28 / 16.4** * | **1.28 / 16.4** * | – | – | – | 1,507 / 6,291 | **1.28 / 16.4** * | – | ‖ | **1.28 / 16.4** * | – |
| mix-socks-3k | **1.34 / 16.4** * | **1.28 / 16.4** * | – | – | – | – | – | 63.5 / 5,243 | ‖ | **1.28 / 16.4** * | – |
| mix-relay-3k | **1.28 / 16.4** * | **1.28 / 16.4** * | **1.22 / 16.4** * | **1.15 / 16.4** * | **1.22 / 16.4** * | – | – | – | ‖ | **1.28 / 16.4** * | **1.22 / 16.4** * |

### Intel (Skylake)

**throughput, Gbit/s (thousands of requests per second for HTTP)**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 2.14 (5.9k/s) | 2.04 (5.6k/s) | 2.42 (7.4k/s) | **2.94 (8.0k/s)** | 2.04 (5.6k/s) | 0.65 (1.7k/s) | 0.82 (2.4k/s) | ‖ | 2.43 (6.7k/s) | **3.19 (9.1k/s)** |
| mix-connect | **3.02 (8.1k/s)** | **3.03 (8.1k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | 1.04 (2.9k/s) | **2.86 (7.6k/s)** | ‖ | **3.48 (9.3k/s)** | – (–k/s) |
| mix-socks | 3.08 (8.4k/s) | **3.25 (8.7k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | **3.41 (9.2k/s)** | – (–k/s) |
| mix-relay | 3.09 (8.5k/s) | 3.26 (9.0k/s) | 2.53 (7.9k/s) | **3.66 (10.0k/s) ‡** | 3.24 (8.9k/s) | – (–k/s) | – (–k/s) | ‖ | **3.46 (9.5k/s)** | 3.27 (9.2k/s) |
| mix-http-3k | 1.08 (3.0k/s) | **1.08 (3.0k/s)** | 1.08 (3.0k/s) | **1.09 (3.0k/s)** | **1.09 (3.0k/s)** | 0.66 (1.7k/s) | 0.79 (2.3k/s) | ‖ | **1.09 (3.0k/s)** | 1.08 (3.0k/s) |
| mix-connect-3k | **1.08 (3.0k/s)** | **1.08 (3.0k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | 1.06 (2.9k/s) | 1.08 (3.0k/s) | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-socks-3k | **1.08 (3.0k/s)** | **1.08 (3.0k/s)** | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | – (–k/s) | ‖ | **1.08 (3.0k/s)** | – (–k/s) |
| mix-relay-3k | 1.08 (3.0k/s) | 1.08 (3.0k/s) | 1.08 (3.0k/s) | 1.08 (3.0k/s) | **1.22 (3.3k/s)** | – (–k/s) | – (–k/s) | ‖ | **1.09 (3.0k/s)** | **1.08 (3.0k/s)** |

**proxy CPU time per gigabyte or per request**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 178 µs/req | 186 µs/req | 140 µs/req | **129 µs/req** | 188 µs/req | 630 µs/req | 436 µs/req | ‖ | 155 µs/req | **115 µs/req** |
| mix-connect | **127 µs/req** | **126 µs/req** | – µs/req | – µs/req | – µs/req | 362 µs/req | **137 µs/req** | ‖ | **113 µs/req** | – µs/req |
| mix-socks | **127 µs/req** | **122 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | – µs/req | ‖ | **115 µs/req** | – µs/req |
| mix-relay | 122 µs/req | 116 µs/req | 133 µs/req | **104 µs/req** | 117 µs/req | – µs/req | – µs/req | ‖ | **110 µs/req** | 113 µs/req |
| mix-http-3k | 217 µs/req | 223 µs/req | **166 µs/req** | 181 µs/req | 236 µs/req | 626 µs/req | 459 µs/req | ‖ | 204 µs/req | **154 µs/req** |
| mix-connect-3k | **171 µs/req** | **167 µs/req** | – µs/req | – µs/req | – µs/req | 358 µs/req | 185 µs/req | ‖ | **160 µs/req** | – µs/req |
| mix-socks-3k | 179 µs/req | **165 µs/req** | – µs/req | – µs/req | – µs/req | – µs/req | – µs/req | ‖ | **167 µs/req** | – µs/req |
| mix-relay-3k | 173 µs/req | 167 µs/req | **162 µs/req** | **159 µs/req** | **158 µs/req** | – µs/req | – µs/req | ‖ | 166 µs/req | **154 µs/req** |

**proxy peak memory, MB**

| scenario | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 1,765 | 2,851 | 489 | **220** | 609 | 786 | 650 | ‖ | 1,813 | **434** |
| mix-connect | 1,411 | 3,280 | – | – | – | **1,062** | 1,839 | ‖ | **1,442** | – |
| mix-socks | **1,408** | 2,157 | – | – | – | – | – | ‖ | **1,444** | – |
| mix-relay | 1,289 | 1,809 | **477** | 662 | 723 | – | – | ‖ | 1,324 | **340** |
| mix-http-3k | 1,622 | 2,817 | 172 | **153** | 414 | 765 | 613 | ‖ | 1,625 | **179** |
| mix-connect-3k | 1,403 | 2,837 | – | – | – | **1,034** | 1,378 | ‖ | **1,416** | – |
| mix-socks-3k | **1,400** | 1,573 | – | – | – | – | – | ‖ | **1,413** | – |
| mix-relay-3k | 1,357 | 1,529 | **315** | 625 | 614 | – | – | ‖ | 1,372 | **321** |

**latency, 50th / 99th percentile, ms**

| scenario, p50 / p99 ms | devel -s0 | 1.0.1 | haproxy | nginx | envoy | tinyproxy | squid | ‖ | devel | haproxy splice-auto |
|---|---:|---:|---:|---:|---:|---:|---:|:-:|---:|---:|
| mix-http | 6.14 / 5,767 | 4.86 / 5,767 | 115 / 2,621 | 8.19 / 3,801 | **344 / 475** * | 81.9 / 5,505 | 36.9 / 7,340 | ‖ | 4.61 / 4,981 | **139 / 1,311** |
| mix-connect | **4.35 / 3,539** | **5.89 / 3,408** | – | – | – | 77.8 / 5,505 | 12.8 / 3,670 | ‖ | **3.07 / 3,146** * | – |
| mix-socks | **4.61 / 3,277** * | **4.86 / 3,146** * | – | – | – | – | – | ‖ | **3.33 / 3,146** * | – |
| mix-relay | 2.56 / 3,670 | 3.33 / 3,277 | 111 / 2,621 | 3.46 / 2,884 | **213 / 344** * | – | – | ‖ | 1.98 / 3,146 | **69.6 / 2,359** |
| mix-http-3k | **1.34 / 16.4** * | 1.47 / 21.5 | **1.22 / 16.4** * | **1.28 / 19.5** * | **1.66 / 17.4** * | 1,049 / 5,767 | 1,245 / 7,078 | ‖ | **1.34 / 17.4** * | **1.15 / 17.4** * |
| mix-connect-3k | **1.15 / 16.4** * | **1.15 / 17.4** * | – | – | – | 24.6 / 2,228 | 1.28 / 18.4 | ‖ | **1.15 / 17.4** * | – |
| mix-socks-3k | **1.15 / 16.4** * | **1.15 / 16.4** * | – | – | – | – | – | ‖ | **1.15 / 17.4** * | – |
| mix-relay-3k | **1.15 / 16.4** * | **1.15 / 17.4** * | **1.15 / 16.4** * | **1.15 / 16.4** * | 1.47 / 1,114 | – | – | ‖ | **1.15 / 16.4** * | **1.15 / 16.4** * |

* Many small exchanges: devel does 63% of nginx's as an HTTP proxy on ARM,
  74% of haproxy `splice-auto`'s on Intel, and 81-95% of nginx's as a relay;
  through CONNECT and SOCKS it leads on Intel. At a fixed rate it takes 8-23%
  more CPU than the best as a relay, 32-49% more as an HTTP proxy; through
  CONNECT 5% more than squid on ARM and 14% less on Intel, through SOCKS 41%
  less than dante.
* Memory is where a thread per connection shows: 65-75 KB a connection for a
  relay or a SOCKS tunnel (the thread's stack and two 16 KB buffers), 70-90 KB
  for an HTTP proxy or CONNECT connection, against 8-36 KB for nginx, haproxy
  and envoy. That is 30-45% less than in the morning session (120-140 KB
  for HTTP and CONNECT): devel now frees the request buffer of a kept-alive
  connection idle for a second, and before relaying a CONNECT tunnel.
* No exchange failed through devel, or through nginx relaying with
  `proxy_half_close on`. 1.0.1 still loses 1-5 a run in the tunnels and
  relays, exchanges half-closed by the client with a large answer cut short,
  the bug fixed in devel (and in master and 0.9) since the morning session.
* envoy at the fixed rate on Intel relays more than 3000 a second: it fell
  behind at times (p99 0.7-1.2 s) and the client made up the delayed
  exchanges.
* Latency: at the fixed rate devel answers in 1.15-1.47 ms (median) and
  16.4-17.4 ms (99th percentile), as nginx and haproxy do; tinyproxy, squid
  as an HTTP proxy on Intel and dante on ARM fall behind, to seconds. With
  2000 exchanges in flight every proxy queues them, to 99th percentiles of
  1.3-8 seconds, but envoy, which keeps them to 340-480 ms around a median of
  210-340.

## Grace delay on a slow link

Measured on 14 October 2026 ([data/](data/) `*-grace-link.csv`) with devel
as in the tables above, and nginx for reference, over an emulated link
between the client and the proxy: each connection limited to 20 Mbit/s each
way (`--flow-rate 20mbit`), 5 ms of delay and 0.5% of the packets lost, each
way (`--netem "delay 5ms loss 0.5%"`), segmentation offload and GRO off. The
emulation runs in the client's namespace, on its CPUs; the link from the
proxy to the origin is left as it is ([README](README.md)). Scenarios: one
iperf3 download stream and 16 upload streams through a TCP relay
(`tcppm`), and the mix scenarios at a fixed 3000 exchanges a second with
20000 connections open.

`-gTRAFF,NUM,DELAY`: once a second has seen NUM reads in a row in one
direction averaging TRAFF bytes or less, 3proxy waits DELAY ms before it
polls again, so that data gathers and is read in fewer, larger pieces. A
read takes at most 16 KB, so the wait also caps a connection: 16 KB per
DELAY, 13 Mbit/s at 10 ms, 26 at 5 ms, 65 at 2 ms. `-g65536,2,5` waits after
any two reads.

**ARM (M4)**

| | devel | -g8000,3,10 | -g8000,3,5 | -g8000,3,2 | -g65536,2,5 | nginx |
|---|---:|---:|---:|---:|---:|---:|
| relay-stream1-down, Mbit/s | 13.9 | 13.4 | 14.7 | 14.2 | 15.0 | 14.9 |
| relay-stream16, Mbit/s | 290 | 238 | 261 | 279 | 227 | 289 |
| relay-stream16, proxy CPU s/GB | 18.7 | 12.6 | 13.3 | 13.9 | 10.8 | 16.7 |
| mix-relay-3k, k/s | 1.86 | 1.86 | 1.86 | 1.90 | 1.85 | 1.94 |
| mix-relay-3k, µs/exchange | 460 | 462 | 465 | 459 | 476 | 366 |
| mix-relay-3k, p50 / p90 / p99 ms | 2,097 / 3,801 / 6,554 | 2,097 / 3,932 / 6,554 | 2,097 / 3,801 / 6,816 | 2,097 / 3,801 / 6,554 | 2,097 / 3,932 / 6,554 | 1,966 / 3,670 / 6,291 |
| mix-http-3k, k/s | 1.78 | 1.79 | 1.82 | 1.82 | 1.83 | 1.95 |
| mix-http-3k, µs/exchange | 523 | 470 | 506 | 517 | 512 | 337 |
| mix-http-3k, p50 / p90 / p99 ms | 2,621 / 4,194 / 7,078 | 2,359 / 4,194 / 6,816 | 2,359 / 4,063 / 6,816 | 2,359 / 4,063 / 6,816 | 2,359 / 4,194 / 6,816 | 1,901 / 3,539 / 6,291 |

**Intel (Skylake)**

| | devel | -g8000,3,10 | -g8000,3,5 | -g8000,3,2 | -g65536,2,5 | nginx |
|---|---:|---:|---:|---:|---:|---:|
| relay-stream1-down, Mbit/s | 16.0 | 14.7 | 15.3 | 16.3 | 16.0 | 15.5 |
| relay-stream16, Mbit/s | 291 | 239 | 259 | 281 | 236 | 293 |
| relay-stream16, proxy CPU s/GB | 10.5 | 5.7 | 6.3 | 6.7 | 4.3 | 9.8 |
| mix-relay-3k, k/s | 2.98 | 2.99 | 2.99 | 2.99 | 2.99 | 2.98 |
| mix-relay-3k, µs/exchange | 253 | 237 | 257 | 244 | 244 | 241 |
| mix-relay-3k, p50 / p90 / p99 ms | 20.5 / 63.5 / 279 | 20.5 / 65.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 21.5 / 65.5 / 279 | 20.5 / 63.5 / 279 |
| mix-http-3k, k/s | 2.99 | 3.01 | 3.10 | 2.99 | 3.01 | 2.99 |
| mix-http-3k, µs/exchange | 294 | 306 | 303 | 300 | 312 | 264 |
| mix-http-3k, p50 / p90 / p99 ms | 22.5 / 73.7 / 311 | 24.6 / 147 / 557 | 34.8 / 590 / 1,769 | 23.6 / 77.8 / 311 | 25.6 / 115 / 393 | 20.5 / 65.5 / 295 |

* 16 streams: every wait costs throughput and saves CPU. 2 ms costs 3-4% and
  saves 26% of the proxy's CPU per gigabyte on ARM, 36% on Intel; 5 ms costs
  10-11% and saves 29-40%; 10 ms, whose cap (13 Mbit/s) is under the link's
  rate, costs 18% and saves 33-46%; `-g65536,2,5` costs 19-22% and saves
  42-59%. Without a wait devel needs 7-12% more CPU per gigabyte than nginx,
  with any of them less.
* One stream is held to 13-16 Mbit/s by the loss (TCP at 0.5% loss and a
  10 ms round trip), whatever the setting.
* The mix scenarios show no difference: on Intel the proxy's CPU per
  exchange is within 8% across the settings and the latency the same but
  for runs which stalled and caught up (more than 3000 exchanges a second),
  several in every setting, devel without a wait among them. On ARM the client
  could not keep 3000 exchanges a second over the shaped link (1.8-1.9k, its
  CPUs the limit), so the latency there is the client's backlog; the CPU per
  exchange does not move with the setting either. devel needs 5-11% more CPU
  per exchange than nginx on Intel, 26-55% on ARM.
* For slow clients moving bulk data `-g8000,3,2` keeps 96% of the
  throughput for a quarter to a third less CPU; longer waits trade more of
  one for the other.

### Seven settings, 5 client CPUs

The same link (20 Mbit/s, 5 ms, 0.5% loss), the client given a fifth CPU
(`--cpus cli=0-4,prx=5,srv=6-7`), the origin two, the proxy one as before
([data/](data/) `*-grace-link2.csv`). Each cell is the median of three runs;
"process" is the CPU time of the proxy's own processes (its threads, and the
kernel's work in their system calls), "busy" the time its CPU was busy,
the kernel's work on the network there included.

**Intel (Skylake)**

| | nginx | devel | -g8000,3,2 | -g4000,3,2 | -g6000,3,2 | -g8000,3,1 | -g8000,2,2 |
|---|---:|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 292 | 293 | 276 | 288 | 283 | 289 | 281 |
| stream16, process / busy CPU s/GB | 4.1 / 9.8 | 4.8 / 11.4 | 2.8 / 7.0 | 3.9 / 9.4 | 3.1 / 7.4 | 4.9 / 10.7 | 2.8 / 6.9 |
| mix-relay-3k, k/s | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-relay-3k, process / busy CPU µs | 68 / 239 | 78 / 257 | 84 / 260 | 83 / 267 | 77 / 251 | 80 / 258 | 77 / 251 |
| mix-relay-3k, CPU busy % | 72 | 77 | 78 | 80 | 75 | 77 | 75 |
| mix-relay-3k, p50 / p90 / p99 ms | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 295 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 |
| mix-http-3k, k/s | 3.00 | 3.09 | 3.06 | 3.04 | 3.00 | 3.01 | 3.00 |
| mix-http-3k, process / busy CPU µs | 113 / 265 | 131 / 298 | 142 / 315 | 144 / 319 | 121 / 290 | 119 / 287 | 131 / 306 |
| mix-http-3k, CPU busy % | 79 | 93 | 96 | 98 | 87 | 87 | 92 |
| mix-http-3k, p50 / p90 / p99 ms | 20.5 / 63.5 / 279 | 36.9 / 492 / 1,507 | 45.1 / 393 / 2,228 | 34.8 / 164 / 819 | 21.5 / 65.5 / 279 | 22.5 / 73.7 / 295 | 25.6 / 213 / 721 |

**ARM (M4)**

| | nginx | devel | -g8000,3,2 | -g4000,3,2 | -g6000,3,2 | -g8000,3,1 | -g8000,2,2 |
|---|---:|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 289 | 286 | 274 | 284 | 280 | 281 | 277 |
| stream16, process / busy CPU s/GB | 8.1 / 16.7 | 9.9 / 18.8 | 7.2 / 13.9 | 8.5 / 16.8 | 7.3 / 14.4 | 11.3 / 16.5 | 7.1 / 13.7 |
| mix-relay-3k, k/s | 1.88 | 1.82 | 1.84 | 1.83 | 1.85 | 1.85 | 1.85 |
| mix-relay-3k, process / busy CPU µs | 186 / 378 | 297 / 476 | 271 / 464 | 273 / 467 | 266 / 454 | 281 / 467 | 259 / 450 |
| mix-relay-3k, CPU busy % | 72 | 87 | 85 | 87 | 86 | 88 | 84 |
| mix-relay-3k, p50 / p90 / p99 ms | 2,097 / 3,801 / 6,291 | 2,359 / 4,063 / 6,816 | 2,097 / 3,932 / 6,554 | 2,228 / 3,932 / 6,554 | 2,228 / 3,932 / 6,816 | 2,097 / 3,932 / 6,554 | 2,097 / 3,932 / 6,554 |
| mix-http-3k, k/s | 1.93 | 1.79 | 1.74 | 1.77 | 1.80 | 1.76 | 1.79 |
| mix-http-3k, process / busy CPU µs | 167 / 351 | 356 / 508 | 424 / 577 | 350 / 523 | 348 / 511 | 350 / 521 | 323 / 502 |
| mix-http-3k, CPU busy % | 68 | 92 | 100 | 91 | 92 | 90 | 89 |
| mix-http-3k, p50 / p90 / p99 ms | 1,901 / 3,539 / 6,291 | 2,490 / 4,194 / 6,554 | 2,490 / 4,194 / 6,554 | 2,359 / 4,194 / 6,816 | 2,359 / 4,194 / 6,554 | 2,359 / 4,194 / 6,816 | 2,228 / 4,194 / 6,816 |

* On streams `-g8000,2,2` and `-g8000,3,2` save the most: 27-42% of the
  process CPU per gigabyte for 3-6% of the throughput, below nginx's. A wait
  of 1 ms (`-g8000,3,1`) saves nothing, a threshold of 4000 bytes little.
* On ARM the fifth CPU did not help the client: it still managed 1.8-1.9k
  exchanges a second, with its CPUs 79% busy, likely held by the ifb, whose
  one queue takes all it receives on one CPU.

### Three link qualities

Each connection each way: better 100 Mbit/s, 2 ms, 0.1% loss; current 20
Mbit/s, 5 ms, 0.5%; worse 5 Mbit/s, 25 ms, 1%. 5 client CPUs ([data/](data/)
`*-grace3-*.csv`).

**Intel (Skylake), better: 100 Mbit/s, 2 ms, 0.1%**

| | nginx | devel | -g8000,2,2 | -g6000,2,2 | -g6000,3,2 | -g8000,2,3 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 1527 | 1527 | 1527 | 1527 | 1527 | 1527 |
| stream16, process / busy CPU s/GB | 1.1 / 2.8 | 1.1 / 2.9 | 1.1 / 3.0 | 1.1 / 2.9 | 1.1 / 2.9 | 1.2 / 3.0 |
| mix-relay-3k, k/s | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-relay-3k, process / busy CPU µs | 65 / 191 | 72 / 207 | 71 / 202 | 74 / 207 | 70 / 197 | 71 / 199 |
| mix-relay-3k, CPU busy % | 57 | 62 | 61 | 62 | 59 | 60 |
| mix-relay-3k, p50 / p90 / p99 ms | 8.2 / 20.5 / 65.5 | 8.2 / 20.5 / 81.9 | 8.7 / 21.5 / 81.9 | 8.7 / 21.5 / 81.9 | 8.2 / 20.5 / 86.0 | 8.7 / 21.5 / 81.9 |
| mix-http-3k, k/s | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-http-3k, process / busy CPU µs | 109 / 218 | 114 / 243 | 115 / 244 | 116 / 242 | 114 / 243 | 114 / 245 |
| mix-http-3k, CPU busy % | 65 | 73 | 73 | 74 | 73 | 73 |
| mix-http-3k, p50 / p90 / p99 ms | 8.2 / 20.5 / 63.5 | 8.7 / 21.5 / 86.0 | 8.7 / 21.5 / 81.9 | 8.7 / 21.5 / 86.0 | 8.7 / 21.5 / 86.0 | 8.7 / 21.5 / 81.9 |

**Intel (Skylake), current: 20 Mbit/s, 5 ms, 0.5%**

| | nginx | devel | -g8000,2,2 | -g6000,2,2 | -g6000,3,2 | -g8000,2,3 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 293 | 292 | 282 | 282 | 282 | 272 |
| stream16, process / busy CPU s/GB | 4.0 / 9.8 | 4.6 / 10.6 | 2.7 / 6.6 | 3.0 / 7.4 | 3.0 / 7.4 | 2.5 / 6.4 |
| mix-relay-3k, k/s | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-relay-3k, process / busy CPU µs | 72 / 243 | 71 / 239 | 82 / 257 | 87 / 268 | 72 / 240 | 82 / 255 |
| mix-relay-3k, CPU busy % | 73 | 72 | 77 | 80 | 72 | 76 |
| mix-relay-3k, p50 / p90 / p99 ms | 20.5 / 63.5 / 262 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 |
| mix-http-3k, k/s | 3.00 | 3.05 | 3.00 | 3.02 | 3.01 | 3.02 |
| mix-http-3k, process / busy CPU µs | 112 / 263 | 140 / 308 | 123 / 294 | 130 / 305 | 129 / 304 | 122 / 293 |
| mix-http-3k, CPU busy % | 79 | 97 | 88 | 92 | 92 | 88 |
| mix-http-3k, p50 / p90 / p99 ms | 20.5 / 63.5 / 279 | 29.7 / 328 / 1,442 | 22.5 / 73.7 / 295 | 25.6 / 123 / 442 | 23.6 / 86.0 / 344 | 23.6 / 77.8 / 295 |

**Intel (Skylake), worse: 5 Mbit/s, 25 ms, 1%**

| | nginx | devel | -g8000,2,2 | -g6000,2,2 | -g6000,3,2 | -g8000,2,3 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 58 | 60 | 59 | 59 | 58 | 58 |
| stream16, process / busy CPU s/GB | 5.6 / 15.3 | 6.4 / 16.9 | 7.9 / 19.8 | 7.8 / 19.0 | 7.8 / 18.6 | 7.2 / 17.2 |
| mix-relay-3k, k/s | 2.99 | 2.99 | 2.99 | 2.99 | 3.00 | 3.00 |
| mix-relay-3k, process / busy CPU µs | 72 / 285 | 77 / 286 | 93 / 309 | 87 / 302 | 89 / 310 | 93 / 313 |
| mix-relay-3k, CPU busy % | 85 | 86 | 92 | 90 | 93 | 94 |
| mix-relay-3k, p50 / p90 / p99 ms | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 328 / 1,180 |
| mix-http-3k, k/s | 3.00 | 2.99 | 2.94 | 3.02 | 2.97 | 2.96 |
| mix-http-3k, process / busy CPU µs | 115 / 308 | 151 / 357 | 149 / 355 | 151 / 356 | 152 / 361 | 147 / 355 |
| mix-http-3k, CPU busy % | 92 | 105 | 106 | 107 | 106 | 106 |
| mix-http-3k, p50 / p90 / p99 ms | 102 / 311 / 1,180 | 475 / 1,114 / 3,801 | 557 / 1,376 / 3,539 | 254 / 1,180 / 3,670 | 344 / 1,049 / 2,621 | 524 / 1,245 / 3,277 |

**ARM (M4), better: 100 Mbit/s, 2 ms, 0.1%**

| | nginx | devel | -g8000,2,2 | -g6000,2,2 | -g6000,3,2 | -g8000,2,3 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 1523 | 1518 | 1520 | 1522 | 1521 | 1520 |
| stream16, process / busy CPU s/GB | 2.8 / 4.4 | 4.1 / 5.0 | 4.2 / 5.1 | 4.2 / 5.1 | 4.2 / 5.1 | 4.2 / 5.1 |
| mix-relay-3k, k/s | 1.98 | 1.92 | 1.97 | 1.92 | 1.92 | 1.88 |
| mix-relay-3k, process / busy CPU µs | 181 / 371 | 272 / 455 | 240 / 432 | 255 / 441 | 251 / 445 | 284 / 474 |
| mix-relay-3k, CPU busy % | 74 | 87 | 85 | 85 | 85 | 89 |
| mix-relay-3k, p50 / p90 / p99 ms | 1,704 / 3,277 / 6,029 | 2,032 / 3,670 / 6,291 | 1,901 / 3,408 / 6,291 | 1,835 / 3,539 / 6,291 | 1,966 / 3,539 / 6,291 | 1,901 / 3,539 / 6,291 |
| mix-http-3k, k/s | 1.96 | 1.89 | 1.87 | 1.81 | 1.84 | 1.85 |
| mix-http-3k, process / busy CPU µs | 165 / 354 | 337 / 475 | 355 / 511 | 342 / 500 | 401 / 544 | 387 / 519 |
| mix-http-3k, CPU busy % | 69 | 93 | 96 | 91 | 100 | 96 |
| mix-http-3k, p50 / p90 / p99 ms | 1,704 / 3,408 / 6,029 | 2,032 / 3,670 / 6,291 | 2,097 / 3,801 / 6,554 | 2,097 / 3,932 / 6,554 | 2,359 / 3,932 / 6,291 | 2,228 / 3,932 / 6,554 |

**ARM (M4), current: 20 Mbit/s, 5 ms, 0.5%**

| | nginx | devel | -g8000,2,2 | -g6000,2,2 | -g6000,3,2 | -g8000,2,3 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 290 | 290 | 275 | 279 | 277 | 272 |
| stream16, process / busy CPU s/GB | 7.7 / 15.9 | 10.3 / 18.7 | 7.2 / 13.7 | 7.3 / 14.7 | 7.4 / 14.5 | 5.8 / 13.2 |
| mix-relay-3k, k/s | 1.90 | 1.86 | 1.85 | 1.83 | 1.86 | 1.86 |
| mix-relay-3k, process / busy CPU µs | 197 / 393 | 281 / 471 | 296 / 485 | 273 / 464 | 263 / 454 | 279 / 471 |
| mix-relay-3k, CPU busy % | 75 | 88 | 90 | 86 | 85 | 88 |
| mix-relay-3k, p50 / p90 / p99 ms | 2,097 / 3,670 / 6,291 | 2,228 / 3,932 / 6,816 | 2,228 / 3,932 / 6,554 | 2,228 / 4,063 / 6,554 | 2,097 / 3,801 / 6,554 | 2,359 / 4,063 / 6,816 |
| mix-http-3k, k/s | 1.90 | 1.78 | 1.76 | 1.77 | 1.80 | 1.78 |
| mix-http-3k, process / busy CPU µs | 175 / 364 | 379 / 533 | 441 / 581 | 392 / 545 | 375 / 533 | 335 / 508 |
| mix-http-3k, CPU busy % | 69 | 97 | 102 | 98 | 95 | 90 |
| mix-http-3k, p50 / p90 / p99 ms | 2,032 / 3,670 / 6,291 | 2,359 / 4,194 / 6,816 | 2,621 / 4,456 / 6,554 | 2,490 / 4,194 / 6,554 | 2,359 / 4,063 / 6,554 | 2,228 / 4,063 / 6,554 |

**ARM (M4), worse: 5 Mbit/s, 25 ms, 1%**

| | nginx | devel | -g8000,2,2 | -g6000,2,2 | -g6000,3,2 | -g8000,2,3 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 56 | 53 | 53 | 52 | 54 | 51 |
| stream16, process / busy CPU s/GB | 20.7 / 50.0 | 22.7 / 53.8 | 28.6 / 47.5 | 30.4 / 50.8 | 29.4 / 49.2 | 25.7 / 46.7 |
| mix-relay-3k, k/s | 1.84 | 1.83 | 1.82 | 1.80 | 1.83 | 1.78 |
| mix-relay-3k, process / busy CPU µs | 205 / 409 | 255 / 454 | 287 / 486 | 308 / 499 | 263 / 463 | 310 / 505 |
| mix-relay-3k, CPU busy % | 74 | 83 | 88 | 90 | 85 | 90 |
| mix-relay-3k, p50 / p90 / p99 ms | 2,228 / 4,063 / 6,554 | 2,228 / 4,063 / 6,554 | 2,228 / 4,063 / 6,554 | 2,359 / 4,194 / 6,816 | 2,359 / 4,063 / 6,554 | 2,228 / 4,194 / 6,554 |
| mix-http-3k, k/s | 1.89 | 1.75 | 1.73 | 1.76 | 1.74 | 1.75 |
| mix-http-3k, process / busy CPU µs | 163 / 352 | 361 / 527 | 376 / 534 | 348 / 515 | 389 / 554 | 332 / 510 |
| mix-http-3k, CPU busy % | 67 | 92 | 95 | 90 | 96 | 90 |
| mix-http-3k, p50 / p90 / p99 ms | 2,097 / 3,932 / 6,291 | 2,621 / 4,456 / 6,816 | 2,490 / 4,456 / 6,816 | 2,490 / 4,194 / 6,816 | 2,621 / 4,456 / 6,816 | 2,490 / 4,194 / 6,816 |

* Better link: 16 streams reach the 100 Mbit/s per connection for every
  proxy and setting; reads are large, the wait never applies, and nothing
  changes. In the mix scenarios on Intel the settings are within 5% of each
  other.
* Current link: on streams the wait saves 35-46% of the process CPU per
  gigabyte on Intel (3-7% of the throughput), 28-44% on ARM. In
  `mix-http-3k` on Intel devel's CPU was 97% busy and its latency jumped
  (p90 328 ms); the settings brought it to 88-92% and p90 74-123 ms, near
  nginx's (79%, 64 ms). The earlier runs on this link did not show that gain
  in the mix: it is within the noise of a CPU this close to full.
* Worse link: loss holds 16 streams to 51-60 Mbit/s in all; reads are small
  and frequent, and the wait costs CPU instead: 13-23% more per gigabyte on
  Intel. As an HTTP proxy at 3000 exchanges a second every 3proxy setting
  ran out of CPU on Intel (latency p50 0.25-0.56 s), nginx did not (92%,
  p50 102 ms); as a relay all kept up.
* Grace delay does not help when the proxy's CPU is exhausted, and degrades
  slightly: on the worse link, with the proxy's CPU at its limit on Intel,
  the waits added 13-21% process CPU per exchange as a relay (86% busy
  without them, 90-94% with), and as an HTTP proxy, out of CPU, no setting
  made the latency reliably better (p50 0.25-0.56 s against 0.48 s).
* ARM's client held every mix run at 1.8-2.0k exchanges a second: latency
  there is its backlog. 1-3 exchanges were lost in each link's 3proxy
  `mix-relay-3k` runs on ARM, none on Intel.

### Splice and grace delay

devel copying (`-s0`) and splicing (`-s`), without grace delay and with two
settings, over the better and current links with 5 client CPUs
([data/](data/) `*-splice-g-*.csv`, `*-connect-g-*.csv`).

**Intel (Skylake), better: 100 Mbit/s, 2 ms, 0.1%**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g6000,3,2 | -s -g6000,3,2 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 1527 | 1526 | 1527 | 1527 | 1527 | 1527 |
| stream16, process / busy CPU s/GB | 1.2 / 2.9 | 1.1 / 2.9 | 1.2 / 2.8 | 1.1 / 2.8 | 1.2 / 2.9 | 1.1 / 2.8 |
| mix-relay-3k, k/s | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-relay-3k, process / busy CPU µs | 76 / 205 | 71 / 207 | 80 / 208 | 75 / 211 | 79 / 214 | 72 / 204 |
| mix-relay-3k, CPU busy % | 62 | 62 | 62 | 63 | 64 | 61 |
| mix-relay-3k, p50 / p90 / p99 ms | 8.2 / 20.5 / 81.9 | 8.2 / 20.5 / 86.0 | 8.7 / 21.5 / 98.3 | 8.7 / 21.5 / 81.9 | 8.2 / 20.5 / 86.0 | 8.2 / 20.5 / 86.0 |
| mix-http-3k, k/s | 3.00 | 3.01 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-http-3k, process / busy CPU µs | 125 / 251 | 124 / 257 | 125 / 254 | 120 / 255 | 124 / 251 | 113 / 244 |
| mix-http-3k, CPU busy % | 76 | 78 | 76 | 76 | 75 | 73 |
| mix-http-3k, p50 / p90 / p99 ms | 8.7 / 21.5 / 86.0 | 8.7 / 22.5 / 106 | 8.7 / 21.5 / 86.0 | 8.7 / 21.5 / 86.0 | 8.7 / 21.5 / 86.0 | 8.7 / 21.5 / 77.8 |
| mix-connect-3k, k/s | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-connect-3k, process / busy CPU µs | 77 / 201 | 72 / 203 | 86 / 221 | 81 / 217 | 82 / 211 | 79 / 213 |
| mix-connect-3k, CPU busy % | 60 | 61 | 66 | 65 | 63 | 64 |
| mix-connect-3k, p50 / p90 / p99 ms | 8.2 / 20.5 / 63.5 | 8.2 / 20.5 / 65.5 | 8.7 / 21.5 / 65.5 | 8.7 / 21.5 / 65.5 | 8.2 / 21.5 / 65.5 | 8.2 / 21.5 / 63.5 |

**Intel (Skylake), current: 20 Mbit/s, 5 ms, 0.5%**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g6000,3,2 | -s -g6000,3,2 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 292 | 293 | 281 | 280 | 282 | 281 |
| stream16, process / busy CPU s/GB | 4.8 / 10.6 | 4.9 / 10.9 | 3.1 / 7.4 | 2.7 / 6.6 | 3.1 / 7.5 | 3.2 / 7.6 |
| mix-relay-3k, k/s | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 | 3.00 |
| mix-relay-3k, process / busy CPU µs | 80 / 250 | 81 / 258 | 82 / 255 | 80 / 261 | 79 / 248 | 73 / 245 |
| mix-relay-3k, CPU busy % | 75 | 77 | 76 | 78 | 74 | 73 |
| mix-relay-3k, p50 / p90 / p99 ms | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 | 20.5 / 63.5 / 279 |
| mix-http-3k, k/s | 3.02 | 3.00 | 3.06 | 3.04 | 3.02 | 3.02 |
| mix-http-3k, process / busy CPU µs | 139 / 309 | 122 / 293 | 143 / 314 | 140 / 315 | 147 / 318 | 138 / 318 |
| mix-http-3k, CPU busy % | 93 | 88 | 95 | 95 | 96 | 96 |
| mix-http-3k, p50 / p90 / p99 ms | 24.6 / 86.0 / 311 | 23.6 / 115 / 410 | 31.7 / 344 / 819 | 36.9 / 459 / 1,442 | 30.7 / 147 / 721 | 30.7 / 229 / 950 |
| mix-connect-3k, k/s | 2.99 | 3.00 | 3.00 | 3.00 | 2.99 | 3.00 |
| mix-connect-3k, process / busy CPU µs | 87 / 264 | 93 / 285 | 85 / 257 | 82 / 261 | 90 / 270 | 76 / 249 |
| mix-connect-3k, CPU busy % | 79 | 86 | 77 | 78 | 81 | 74 |
| mix-connect-3k, p50 / p90 / p99 ms | 20.5 / 63.5 / 262 | 20.5 / 63.5 / 262 | 20.5 / 63.5 / 279 | 20.5 / 65.5 / 279 | 20.5 / 65.5 / 262 | 20.5 / 63.5 / 279 |

**ARM (M4), better: 100 Mbit/s, 2 ms, 0.1%**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g6000,3,2 | -s -g6000,3,2 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 1522 | 1520 | 1523 | 1518 | 1523 | 1521 |
| stream16, process / busy CPU s/GB | 3.5 / 4.9 | 4.2 / 5.1 | 3.6 / 4.9 | 4.1 / 5.0 | 3.5 / 4.9 | 4.2 / 5.1 |
| mix-relay-3k, k/s | 1.96 | 1.89 | 1.94 | 1.93 | 1.89 | 1.89 |
| mix-relay-3k, process / busy CPU µs | 276 / 456 | 305 / 495 | 275 / 455 | 257 / 445 | 294 / 473 | 288 / 481 |
| mix-relay-3k, CPU busy % | 89 | 90 | 90 | 86 | 89 | 90 |
| mix-relay-3k, p50 / p90 / p99 ms | 1,835 / 3,408 / 6,291 | 1,966 / 3,670 / 6,291 | 1,769 / 3,408 / 6,029 | 1,901 / 3,539 / 6,291 | 1,966 / 3,670 / 6,291 | 2,032 / 3,801 / 6,554 |
| mix-http-3k, k/s | 1.85 | 1.88 | 1.86 | 1.85 | 1.86 | 1.89 |
| mix-http-3k, process / busy CPU µs | 399 / 536 | 340 / 495 | 417 / 537 | 379 / 527 | 361 / 512 | 336 / 484 |
| mix-http-3k, CPU busy % | 98 | 93 | 99 | 95 | 93 | 92 |
| mix-http-3k, p50 / p90 / p99 ms | 2,097 / 3,801 / 6,291 | 2,097 / 3,801 / 6,554 | 2,097 / 3,801 / 6,291 | 2,097 / 3,932 / 6,291 | 2,097 / 3,932 / 6,554 | 2,097 / 3,801 / 6,291 |
| mix-connect-3k, k/s | 2.02 | 2.02 | 1.97 | 1.97 | 2.00 | 1.98 |
| mix-connect-3k, process / busy CPU µs | 272 / 450 | 247 / 432 | 312 / 479 | 274 / 454 | 284 / 463 | 255 / 437 |
| mix-connect-3k, CPU busy % | 91 | 87 | 94 | 91 | 93 | 86 |
| mix-connect-3k, p50 / p90 / p99 ms | 1,769 / 3,277 / 6,029 | 1,573 / 3,146 / 6,029 | 1,704 / 3,277 / 6,029 | 1,638 / 3,277 / 6,029 | 1,573 / 3,146 / 6,029 | 1,638 / 3,277 / 6,029 |

**ARM (M4), current: 20 Mbit/s, 5 ms, 0.5%**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g6000,3,2 | -s -g6000,3,2 |
|---|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 291 | 290 | 279 | 278 | 278 | 278 |
| stream16, process / busy CPU s/GB | 9.8 / 18.8 | 9.8 / 18.6 | 7.0 / 14.3 | 7.2 / 13.7 | 7.2 / 14.4 | 7.3 / 14.6 |
| mix-relay-3k, k/s | 1.85 | 1.88 | 1.89 | 1.87 | 1.87 | 1.86 |
| mix-relay-3k, process / busy CPU µs | 280 / 474 | 254 / 450 | 273 / 467 | 262 / 456 | 254 / 443 | 254 / 446 |
| mix-relay-3k, CPU busy % | 87 | 84 | 88 | 86 | 83 | 82 |
| mix-relay-3k, p50 / p90 / p99 ms | 2,228 / 3,932 / 6,554 | 2,032 / 3,801 / 6,554 | 2,032 / 3,801 / 6,291 | 2,097 / 3,801 / 6,554 | 2,097 / 3,801 / 6,554 | 2,032 / 3,801 / 6,554 |
| mix-http-3k, k/s | 1.79 | 1.80 | 1.79 | 1.78 | 1.80 | 1.78 |
| mix-http-3k, process / busy CPU µs | 347 / 514 | 324 / 498 | 325 / 493 | 300 / 478 | 313 / 486 | 355 / 528 |
| mix-http-3k, CPU busy % | 92 | 88 | 88 | 87 | 87 | 94 |
| mix-http-3k, p50 / p90 / p99 ms | 2,359 / 4,194 / 6,816 | 2,359 / 4,063 / 6,554 | 2,490 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 | 2,359 / 4,063 / 6,554 | 2,359 / 4,194 / 6,816 |
| mix-connect-3k, k/s | 1.92 | 1.96 | 1.92 | 1.95 | 1.93 | 1.91 |
| mix-connect-3k, process / busy CPU µs | 269 / 454 | 257 / 444 | 266 / 452 | 247 / 439 | 266 / 455 | 276 / 462 |
| mix-connect-3k, CPU busy % | 87 | 87 | 87 | 86 | 88 | 88 |
| mix-connect-3k, p50 / p90 / p99 ms | 1,901 / 3,670 / 6,291 | 1,901 / 3,539 / 6,291 | 1,966 / 3,670 / 6,554 | 1,901 / 3,539 / 6,291 | 1,835 / 3,539 / 6,291 | 1,966 / 3,670 / 6,554 |

* Conclusion: for web traffic `-s`, the default, and `-s0` show no
  significant difference; `-s` increases the speed and decreases the CPU
  usage for high-speed large uploads and downloads, especially for traffic
  inside high-speed local networks and virtual environments (the synthetic
  tables above: 3 times the speed at 60-70% less CPU per gigabyte).
* Over these links splice() and copying cost about the same in the mix
  scenarios, within the 7-10% the runs move by; the threefold gains of the
  synthetic tables above come from links with no limit. On streams at 20
  Mbit/s with grace delay, splice() saves a little more than copying
  (`-g8000,2,2`: 2.7 against 3.1 s/GB of process CPU on Intel).
* On the better link grace delay changes nothing on streams, and costs
  6-12% of process CPU through CONNECT on Intel.

### The slow link with longer waits

5 Mbit/s, 25 ms and 1% loss each way, the client with 4 CPUs
(`--cpus cli=0-3,prx=4,srv=5-7`), waits of 2, 10 and 20 ms: at this rate
8000 bytes take 13-17 ms to come, so a 2 ms wait gathers next to nothing; 10
ms caps a copying connection at 13 Mbit/s, 20 ms at 6.5 ([data/](data/)
`*-slow-g.csv`).

**Intel (Skylake)**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g8000,2,10 | -s -g8000,2,10 | -s0 -g8000,2,20 | -s -g8000,2,20 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 58 | 60 | 61 | 57 | 55 | 55 | 50 | 51 |
| stream16, process / busy CPU s/GB | 6.3 / 16.6 | 6.2 / 15.8 | 7.6 / 18.5 | 7.6 / 18.5 | 4.5 / 11.5 | 4.9 / 12.3 | 4.3 / 11.0 | 4.3 / 12.1 |
| mix-relay-3k, k/s | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 |
| mix-relay-3k, process / busy CPU µs | 92 / 301 | 84 / 302 | 94 / 302 | 87 / 304 | 93 / 304 | 88 / 306 | 96 / 313 | 100 / 326 |
| mix-relay-3k, CPU busy % | 90 | 90 | 90 | 91 | 91 | 91 | 93 | 97 |
| mix-relay-3k, p50 / p90 / p99 ms | 102 / 311 / 1,114 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 106 / 328 / 1,180 |
| mix-http-3k, k/s | 2.51 | 2.88 | 2.77 | 2.94 | 2.98 | 2.82 | 2.89 | 2.51 |
| mix-http-3k, process / busy CPU µs | 179 / 413 | 161 / 376 | 173 / 387 | 151 / 357 | 161 / 360 | 161 / 379 | 169 / 376 | 173 / 419 |
| mix-http-3k, CPU busy % | 105 | 107 | 105 | 105 | 107 | 107 | 108 | 105 |
| mix-http-3k, p50 / p90 / p99 ms | 1,376 / 2,097 / 4,063 | 885 / 1,704 / 3,539 | 786 / 1,573 / 3,277 | 557 / 1,507 / 4,063 | 377 / 1,180 / 3,670 | 950 / 1,704 / 4,063 | 819 / 1,638 / 3,670 | 1,049 / 1,901 / 4,456 |
| mix-connect-3k, k/s | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 |
| mix-connect-3k, process / busy CPU µs | 91 / 304 | 85 / 298 | 102 / 319 | 95 / 315 | 89 / 297 | 87 / 299 | 87 / 295 | 88 / 308 |
| mix-connect-3k, CPU busy % | 91 | 89 | 95 | 94 | 88 | 89 | 88 | 92 |
| mix-connect-3k, p50 / p90 / p99 ms | 102 / 311 / 1,114 | 102 / 311 / 1,180 | 106 / 328 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 |

**ARM (M4)**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g8000,2,10 | -s -g8000,2,10 | -s0 -g8000,2,20 | -s -g8000,2,20 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 56 | 56 | 54 | 53 | 51 | 49 | 47 | 48 |
| stream16, process / busy CPU s/GB | 21.3 / 52.1 | 23.0 / 53.8 | 29.9 / 51.4 | 30.1 / 49.3 | 19.6 / 44.8 | 22.5 / 47.6 | 18.7 / 42.4 | 19.7 / 44.4 |
| mix-relay-3k, k/s | 1.74 | 1.80 | 1.80 | 1.81 | 1.81 | 1.78 | 1.75 | 1.71 |
| mix-relay-3k, process / busy CPU µs | 366 / 550 | 286 / 478 | 284 / 470 | 296 / 486 | 289 / 487 | 333 / 522 | 361 / 540 | 375 / 557 |
| mix-relay-3k, CPU busy % | 96 | 86 | 85 | 88 | 88 | 93 | 94 | 95 |
| mix-relay-3k, p50 / p90 / p99 ms | 2,621 / 4,456 / 6,816 | 2,359 / 4,194 / 6,554 | 2,359 / 4,194 / 6,554 | 2,359 / 4,194 / 6,554 | 2,359 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 | 2,490 / 4,194 / 6,816 | 2,490 / 4,456 / 6,816 |
| mix-http-3k, k/s | 1.68 | 1.70 | 1.65 | 1.67 | 1.70 | 1.68 | 1.68 | 1.71 |
| mix-http-3k, process / busy CPU µs | 420 / 582 | 385 / 550 | 476 / 618 | 397 / 560 | 434 / 584 | 411 / 581 | 451 / 590 | 368 / 536 |
| mix-http-3k, CPU busy % | 99 | 94 | 101 | 95 | 99 | 95 | 100 | 92 |
| mix-http-3k, p50 / p90 / p99 ms | 2,753 / 4,456 / 6,816 | 2,621 / 4,456 / 7,078 | 2,884 / 4,719 / 7,078 | 2,884 / 4,456 / 7,078 | 2,621 / 4,456 / 6,816 | 2,621 / 4,456 / 7,078 | 2,884 / 4,719 / 6,816 | 2,753 / 4,456 / 7,078 |
| mix-connect-3k, k/s | 1.78 | 1.77 | 1.76 | 1.77 | 1.80 | 1.81 | 1.80 | 1.79 |
| mix-connect-3k, process / busy CPU µs | 291 / 484 | 325 / 515 | 326 / 514 | 329 / 517 | 305 / 494 | 289 / 487 | 300 / 492 | 316 / 510 |
| mix-connect-3k, CPU busy % | 86 | 91 | 90 | 91 | 89 | 86 | 88 | 91 |
| mix-connect-3k, p50 / p90 / p99 ms | 2,359 / 4,194 / 6,816 | 2,490 / 4,194 / 7,078 | 2,359 / 4,194 / 6,816 | 2,490 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 | 2,359 / 4,194 / 6,554 | 2,359 / 4,194 / 6,816 |

* 16 streams, held by the loss to 50-61 Mbit/s: a wait matched to the rate
  pays. 10 ms takes 21-29% off the process CPU per gigabyte on Intel for 5-8%
  of the throughput; 20 ms 31-32% for 12-17%; 2 ms adds 21-23%.
* The mix scenarios do not change with the setting beyond the noise. As an
  HTTP proxy at 3000 exchanges a second the proxy's CPU ran out in every
  configuration on Intel (2.5-3.0k a second, p90 1.2-2.1 s), with no
  setting consistently ahead.
* ARM's client again set the pace of the mix (1.7-1.8k a second); 3
  exchanges were lost there (`mix-connect-3k` and `mix-relay-3k`), none on
  Intel.

### The slow link, two CPUs for the proxy

The same, with the client's 4 CPUs kept and a second CPU for the proxy
(`--cpus cli=0-3,prx=4-5,srv=6-7`), so that the HTTP proxy is not held by
its CPU ([data/](data/) `*-slow-gp2.csv`). "CPU busy" is of both of the
proxy's CPUs, 200% for both full.

**Intel (Skylake)**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g8000,2,10 | -s -g8000,2,10 | -s0 -g8000,2,20 | -s -g8000,2,20 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 59 | 60 | 57 | 58 | 57 | 55 | 51 | 54 |
| stream16, process / busy CPU s/GB | 8.3 / 20.8 | 8.1 / 20.2 | 9.9 / 24.2 | 9.1 / 22.7 | 5.5 / 13.9 | 5.9 / 14.6 | 5.2 / 13.4 | 5.4 / 13.6 |
| mix-relay-3k, k/s | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 |
| mix-relay-3k, process / busy CPU µs | 103 / 351 | 95 / 342 | 119 / 358 | 105 / 342 | 107 / 346 | 108 / 362 | 104 / 329 | 95 / 337 |
| mix-relay-3k, CPU busy % | 105 | 102 | 107 | 102 | 103 | 108 | 98 | 100 |
| mix-relay-3k, p50 / p90 / p99 ms | 98.3 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,114 | 102 / 311 / 1,180 | 102 / 311 / 1,180 |
| mix-http-3k, k/s | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 |
| mix-http-3k, process / busy CPU µs | 137 / 367 | 135 / 373 | 160 / 417 | 135 / 394 | 140 / 377 | 144 / 392 | 147 / 379 | 134 / 378 |
| mix-http-3k, CPU busy % | 109 | 111 | 124 | 117 | 112 | 117 | 113 | 113 |
| mix-http-3k, p50 / p90 / p99 ms | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,114 | 102 / 311 / 1,180 | 102 / 311 / 1,114 | 102 / 311 / 1,180 | 102 / 311 / 1,180 |
| mix-connect-3k, k/s | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 | 2.98 |
| mix-connect-3k, process / busy CPU µs | 97 / 335 | 91 / 330 | 113 / 350 | 98 / 337 | 111 / 354 | 105 / 345 | 99 / 325 | 108 / 352 |
| mix-connect-3k, CPU busy % | 100 | 98 | 104 | 100 | 106 | 103 | 97 | 105 |
| mix-connect-3k, p50 / p90 / p99 ms | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 | 102 / 311 / 1,180 |

**ARM (M4)**

| | -s0 | -s | -s0 -g8000,2,2 | -s -g8000,2,2 | -s0 -g8000,2,10 | -s -g8000,2,10 | -s0 -g8000,2,20 | -s -g8000,2,20 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| stream16, Mbit/s | 55 | 57 | 53 | 53 | 54 | 53 | 49 | 46 |
| stream16, process / busy CPU s/GB | 26.9 / 66.8 | 26.2 / 66.8 | 34.9 / 67.2 | 34.5 / 63.1 | 23.6 / 48.4 | 23.4 / 47.6 | 22.6 / 43.2 | 24.5 / 48.9 |
| mix-relay-3k, k/s | 1.81 | 1.77 | 1.78 | 1.77 | 1.72 | 1.76 | 1.75 | 1.76 |
| mix-relay-3k, process / busy CPU µs | 340 / 629 | 369 / 678 | 375 / 669 | 363 / 667 | 438 / 736 | 362 / 670 | 405 / 691 | 378 / 682 |
| mix-relay-3k, CPU busy % | 114 | 120 | 118 | 118 | 127 | 118 | 121 | 120 |
| mix-relay-3k, p50 / p90 / p99 ms | 2,359 / 4,194 / 6,554 | 2,490 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 | 2,490 / 4,194 / 6,816 | 2,621 / 4,456 / 7,078 | 2,490 / 4,194 / 6,816 | 2,490 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 |
| mix-http-3k, k/s | 1.70 | 1.74 | 1.74 | 1.74 | 1.74 | 1.67 | 1.66 | 1.73 |
| mix-http-3k, process / busy CPU µs | 472 / 737 | 395 / 671 | 401 / 685 | 391 / 662 | 397 / 658 | 478 / 757 | 478 / 764 | 383 / 666 |
| mix-http-3k, CPU busy % | 125 | 117 | 120 | 116 | 115 | 127 | 127 | 114 |
| mix-http-3k, p50 / p90 / p99 ms | 2,621 / 4,456 / 7,078 | 2,621 / 4,456 / 6,816 | 2,621 / 4,456 / 6,816 | 2,621 / 4,456 / 6,816 | 2,621 / 4,456 / 6,816 | 2,753 / 4,719 / 7,078 | 2,621 / 4,719 / 7,078 | 2,490 / 4,456 / 6,816 |
| mix-connect-3k, k/s | 1.77 | 1.81 | 1.78 | 1.74 | 1.78 | 1.75 | 1.77 | 1.74 |
| mix-connect-3k, process / busy CPU µs | 367 / 662 | 329 / 626 | 409 / 694 | 473 / 769 | 388 / 668 | 416 / 722 | 358 / 654 | 412 / 700 |
| mix-connect-3k, CPU busy % | 117 | 113 | 123 | 134 | 119 | 126 | 116 | 122 |
| mix-connect-3k, p50 / p90 / p99 ms | 2,359 / 4,194 / 6,816 | 2,228 / 4,063 / 6,816 | 2,359 / 4,194 / 6,816 | 2,490 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 | 2,228 / 4,194 / 6,816 | 2,359 / 4,194 / 6,816 | 2,490 / 4,194 / 6,816 |

* With two CPUs the HTTP proxy kept the 3000 exchanges a second in every
  configuration on Intel, at the latency of the relay (p90 311 ms).
* The settings rank as with one: on streams 10 ms takes 27-34% off the
  process CPU per gigabyte for 3-8% of the throughput, 20 ms 33-37% for
  10-14%, 2 ms adds 12-19%. In the mix a 2 ms wait adds up to 17% per
  exchange; 10 and 20 ms move it by less than the runs do.
* On two CPUs the proxy spends 7-13% more process CPU per exchange as a
  relay and through CONNECT than on one, the cost of spreading its threads.
* ARM's client set the pace of the mix again (1.7-1.8k a second); 1 exchange
  was lost there, none on Intel.

### CONNECT at 10 Mbit/s

Intel only: 10 Mbit/s, 10 ms and 0.5% loss each way, two CPUs for the proxy
(`--cpus cli=0-3,prx=4-5,srv=6-7`), `mix-connect-3k` only ([data/](data/)
`skylake-10m-connect.csv`); each cell the three runs.

| | -s0 | -s | -s0 -g8000,2,5 | -s -g8000,2,5 |
|---|---:|---:|---:|---:|
| exchanges a second | 2.98k | 2.98k | 2.98k | 2.98k |
| CPU busy, % of 200 | 98, 98, 105 | 94, 96, 100 | 96, 96, 101 | 94, 97, 102 |
| process CPU µs per exchange | 104, 108, 114 | 98, 98, 102 | 97, 103, 111 | 97, 100, 105 |
| p50 / p90 / p99 ms | 41 / 123-127 / 508 | 41 / 123-127 / 508 | 41 / 127 / 508 | 41 / 127 / 508 |

* `-s` takes about 9% off the process CPU per exchange; a wait matched to
  the rate (5 ms: 8000 bytes take about 6 ms to come) changes nothing beyond
  the spread of the runs, as on the other links, and no setting moves the
  latency.

### splice() heuristics in the mix

Intel only, `-s` (the default, `-s:16384,2,4096`) against `-s:8192`, which
splices after two reads of 8K rather than 16K: the mix scenarios, whose
answers have a median of 12K, unshaped and over the 20 Mbit/s, 5 ms, 0.5%
loss link with 5 client CPUs ([data/](data/) `skylake-mixsh-*.csv`); process
CPU per exchange, three runs each.

| scenario | -s | -s:8192 |
|---|---:|---:|
| mix-relay, unshaped | 62-65 µs | 61-65 µs |
| mix-http, unshaped | 96-100 µs | 93-104 µs |
| mix-connect, unshaped | 61-62 µs | 61-64 µs |
| mix-connect-3k, unshaped | 76-88 µs | 77-93 µs |
| mix-http-3k, 20 Mbit/s | 122-143 µs, p99 0.8 s | 152-172 µs, p99 3.1 s |
| mix-relay-3k, mix-connect-3k, 20 Mbit/s | 80-94 µs | 80-98 µs |

* Splicing the 8-16K exchanges too is never better and, as an HTTP proxy on
  the slow link, costs 20% more CPU and a longer tail: the default stays.

### The TLS splice() threshold

Intel only, splicing over kernel TLS (`ssl_ktls`): from a TLS socket a read
of SMALL counts as large, 4K by default (`-s`), against 8K
(`-s:16384,2,8192`) and 16K (`-s:16384,2,16384`), in the new
`tls-term-ka-2k-50k-2000` and `tls-init-ka-2k-50k-2000` scenarios (2000
clients, a 2K POST and a 50K answer each) over 20, 10 and 5 Mbit/s links
(5 ms 0.5%, 10 ms 0.5%, 25 ms 1% loss), 5 client CPUs ([data/](data/)
`skylake-tls8-*.csv`). The proxy's CPU was 99-100% busy in every run, so
the requests a second and the process CPU per request compare.

| link, scenario | 4K (default) | 8K | 16K |
|---|---|---|---|
| 20 Mbit/s, term | 5.3-5.6k/s, 107-111 µs | 5.5-5.8k/s, 105-108 µs | 5.4-5.5k/s, 106-108 µs |
| 20 Mbit/s, init | 4.3-4.4k/s, 122-123 µs | 4.0-4.4k/s, 121-131 µs | 4.2-4.3k/s, 124-129 µs |
| 10 Mbit/s, term | 4.4-5.0k/s, 111-124 µs | 4.7-4.9k/s, 112-117 µs | 4.8-4.9k/s, 113-116 µs |
| 10 Mbit/s, init | 4.0-4.2k/s, 128-134 µs | 4.1k/s, 130-131 µs | 4.0-4.1k/s, 129-134 µs |
| 5 Mbit/s, term | 3.7-3.9k/s, 129-136 µs | 3.6k/s, 139-141 µs | 3.4-3.7k/s, 133-146 µs |
| 5 Mbit/s, init | 3.0-3.4k/s, 154-171 µs | 2.6-3.3k/s, 158-201 µs | 3.1-3.2k/s, 162-169 µs |

* At 20 and 10 Mbit/s the three cannot be told apart; at 5 Mbit/s 4K is a
  little ahead (5-7% less CPU per request ending TLS): the default stays.

## Earlier sessions

The morning session of 13 October ([data/](data/) `*-16k-*.csv`, `*-mix.csv`)
ran devel before the half-close fix, the idle buffer release and the TLS
changes, 1.0.1 without TCP_NODELAY and nginx relays without
`proxy_half_close`, and had no envoy. Its ARM figures are 5-15% lower for
every proxy alike, probably because two stray 3proxy processes were spinning
on the host's CPUs at the time.

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

## Caveats

* Every scenario but the mix ones is synthetic: the links between the
  client, the proxy and the origin have no bandwidth limit and no delay, and
  one or a few kinds of request are repeated, so each connection goes as fast
  as the CPUs allow. The mix scenarios, many connections with web-like
  exchanges, and above all over the emulated links of the grace delay
  section, are the closest to a proxy giving clients access to the Internet.
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

