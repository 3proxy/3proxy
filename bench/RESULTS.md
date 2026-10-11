# Benchmark results

3proxy 0.9.4, 1.0.1 and devel against nginx and haproxy, measured on two
machines, 11 October 2026. How the benchmark works is in
[README.md](README.md); the measurements are in [data/](data/), and
`bench/report.py` turns them into the tables below.

## In short

* **Bulk TCP, no splice:** devel and 1.0.1 move 19-22 Gbit/s per CPU core,
  1.5 to 2.2 times nginx and haproxy and 2.4 to 3.6 times 0.9.4, at 0.36-0.43
  CPU seconds per gigabyte against 0.59-0.87 for nginx and haproxy.
* **Bulk TCP and large HTTP answers with splice():** 3proxy with splice moves
  1.3 to 2.1 times what it does without, at 40-55% less CPU per gigabyte. On
  the Skylake host it is level with haproxy splicing every connection with TCP
  streams and 11% behind it with 1 MB HTTP answers; on the M4 it is ahead (37.8
  against 22.1 Gbit/s with 16 streams, 35.3 against 28.0 with 1 MB HTTP
  answers). haproxy's own heuristic (`splice-auto`) does not engage for 1 MB
  HTTP answers on the M4 (haproxy 2.8) and stays at its copying speed.
* **Small requests:** nginx and haproxy answer 2 to 3 times more 1 KB requests
  per core over kept-alive connections, and 3 times more when every request
  opens a new connection: 3proxy runs a thread per connection. splice() makes
  small requests slower (13.4-14.9k against 15.8-18.1k requests per second),
  which is why it stays off unless asked for.
* **2000 clients, 50 KB answers:** devel leads the copying proxies on the
  Skylake host (10.5k requests per second against nginx's 9.2k and haproxy's
  7.3k), nginx leads on the M4 (11.0k against devel's 10.4k); haproxy splicing
  every connection is fastest there (11.9k). splice() does not help 3proxy with
  answers this small.
* **1.0.1 against devel:** 1.0.1 manages 6k requests per second over kept-alive
  connections whatever the CPU, held by a 10 ms sleep each time a request is
  answered; devel has it removed and also sets TCP_NODELAY by default.
* **Memory:** with few connections 3proxy needs the least (devel 8-17 MB
  against 30-54 MB for nginx and haproxy; 57 MB when every request opens a new
  connection on the Skylake host); with 2000 connections at once, a thread for
  each costs it 150-200 MB against nginx's 90-113 MB.

## Setup

| | M4 | Skylake |
|---|---|---|
| host | Apple M4 Pro laptop, UTM (Apple Virtualization) | OpenStack virtual machine, KVM |
| virtual machine | 8 CPUs, 8 GB | 8 CPUs (Intel Xeon, Skylake, 2.0 GHz), 8 GB |
| system | Ubuntu 24.04, Linux 6.8, aarch64 | AlmaLinux 10, Linux 6.12, x86_64 |
| nginx | 1.24.0 | 1.26.3 |
| haproxy | 2.8.16 | 3.0.5 |
| wrk, iperf3 | 4.1.0, 3.16 | 4.2.0, 3.17.1 |

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
  3proxy's thread per connection confined to the same CPU.
* **CPU time** is the busy time of the role's CPUs from `/proc/stat`, its own
  processes plus the interrupts and softirqs handled there (a quarter of a
  proxy's time here), so a proxy is also charged for the kernel's work on its
  connections - which is where splice() moves the copying.
* **Which side set the pace** is recorded for every run: the role whose CPUs,
  or one thread of it, were busy at least 90% of the time.
* **Repetitions:** three runs of 10 seconds per proxy and scenario, the order
  of the proxies rotated between repetitions; the tables give medians. The
  haproxy splice columns come from a second session an hour later, with plain
  haproxy run again to see how far the conditions moved: by 2.5% or less on
  the M4 and 7.5% or less on the Skylake host, except for one origin-bound
  case (-9.7%).

### Proxies

| column | configuration |
|---|---|
| 0.9.4 | 0.9.4, `-s0` (no splice) `-ocTCP_NODELAY -osTCP_NODELAY` |
| 1.0.1 | 1.0.1, `-ocTCP_NODELAY -osTCP_NODELAY` (built without splice) |
| devel | devel as of these tests, defaults (TCP_NODELAY is on by default) |
| nginx | `proxy_pass` to an upstream with `keepalive 1024`, `stream` for TCP, `reuseport` |
| haproxy | `mode http` with `http-reuse always`, `mode tcp` for TCP |
| 0.9.4 splice | 0.9.4, which splices by default, `-ocTCP_NODELAY -osTCP_NODELAY` |
| devel splice | devel with `-s` |
| haproxy splice-auto | `option splice-auto`: splices a direction once reads fill the buffer three times in a row |
| haproxy splice | `option splice-request` and `option splice-response`: splices always |

nginx has no splice() support. 3proxy versions are built with the Makefile
they shipped with (`-O3 -flto` for 1.0.1 and devel, `-O2` for 0.9.4, which on
gcc 14 also needs `-fpermissive`). Logging is off everywhere.

### Scenarios

| scenario | load |
|---|---|
| stream1, stream1-down | one iperf3 stream through a TCP relay (3proxy `tcppm`), upload and download |
| stream16 | 16 iperf3 streams |
| http-ka-1k, http-ka-1m | 64 (1 KB) or 16 (1 MB) kept-alive connections through the HTTP proxy |
| http-ka-50k-2000 | 2000 kept-alive connections, 50 KB answers |
| http-close-1k | 64 connections, a new one for every request |

## How to read the tables

* Columns: the client talking to the origin with no proxy (only the kernel
  forwarding, for reference), then the proxies copying through user space,
  then after the second ‖ the proxies using splice().
* **Bold**: the best of its group in the row, and any other of the group whose
  three runs overlap the best one's - the measurement cannot tell them apart.
* ‡: the client or the origin, not the proxy, set the pace in most runs, so the
  proxy can do at least that much. Single streams often end there with
  splice(): one iperf3 stream is one thread, and the proxy needs less of a CPU
  than it.
* CPU is per gigabyte for the bulk scenarios and per request for the small
  ones.
* http-ka-50k-2000: every proxy but haproxy leaves some requests waiting longer
  than wrk's 2 second limit (counted as timeouts in the data, 140-540 a run);
  haproxy serves the 2000 connections more evenly, with none over 2 seconds but
  a median wait 2 to 3 times longer.

## M4 (Apple M4 Pro, virtual machine)

#### Throughput, Gbit/s (thousands of requests per second for HTTP)

| scenario | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1 | 62.0 | ‖ | 8.3 | **22.1** | **22.0** | 13.5 | 13.6 | ‖ | 25.1 | **45.7 ‡** | 29.5 | **44.7** |
| stream16 | 141.2 | ‖ | 8.7 | **20.9** | **20.9** | 13.5 | 9.5 ‡ | ‖ | 24.5 | **37.8 ‡** | 15.9 ‡ | 22.1 ‡ |
| stream1-down | 61.8 | ‖ | 8.8 | **22.4** | **22.1** | 13.6 | 13.6 | ‖ | **47.9 ‡** | **47.4 ‡** | 30.4 | **47.6 ‡** |
| http-ka-1k | 1.24 (120.3k/s) | ‖ | 0.14 (14.1k/s) | 0.06 (6.0k/s) | 0.16 (15.8k/s) | 0.38 (37.0k/s) | **0.45 (44.3k/s)** | ‖ | 0.14 (13.4k/s) | 0.15 (14.9k/s) | **0.45 (44.1k/s)** | **0.45 (44.1k/s)** |
| http-ka-1m | 71.55 (8.5k/s) | ‖ | 8.33 (1.0k/s) | 12.46 (1.5k/s) | **21.90 (2.6k/s) ‡** | 12.63 (1.5k/s) | 6.02 (0.7k/s) ‡ | ‖ | 32.99 (3.9k/s) ‡ | **35.30 (4.2k/s) ‡** | 5.91 (0.7k/s) ‡ | 28.00 (3.3k/s) ‡ |
| http-ka-50k-2000 | 34.79 (84.5k/s) | ‖ | 3.12 (7.6k/s) | 3.69 (9.0k/s) | 4.27 (10.4k/s) | **4.55 (11.0k/s)** | 4.01 (9.6k/s) | ‖ | 3.73 (9.1k/s) | 4.07 (9.9k/s) | 4.00 (9.6k/s) | **4.92 (11.9k/s)** |
| http-close-1k | 0.50 (48.7k/s) | ‖ | 0.05 (5.0k/s) | 0.05 (4.4k/s) | 0.05 (5.2k/s) | 0.14 (13.3k/s) | **0.17 (16.6k/s)** | ‖ | 0.05 (4.8k/s) | 0.05 (5.0k/s) | **0.17 (16.7k/s)** | **0.17 (16.8k/s)** |

#### Proxy CPU time per gigabyte or per request

| scenario | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1 | – | ‖ | 0.96 s/GB | **0.36 s/GB** | **0.36 s/GB** | 0.59 s/GB | 0.59 s/GB | ‖ | 0.32 s/GB | **0.17 s/GB** | 0.27 s/GB | **0.18 s/GB** |
| stream16 | – | ‖ | 0.92 s/GB | **0.38 s/GB** | **0.38 s/GB** | 0.59 s/GB | 0.84 s/GB | ‖ | 0.33 s/GB | **0.21 s/GB** | 0.51 s/GB | 0.36 s/GB |
| stream1-down | – | ‖ | 0.91 s/GB | **0.36 s/GB** | **0.36 s/GB** | 0.59 s/GB | 0.59 s/GB | ‖ | **0.17 s/GB** | **0.17 s/GB** | 0.26 s/GB | **0.17 s/GB** |
| http-ka-1k | – | ‖ | 71 µs/req | 105 µs/req | 63 µs/req | 27 µs/req | **23 µs/req** | ‖ | 74 µs/req | 67 µs/req | **23 µs/req** | **23 µs/req** |
| http-ka-1m | – | ‖ | 0.96 s/GB | 0.44 s/GB | **0.37 s/GB** | 0.64 s/GB | 1.34 s/GB | ‖ | 0.24 s/GB | **0.23 s/GB** | 1.37 s/GB | 0.29 s/GB |
| http-ka-50k-2000 | – | ‖ | 2.67 s/GB | 2.27 s/GB | 1.95 s/GB | **1.79 s/GB** | 2.01 s/GB | ‖ | 2.23 s/GB | 2.04 s/GB | 2.02 s/GB | **1.65 s/GB** |
| http-close-1k | – | ‖ | 201 µs/req | 227 µs/req | 194 µs/req | 75 µs/req | **60 µs/req** | ‖ | 208 µs/req | 200 µs/req | **60 µs/req** | **60 µs/req** |

#### Proxy peak memory, MB

| scenario | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1 | – | ‖ | **2** | 10 | 8 | 32 | 32 | ‖ | **5** | 11 | 44 | 45 |
| stream16 | – | ‖ | **31** | 75 | 63 | 75 | 48 | ‖ | **61** | 85 | **60** | **56** |
| stream1-down | – | ‖ | **2** | 6 | 10 | 34 | 31 | ‖ | **11** | 11 | 40 | 45 |
| http-ka-1k | – | ‖ | **5** | 9 | 9 | 30 | 30 | ‖ | **5** | 9 | 36 | 36 |
| http-ka-1m | – | ‖ | **11** | **10** | 16 | 45 | 39 | ‖ | **15** | **17** | 44 | 52 |
| http-ka-50k-2000 | – | ‖ | 126 | 199 | 194 | **90** | 176 | ‖ | **97** | 187 | 182 | 136 |
| http-close-1k | – | ‖ | **10** | 31 | 14 | 30 | 30 | ‖ | **10** | 12 | 36 | 36 |


## Skylake (Intel Xeon, OpenStack virtual machine)

#### Throughput, Gbit/s (thousands of requests per second for HTTP)

| scenario | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1 | 44.4 | ‖ | 5.5 | 19.1 | **19.9** | 9.8 | 9.7 | ‖ | **29.2** | **31.4** | **30.6** | **32.3** |
| stream16 | 150.5 | ‖ | 5.6 | **18.9** | **18.8** | 9.9 | 9.2 | ‖ | 28.3 | **31.2** | **30.3 ‡** | **31.5 ‡** |
| stream1-down | 43.1 | ‖ | 5.6 | **18.8** | **19.4** | 9.7 | 9.3 | ‖ | **34.4** | 32.0 | 31.0 | **33.7** |
| http-ka-1k | 1.30 (127.1k/s) | ‖ | 0.19 (19.2k/s) | 0.06 (6.1k/s) | 0.18 (18.1k/s) | **0.37 (36.5k/s)** | **0.37 (37.3k/s)** | ‖ | 0.15 (14.6k/s) | 0.14 (13.8k/s) | **0.37 (37.2k/s)** | **0.38 (38.0k/s)** |
| http-ka-1m | 67.52 (8.0k/s) | ‖ | 5.84 (0.7k/s) | 12.37 (1.5k/s) | **18.30 (2.2k/s) ‡** | 5.77 (0.7k/s) | 7.56 (0.9k/s) | ‖ | **26.63 (3.2k/s) ‡** | 23.88 (2.8k/s) ‡ | 24.22 (2.9k/s) ‡ | **26.71 (3.2k/s) ‡** |
| http-ka-50k-2000 | 35.30 (85.7k/s) | ‖ | 2.89 (7.0k/s) | 4.24 (10.3k/s) | **4.33 (10.5k/s)** | 3.77 (9.2k/s) | 3.01 (7.3k/s) | ‖ | **3.89 (9.4k/s)** | 3.71 (9.0k/s) | 3.19 (7.7k/s) | **3.72 (9.0k/s)** |
| http-close-1k | 0.53 (52.1k/s) | ‖ | 0.05 (4.8k/s) | 0.04 (4.0k/s) | 0.05 (4.8k/s) | 0.13 (12.9k/s) | **0.15 (15.1k/s)** | ‖ | 0.04 (4.4k/s) | 0.04 (4.4k/s) | **0.15 (15.1k/s)** | **0.16 (15.5k/s)** |

#### Proxy CPU time per gigabyte or per request

| scenario | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1 | – | ‖ | 1.45 s/GB | 0.42 s/GB | **0.40 s/GB** | 0.82 s/GB | 0.82 s/GB | ‖ | **0.27 s/GB** | **0.25 s/GB** | **0.26 s/GB** | **0.25 s/GB** |
| stream16 | – | ‖ | 1.43 s/GB | **0.42 s/GB** | **0.43 s/GB** | 0.81 s/GB | 0.87 s/GB | ‖ | 0.28 s/GB | **0.26 s/GB** | **0.26 s/GB** | **0.25 s/GB** |
| stream1-down | – | ‖ | 1.43 s/GB | **0.43 s/GB** | **0.41 s/GB** | 0.82 s/GB | 0.86 s/GB | ‖ | **0.23 s/GB** | 0.25 s/GB | 0.26 s/GB | **0.24 s/GB** |
| http-ka-1k | – | ‖ | 52 µs/req | 72 µs/req | 55 µs/req | **27 µs/req** | **27 µs/req** | ‖ | 68 µs/req | 72 µs/req | **27 µs/req** | **26 µs/req** |
| http-ka-1m | – | ‖ | 1.37 s/GB | 0.53 s/GB | **0.44 s/GB** | 1.39 s/GB | 1.07 s/GB | ‖ | **0.30 s/GB** | 0.34 s/GB | 0.33 s/GB | **0.30 s/GB** |
| http-ka-50k-2000 | – | ‖ | 2.88 s/GB | 1.98 s/GB | **1.93 s/GB** | 2.15 s/GB | 2.70 s/GB | ‖ | **2.15 s/GB** | 2.26 s/GB | 2.55 s/GB | **2.18 s/GB** |
| http-close-1k | – | ‖ | 211 µs/req | 250 µs/req | 210 µs/req | 77 µs/req | **66 µs/req** | ‖ | 229 µs/req | 230 µs/req | **66 µs/req** | **65 µs/req** |

#### Proxy peak memory, MB

| scenario | no proxy | ‖ | 0.9.4 | 1.0.1 | devel | nginx | haproxy | ‖ | 0.9.4 splice | devel splice | haproxy splice-auto | haproxy splice |
|---|---:|:-:|---:|---:|---:|---:|---:|:-:|---:|---:|---:|---:|
| stream1 | – | ‖ | **2** | 5 | 8 | 34 | 30 | ‖ | 10 | **8** | 44 | 42 |
| stream16 | – | ‖ | 93 | 96 | 91 | 107 | **59** | ‖ | 79 | 88 | 107 | **62** |
| stream1-down | – | ‖ | **3** | 8 | 8 | 32 | 31 | ‖ | **9** | 11 | 43 | 46 |
| http-ka-1k | – | ‖ | **5** | 10 | 10 | 32 | 32 | ‖ | **5** | 10 | 37 | 40 |
| http-ka-1m | – | ‖ | **14** | **14** | 17 | 45 | 45 | ‖ | **15** | **18** | 54 | 53 |
| http-ka-50k-2000 | – | ‖ | 185 | 137 | **153** | **113** | 178 | ‖ | **91** | 160 | 185 | 195 |
| http-close-1k | – | ‖ | **16** | 23 | 57 | 31 | 29 | ‖ | **22** | 42 | 40 | 38 |


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
* The haproxy versions differ between the machines (2.8 and 3.0).

