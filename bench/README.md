# Benchmarks

Compares the speed and the cost of 3proxy versions, and of other proxies doing
the same job, on Linux.

Results of the latest comparison, with the setup they were measured on, are
in [RESULTS.md](RESULTS.md); the measurements are in [data/](data/).

## How the measurement is isolated

The client, the proxy and the origin each run in a network namespace of
their own, linked by veth pairs:

```
[bcli] 10.0.1.2 --veth-- 10.0.1.1 [bprx] 10.0.2.1 --veth-- 10.0.2.2 [bsrv]
 wrk, iperf3              the proxy              nginx (files), iperf3 -s
```

so they share no loopback, and a packet crosses the same path whichever proxy
is measured. Each role also runs in a cgroup of its own pinned to separate
CPUs (`--cpus`, default `cli=0-3,prx=4,srv=5-7` for 8 CPUs), so one does not
take CPU from another, and RPS steers what each veth receives to the
receiver's CPUs, so the kernel's network work for a role is done on its own
CPUs too. The proxy's cgroup is created anew for every run, which is what
makes its peak memory readable on its own.

The proxy gets the fewest CPUs on purpose: the measurement is about the proxy,
so it has to be what runs out first. Every proxy is given the same CPUs: nginx
gets as many workers and haproxy as many threads as the proxy has CPUs;
3proxy runs a thread per connection inside the same cpuset. Logging is off
everywhere.

CPU time is the busy time of a role's CPUs read from `/proc/stat`: its
processes and the interrupts and softirqs handled there. The cgroup's own CPU
time is not enough: a kernel with `CONFIG_IRQ_TIME_ACCOUNTING` leaves the
softirqs out of it, and that is where much of the network work is done (a
quarter of a proxy's CPU in these tests).

Every run records which side set its pace (`bound`): the role whose CPUs were
busy at least 90% of the time, or which had a thread doing so (an iperf3
stream is one thread, so one busy core is its limit however many CPUs the
role has). A run bound by the client or the origin says only that the proxy
can do at least that much.

`none` is no proxy at all: the client reaches the origin through the proxy
namespace with the kernel forwarding, the upper bound for every scenario.

Each run also takes the next of eight addresses for the proxy to connect from
(10.0.2.10-17), and the `mix-*` client the next of eight sets of sixteen
(10.0.1.100-227). Connections left in TIME_WAIT by a run, tens of thousands
of them when a run opens many, are then not between the addresses the next
runs use, and have expired by the time an address is taken again; without
that, a run after one which opened as many connections finds the kernel
searching for a free port on every connect.

## What is reported

For every run, in a CSV under `bench/results/`:

| column | meaning |
|---|---|
| `gbit`, `rate` | throughput, requests per second for HTTP |
| `p50_ms`, `p99_ms` | latency from wrk (closed loop: compare at equal load only) |
| `prx_cpu_s`, `prx_task_s` | busy CPU seconds of the proxy's CPUs, network work included; the CPU time of its processes alone |
| `cpu_s_per_gb`, `cpu_us_per_req` | the proxy's cost per unit of work: the fairest figure, least affected by which side was the limit |
| `peak_mb` | the proxy's peak memory |
| `cli_util`, `prx_util`, `srv_util` | how busy each role's CPUs were |
| `cli_thread`, `srv_thread` | the busiest client and origin thread, as a share of one CPU |
| `bound` | `proxy`, `client`, `origin`, or `none` when nothing was busy all the time |
| `errors`, `timeouts`, `retrans` | socket errors and non-2xx answers; requests slower than wrk's 2 seconds; TCP retransmissions in the stream scenarios |

Repetitions rotate the order of the proxies, so drift over time (heat, the
host) falls on all of them alike; the summary gives medians.

## Scenarios

| name | load |
|---|---|
| `stream1`, `stream1-down` | one iperf3 stream through a TCP relay (3proxy `tcppm`, nginx `stream`, haproxy `mode tcp`), upload and download |
| `stream16` | sixteen streams |
| `http-ka-1k`, `http-ka-1m` | HTTP over kept-alive connections through an HTTP proxy (absolute URIs), 1 KB and 1 MB answers |
| `http-ka-50k-2000` | 2000 clients at once, GET answered with 50 KB |
| `http-ka-2k-50k-2000` | the same, each request a POST with a 2 KB body |
| `http-close-1k` | a new connection for every request |
| `connect-*` | the same loads through CONNECT tunnels: wrk and iperf3 run under proxychains-ng, so every connection they make asks the proxy for a tunnel to the origin (`connect-close-1k`: a tunnel for every request) |
| `socks-*` | the same through SOCKSv5 |
| `relay-*` | the same through a TCP relay to a fixed destination: 3proxy `tcppm`, nginx `stream`, haproxy `mode tcp` |
| `mix-http`, `mix-connect`, `mix-socks`, `mix-relay` | a pool of connections open through the proxy and exchanges on random ones of them (see below), `--mix-active` of them going at once all the time |
| `mix-*-3k` | the same, exchanges started at 3000 a second whether the proxy keeps up or not: latencies compared at equal load |
| `tls-term-ka-1k`, `tls-term-ka-1m`, `tls-term-close-1k` | TLS ended by the proxy: wrk speaks HTTPS to a relay of the proxy, which passes plain TCP to the origin; kept-alive connections with 1 KB and 1 MB answers, and a new connection, so a full handshake, for every request |
| `tls-init-*` | TLS begun by the proxy: wrk speaks plain HTTP to a relay, which connects to the origin's HTTPS listener |
| `tls-term-stream1-down`, `tls-term-stream16`, `tls-init-stream1-down`, `tls-init-stream16` | the same with iperf3 streams, one downloading or sixteen uploading |

### The mix scenarios

Every other scenario repeats one request, or one stream, on every
connection. The `mix-*` ones are closer to what a proxy serving many remote
clients sees, with `bench/mix`, a load generator and an origin in Go:

* `--mix-pool` connections (20000) are opened through the proxy before the
  measurement starts, as HTTP proxy connections, CONNECT or SOCKSv5 tunnels or
  through a relay, from sixteen client addresses, and kept open; each goes to
  one of sixteen ports of the origin and keeps to it, through an HTTP proxy
  too, as a tunnel has to;
* each exchange goes to a connection drawn at random from the pool (the next
  idle one if that one is busy): a request with headers of 200 bytes to 4 KB,
  one in ten a POST with a body of up to 1 MB (median 4 KB), and an answer
  drawn from a lognormal distribution with a median of 12 KB, up to 8 MB;
* both sides write in pieces of random sizes with short random pauses between
  them, and the client reads in amounts of its own, now and then slowly, so
  data reaches the proxy in parts and buffers fill up at times;
* the profile is not fitted to measured traffic: sizes are lognormal, the
  shape web workload models use for them (P. Barford, M. Crovella,
  [Generating Representative Web Workloads for Network and Server
  Performance Evaluation](https://doi.org/10.1145/277851.277897), SIGMETRICS
  1998), and the parameters (the medians and spreads in `mix/main.go`, the
  pieces, pauses and how often clients go away) are chosen, not measured;
* connections end and are opened again: a connection carries 15 exchanges on
  average (`-per-conn`, a geometric number), and some end the way clients
  going away end them: 0.5% of exchanges are left with a close before the
  whole answer is in (`-abort`), 0.2% with a reset (`-reset`), before the
  answer or during it, and after 0.5% the client shuts down its sending side
  and reads the answer (`-halfclose`, through tunnels and relays only: an HTTP
  proxy takes that for a client gone). Those left are counted apart, not as
  errors; an answer lost after a half-close is an error. A connection which
  ended is opened again when an exchange next asks for it, and that exchange's
  time includes it.

`mix-relay` asks nothing of the proxy but to copy: each connection is relayed
to the origin, one connection there for one here, by every proxy alike. It
compares how they move data. `mix-http` makes the proxy read and write HTTP
for every exchange as well, and is not the same job for all of them: 3proxy,
tinyproxy and squid are forward proxies, keeping a connection to the server a
client asked for, one for each client connection, while nginx and haproxy
take the requests on a listener of their own (3129) for one backend, the
origin's first port, and share a few connections to it between all the
clients. `mix-connect` and `mix-socks` are relayed like `mix-relay` once the
tunnel is open, the client naming the destination.

The client has a dispatcher for every CPU it has (`-shards`), each with its
share of the pool and of the load: one for all of it would be a single
thread, and the limit of the whole client.

All of it is drawn from `--seed`: what exchange *n* does, the sizes, the
pieces, the pauses and how it ends, on the client and on the origin, is the
same in every run, for every proxy and whatever the number of dispatchers;
only timing differs, and with it which connection an exchange gets when the
one drawn for it is busy.

`rate` is exchanges per second, `p50_ms` and `p99_ms` how long an exchange
took, from the moment it was due (with a fixed rate) to the last byte of its
answer, and `peak_mb` divided by the pool what each open connection costs the
proxy. The binaries are built with `bench/mix/build.sh`, on any system with
Go, for both Linux architectures.

nginx and envoy are not forward proxies: they answer absolute URIs by passing
them to their upstream, which is the origin here. nginx and haproxy have
neither CONNECT nor SOCKS, and envoy is measured as they are, so they take
part in the HTTP and `relay-*` scenarios but not in the `connect-*` and
`socks-*` ones. tinyproxy
and squid are HTTP proxies, measured in the HTTP and `connect-*` scenarios;
dante is a SOCKS server, measured in the `socks-*` ones.

### The TLS scenarios

The `tls-*` scenarios compare TLS done in the proxy: 3proxy (`tcppm` under
`ssl_serv` or `ssl_cli`), nginx (`stream` with `listen ... ssl` and
`proxy_ssl on`), haproxy (`mode tcp` with `bind ... ssl crt` and `server ...
ssl`) and stunnel, which takes part in these scenarios only. Every one relays
TCP: no HTTP is read, so what differs is the TLS and how data is moved around
it. envoy takes part too, with BoringSSL where the others use OpenSSL. The certificate is made for every run: an ECDSA P-256 key signed by a CA
of its own, with the proxy's and the origin's addresses in it; nobody
verifies it. `none` has wrk speak HTTPS to the origin itself.

iperf3 has no TLS of its own, so for the TLS streams `bench/mix tls` wraps
its connections: on the client it begins TLS towards the proxy ending it (or
towards the origin with no proxy), at the origin it ends the TLS a proxy
begins and passes the stream to iperf3. The wrapper is in Go, a goroutine
for each direction of each connection: on one stream it, rather than the
proxy, can be the limit (about 10 Gbit/s a core), which the run's `bound`
shows.

wrk does not resume TLS sessions, so in `tls-term-close-1k` every connection
is a full handshake. Towards the origin a proxy may resume them: nginx
(`proxy_ssl_session_reuse`) and haproxy do by default, so `tls-init-close-1k`
compares that too.

## Running

Root, `iproute2`, `iperf3`, `wrk`, `proxychains4` (proxychains-ng, for the `connect-*` and `socks-*` scenarios), `nginx` (with the stream module:
`libnginx-mod-stream` on Debian and Ubuntu, `nginx-mod-stream` on
RHEL-like systems) and, to compare with it,
`haproxy`; `openssl` for the `tls-*` scenarios, and `stunnel` (`stunnel4` on
Debian and Ubuntu) to compare with it there.

```sh
bench/build.sh 0.9.9.1 1.0.1                      # tags into bench/bin/
NAME=devel bench/build.sh .                       # the working tree
CC="gcc -fcommon" bench/build.sh 0.8.13           # before 0.9, newer gcc
CC="gcc -fpermissive" bench/build.sh 0.9.4        # 0.9.x with gcc 14 and later

sudo bench/bench.py \
    --proxy none \
    --proxy 3proxy:bench/bin/3proxy-1.0.1 \
    --proxy 3proxy:bench/bin/3proxy-devel \
    --proxy "3proxy:bench/bin/3proxy-0.9.4:-s0" \
    --proxy nginx --proxy haproxy
```

`bench/report.py <csv>` turns a run into Markdown tables: throughput, the
proxy's CPU per gigabyte or per request, and its peak memory. With
`--machine NAME=a.csv,b.csv` once per machine it makes a single throughput
table of all of them, each cell their medians and their average; `--overall`
then marks only the best of each row, for tables where one group has a
single proxy.

After the binary, a 3proxy entry can carry options for both its services:
`-s1`, `-s2` and `-s3` splice downloads, uploads or both (`-s0` keeps 0.9.0 to
0.9.8, which use splice() both ways by default, from using it), and
`-ocTCP_NODELAY -osTCP_NODELAY` turns Nagle's algorithm off on the client and
server sockets.

haproxy can be measured with splice() too: `haproxy::splice-auto` lets its
heuristic splice a direction once reads fill the buffer three times in a row;
`haproxy::splice-response`, `haproxy::splice-request` and `haproxy::splice`
always splice the server's data, the client's, or both (`option
splice-response`, `option splice-request`), as 3proxy's `-s1`, `-s2` and `-s3`
do. nginx has no splice() support, so it has no such
variant; `nginx::halfclose` turns on `proxy_half_close` in its relays, which
nginx leaves off: then a client shutting down its sending side still gets the
answer, as through 3proxy and haproxy.

`ktls` asks for kernel TLS in the `tls-*` scenarios: among 3proxy's options
(`3proxy:bench/bin/3proxy:ktls`) it adds `ssl_ktls` before the TLS services,
for nginx (`nginx::ktls`, or `nginx::halfclose+ktls`) it adds `Options KTLS`
to both sides' OpenSSL configuration. Either takes effect only where the
proxy's OpenSSL is built with kernel TLS and the tls module is loaded.

`--proxy stunnel` measures stunnel in the `tls-*` scenarios. `--proxy envoy`
measures envoy where nginx and haproxy are measured: as an HTTP proxy for the
origin (its connections there pooled), as a TCP relay (`tcp_proxy`) and in
the TLS scenarios; its circuit breakers, which allow 1024 connections to a
cluster by default, are lifted for the scenarios that open more. The
official release binaries run as they are (`envoy` on the PATH).

`--scenario` picks scenarios, `--reps` and `--duration` set the repetitions
and their length, `--mtu` changes the links' MTU. Two options make the link
between the client and the proxy more like the clients' links of a real
proxy, both ways: `--netem "delay 5ms loss 0.5%"` adds netem's delay and
loss (`rate` there would be the link's as a whole), `--flow-rate 20mbit`
limits each connection (fq `maxrate`). Both are applied in the client's
namespace, on its way out and on an ifb its way in is redirected through,
so the emulation's work is done on the client's CPUs and not charged to the
proxy. Segmentation offload and GRO are turned off on that link, so that
netem drops single packets: the proxy then sends and receives packets of the
MTU's size, as it would from slow clients, which costs it 2-3 times the CPU
per exchange of a plain veth. Shaped, the client's CPUs set the pace of the
full-load mix scenarios; the fixed-rate `-3k` ones are what compares.

## Caveats

* A virtual machine cannot pin its virtual CPUs to physical ones, so its
  absolute numbers move between sessions: compare within one session, and
  keep absolute figures for real hardware.
* wrk measures latency in a closed loop, so a slower proxy is also offered
  less load; compare latencies only between runs of similar throughput.
* The roles have CPUs of their own but share the memory: memory bandwidth,
  which copying proxies use most, cannot be split, and on some hosts it,
  rather than the CPU, sets the limit. A CPU waiting for memory counts as
  busy, so such a limit shows as less work per busy second.
* Memory is shared too, and has no swap to fall back on in most test
  machines: with the 20000 connections of the `mix-*` scenarios the client
  and the origin take about 2 GB, and a proxy needing several more (dante
  needs 6 GB) can get a process killed by the OOM killer. If it is the
  origin, the run stops at once rather than measuring nothing for the rest
  of it; check `dmesg` for a proxy killed on the way.
* Versions are built with the Makefile they shipped with, so compiler flags
  differ between them (0.8 builds with `-O2`, 0.9.9 and later with
  `-O3 -flto`) as they did for their users.
