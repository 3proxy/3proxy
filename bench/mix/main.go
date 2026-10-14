// mix is a load generator and an origin for proxy benchmarks closer to real
// traffic than one request repeated: a pool of connections open through the
// proxy, exchanges on connections drawn at random from it, requests and
// answers of sizes drawn from a web-like profile, written and read in pieces
// of random sizes with pauses between them.
//
//	mix origin -listen 10.0.2.2:8090
//	mix client -via connect -proxy 10.0.1.1:3128 -origin 10.0.2.2:8090 \
//	    -pool 20000 -active 2000 -duration 10
//
// It speaks HTTP/1.1 everywhere: absolute URIs to an HTTP proxy, origin-form
// requests through CONNECT and SOCKSv5 tunnels, a TCP relay or straight to
// the origin. A request names the size of its answer and a seed, from which
// the origin draws how it writes it.
//
// Replayable: what exchange i does, which connection it asks for, the sizes,
// the pieces and the pauses, comes from a generator seeded by -seed and i,
// and so does how the origin answers it. Only timing differs between runs,
// and with it which connection an exchange gets when the one it asked for is
// busy: the next idle one after it.
//
// The client prints READY once the pool is open and warmed up, then after
// -duration a JSON summary of the exchanges completed in between.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- a TLS wrapper ---------------------------------------------------------------

// wrap relays connections to listen to target, with TLS on one side: given a
// certificate it takes TLS and passes plain TCP on (the end of a TLS stream
// at the origin), without one it takes plain TCP and begins TLS (for a client
// with no TLS of its own, iperf3). A side shut down for writing is shut down
// on the other side too, so half-closed connections work.
func wrap(listen, target, cert, key string) error {
	var server *tls.Config
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return err
		}
		server = &tls.Config{Certificates: []tls.Certificate{pair}}
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			var in, out net.Conn = c, nil
			var err error
			if server != nil {
				in = tls.Server(c, server)
				out, err = net.Dial("tcp", target)
			} else {
				out, err = tls.Dial("tcp", target, &tls.Config{InsecureSkipVerify: true})
			}
			if err != nil {
				c.Close()
				return
			}
			done := make(chan struct{}, 2)
			pass := func(dst, src net.Conn) {
				io.Copy(dst, src)
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
				done <- struct{}{}
			}
			go pass(out, in)
			go pass(in, out)
			<-done
			<-done
			in.Close()
			out.Close()
		}()
	}
}

// --- the profile -------------------------------------------------------------

// lognormal draws from a lognormal distribution by its median and sigma,
// clamped to [lo, hi].
func lognormal(r *rand.Rand, median, sigma float64, lo, hi int) int {
	v := int(median * math.Exp(sigma*r.NormFloat64()))
	return min(max(v, lo), hi)
}

// pause draws a pause: none with probability 1-p, otherwise exponential with
// the mean given, at most max.
func pause(r *rand.Rand, p float64, mean, maxd time.Duration) time.Duration {
	if r.Float64() >= p {
		return 0
	}
	return min(time.Duration(r.ExpFloat64()*float64(mean)), maxd)
}

// pieces is how a writer splits what it sends.
type pieces struct {
	whole           float64 // probability of a message going out at once
	median, sigma   float64 // piece sizes
	lo, hi          int
	gapP            float64 // probability of a pause after a piece
	gapMean, gapMax time.Duration
}

var (
	// a browser: headers mostly in one segment, some of them split
	clientWrites = pieces{whole: 0.5, median: 1400, sigma: 1.0, lo: 1, hi: 64 << 10,
		gapP: 0.3, gapMean: time.Millisecond, gapMax: 20 * time.Millisecond}
	// a remote server sending what it has as it gets it
	originWrites = pieces{whole: 0.3, median: 16 << 10, sigma: 1.0, lo: 512, hi: 256 << 10,
		gapP: 0.2, gapMean: time.Millisecond, gapMax: 20 * time.Millisecond}
)

// exchange is everything one exchange does, drawn from its own seed.
type exchange struct {
	seed   uint64
	conn   int  // the connection asked for
	header int  // request header size
	upload int  // POST body, 0 for GET
	answer int  // response body
	close  bool // the client asks to close after it
	end    int  // how it ends, endNormal unless the client goes away
	stop   int  // with endAbort and endReset: bytes of the answer read first, -1 none
}

// how an exchange ends
const (
	endNormal    = iota
	endAbort     // the client closes before the whole answer is in
	endReset     // the same with a reset (SO_LINGER 0) instead of a FIN
	endHalfClose // the client shuts down its sending side after the request, and reads the answer
)

// churn is how connections end, from -per-conn, -abort, -reset and -halfclose.
type churn struct {
	close, abort, reset, halfclose float64
}

func draw(seed uint64, i uint64, pool int, ch *churn) (exchange, *rand.Rand) {
	r := rand.New(rand.NewPCG(seed, i))
	e := exchange{seed: r.Uint64(), conn: r.IntN(pool), stop: -1}
	e.header = lognormal(r, 600, 0.5, 200, 4000)
	if r.Float64() < 0.1 {
		e.upload = lognormal(r, 4<<10, 1.5, 100, 1<<20)
	}
	e.answer = lognormal(r, 12<<10, 1.6, 100, 8<<20)
	// a connection carrying a geometric number of exchanges, its mean
	// -per-conn, ends after any of them with the same probability
	e.close = r.Float64() < ch.close
	switch x := r.Float64(); {
	case x < ch.abort:
		e.end, e.stop = endAbort, r.IntN(e.answer)
	case x < ch.abort+ch.reset:
		e.end = endReset
		if r.IntN(2) == 0 {
			e.stop = r.IntN(e.answer)
		}
	case x < ch.abort+ch.reset+ch.halfclose:
		e.end = endHalfClose
	}
	return e, r
}

// errGone is an exchange the client gave up on as drawn: not an error.
var errGone = errors.New("client went away")

// --- writing and reading in pieces ---------------------------------------------

var payload = func() []byte {
	b := make([]byte, 256<<10)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range b {
		b[i] = byte('a' + r.IntN(26))
	}
	return b
}()

// send writes head and then body bytes of payload, in pieces with pauses.
func send(c net.Conn, r *rand.Rand, p pieces, head []byte, body int) error {
	if r.Float64() < p.whole && len(head)+body <= p.hi {
		buf := append(head, payload[:body]...)
		_, err := c.Write(buf)
		return err
	}
	total := len(head) + body
	for off := 0; off < total; {
		n := min(lognormal(r, p.median, p.sigma, p.lo, p.hi), total-off)
		var chunk []byte
		switch {
		case off+n <= len(head):
			chunk = head[off : off+n]
		case off >= len(head):
			s := (off - len(head)) % len(payload)
			chunk = payload[s:min(s+n, len(payload))]
			n = len(chunk)
		default:
			chunk = head[off:]
			n = len(chunk)
		}
		if _, err := c.Write(chunk); err != nil {
			return err
		}
		off += n
		if d := pause(r, p.gapP, p.gapMean, p.gapMax); d > 0 && off < total {
			time.Sleep(d)
		}
	}
	return nil
}

// a reader taking what arrives in amounts of its own, now and then slowly
func readSize(r *rand.Rand) int { return lognormal(r, 4<<10, 1.2, 64, 64<<10) }
func readPause(r *rand.Rand) time.Duration {
	return pause(r, 0.05, 2*time.Millisecond, 20*time.Millisecond)
}

// --- the origin -----------------------------------------------------------------

// origin answers on ports consecutive ports from listen's: many destinations,
// as a proxy serving many clients has, rather than one.
func origin(listen string, ports int) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	base, _ := strconv.Atoi(port)
	for k := range ports {
		l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(base+k)))
		if err != nil {
			return err
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					continue
				}
				go serve(c)
			}
		}()
	}
	select {}
}

func serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 16<<10)
	head := make([]byte, 0, 128)
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return
		}
		target := ""
		if f := bytes.Fields(line); len(f) >= 2 {
			target = string(f[1])
		}
		length, closing := 0, false
		for {
			h, err := br.ReadSlice('\n')
			if err != nil {
				return
			}
			if len(bytes.TrimSpace(h)) == 0 {
				break
			}
			k, v, _ := bytes.Cut(h, []byte(":"))
			v = bytes.TrimSpace(v)
			switch strings.ToLower(string(k)) {
			case "content-length":
				length, _ = strconv.Atoi(string(v))
			case "connection":
				closing = bytes.EqualFold(v, []byte("close"))
			}
		}
		if _, err := io.CopyN(io.Discard, br, int64(length)); err != nil {
			return
		}
		size, seed := query(target)
		r := rand.New(rand.NewPCG(seed, 0x6f726967696e))
		head = append(head[:0], "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "...)
		head = strconv.AppendInt(head, int64(size), 10)
		head = append(head, "\r\n\r\n"...)
		if send(c, r, originWrites, head, size) != nil || closing {
			return
		}
	}
}

// query reads s (the answer's size) and r (its seed) from a request target,
// absolute or origin-form.
func query(target string) (size int, seed uint64) {
	_, q, _ := strings.Cut(target, "?")
	for _, kv := range strings.Split(q, "&") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "s":
			size, _ = strconv.Atoi(v)
		case "r":
			seed, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return
}

// --- latencies -----------------------------------------------------------------

// histogram of microseconds, 16 buckets for every power of two
type histogram struct{ b [1024]atomic.Uint64 }

func (h *histogram) add(d time.Duration) {
	us := uint64(max(d.Microseconds(), 0))
	i := int(us)
	if us >= 16 {
		e := bits.Len64(us) - 5
		i = e*16 + int(us>>e)
	}
	h.b[min(i, len(h.b)-1)].Add(1)
}

func (h *histogram) quantile(q float64) float64 {
	var n uint64
	for i := range h.b {
		n += h.b[i].Load()
	}
	if n == 0 {
		return math.NaN()
	}
	want := uint64(math.Ceil(q * float64(n)))
	var seen uint64
	for i := range h.b {
		seen += h.b[i].Load()
		if seen >= want {
			if i < 16 {
				return float64(i) / 1000
			}
			e := i/16 - 1
			us := uint64(i%16+16) << e
			return float64(us) / 1000
		}
	}
	return math.NaN()
}

// --- the client ------------------------------------------------------------------

type client struct {
	via, proxy, origin string
	host               string // the origin's first port's host
	port, origins      int    // its first port, and how many follow
	sources            []*net.TCPAddr
	pool               int
	seed               uint64

	shards []shard // connection id % len(shards) belongs to shard of that number
	pos    []int   // where in its shard's idle each connection is, -1 if not there
	jobs   []chan job

	churn                                   churn
	measuring                               atomic.Bool
	done, bytes, errs, timeouts, reconnects atomic.Uint64
	aborts, resets, halfcloses              atomic.Uint64
	complete, first                         histogram
	dialErr, exchErr                        atomic.Value // the first of each, as text
	errlog                                  bool         // every failed exchange to stderr
}

// shard is a share of the pool with a dispatcher of its own: one dispatcher
// for all of it would be one thread, and the limit of the whole client.
type shard struct {
	mu   sync.Mutex
	idle []int // connections not in an exchange, by index
}

type job struct {
	e     exchange
	r     *rand.Rand
	start time.Time
	slot  chan struct{}
}

// target is the origin's k-th port.
func (cl *client) target(k int) string {
	return net.JoinHostPort(cl.host, strconv.Itoa(cl.port+k))
}

// dial opens connection id of the pool: from a source address and, through
// a tunnel or straight to the origin, to a port of the origin, both taken by
// turns, so that many connections are not all one pair of addresses.
func (cl *client) dial(id int) (net.Conn, error) {
	dest := cl.target(id % cl.origins)
	addr := dest
	if cl.via != "direct" {
		addr = cl.proxy
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	if len(cl.sources) > 0 {
		d.LocalAddr = cl.sources[id%len(cl.sources)]
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	switch cl.via {
	case "connect":
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest)
		resp, err := readHead(c)
		if err == nil && !bytes.Contains(resp[:bytes.IndexByte(resp, '\n')+1], []byte(" 200")) {
			err = errors.New("CONNECT refused")
		}
		if err != nil {
			c.Close()
			return nil, err
		}
	case "socks":
		host, port, _ := net.SplitHostPort(dest)
		ip := net.ParseIP(host).To4()
		p, _ := strconv.Atoi(port)
		buf := make([]byte, 10)
		if _, err = c.Write([]byte{5, 1, 0}); err == nil {
			_, err = io.ReadFull(c, buf[:2])
		}
		if err == nil {
			req := append([]byte{5, 1, 0, 1}, ip...)
			req = binary.BigEndian.AppendUint16(req, uint16(p))
			if _, err = c.Write(req); err == nil {
				_, err = io.ReadFull(c, buf)
			}
		}
		if err == nil && buf[1] != 0 {
			err = errors.New("SOCKS refused")
		}
		if err != nil {
			c.Close()
			return nil, err
		}
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// readHead reads up to the end of a response head byte by byte, leaving
// nothing of what follows read.
func readHead(c net.Conn) ([]byte, error) {
	var h []byte
	b := make([]byte, 1)
	for !bytes.HasSuffix(h, []byte("\r\n\r\n")) {
		if _, err := c.Read(b); err != nil {
			return nil, err
		}
		h = append(h, b[0])
		if len(h) > 8192 {
			return nil, errors.New("response head too long")
		}
	}
	return h, nil
}

// take marks a connection of shard s busy: the one asked for, moved into
// the shard, if it is idle, otherwise the next idle one of the shard after it.
func (cl *client) take(s, want int) int {
	n := len(cl.shards)
	sh := &cl.shards[s]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if len(sh.idle) == 0 {
		return -1
	}
	first := want - want%n + s
	for c := first; ; {
		if c < cl.pool {
			if p := cl.pos[c]; p >= 0 {
				last := len(sh.idle) - 1
				sh.idle[p] = sh.idle[last]
				cl.pos[sh.idle[p]] = p
				sh.idle = sh.idle[:last]
				cl.pos[c] = -1
				return c
			}
		}
		if c += n; c >= cl.pool+n {
			c = s
		}
		if c == first {
			return -1
		}
	}
}

func (cl *client) release(c int) {
	sh := &cl.shards[c%len(cl.shards)]
	sh.mu.Lock()
	cl.pos[c] = len(sh.idle)
	sh.idle = append(sh.idle, c)
	sh.mu.Unlock()
}

// worker is one connection of the pool: it runs the exchanges given to it,
// opening the connection again after an error or a close.
func (cl *client) worker(id int, c net.Conn) {
	scratch := make([]byte, 64<<10)
	head := make([]byte, 0, 4096)
	nth := 0 // exchanges on this connection so far
	for j := range cl.jobs[id] {
		if c == nil {
			nth = 0
			var err error
			if c, err = cl.dial(id); err != nil {
				cl.dialErr.CompareAndSwap(nil, err.Error())
				if cl.measuring.Load() {
					cl.errs.Add(1)
				}
				j.slot <- struct{}{}
				time.Sleep(100 * time.Millisecond)
				cl.release(id)
				continue
			}
			if cl.measuring.Load() {
				cl.reconnects.Add(1)
			}
		}
		n, err := cl.exchange(c, id, j, head, scratch)
		nth++
		j.slot <- struct{}{}
		if err == errGone {
			// closed as drawn, with a reset or not
			c = nil
			if cl.measuring.Load() {
				if j.e.end == endReset {
					cl.resets.Add(1)
				} else {
					cl.aborts.Add(1)
				}
			}
			cl.release(id)
			continue
		}
		halfclosed := j.e.end == endHalfClose && cl.via != "http"
		if err == nil && halfclosed && cl.measuring.Load() {
			cl.halfcloses.Add(1)
		}
		if err != nil || j.e.close || halfclosed {
			c.Close()
			c = nil
			if err != nil && cl.errlog {
				fmt.Fprintf(os.Stderr, "error: connection %d, exchange %d on it: %v\n", id, nth, err)
			}
			if err != nil && cl.measuring.Load() {
				cl.exchErr.CompareAndSwap(nil, err.Error())
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					cl.timeouts.Add(1)
				} else {
					cl.errs.Add(1)
				}
			}
		}
		if err == nil && cl.measuring.Load() {
			cl.done.Add(1)
			cl.bytes.Add(uint64(n))
		}
		cl.release(id)
	}
}

func (cl *client) exchange(c net.Conn, id int, j job, head, scratch []byte) (int, error) {
	e, r := j.e, j.r
	c.SetDeadline(time.Now().Add(15 * time.Second))
	method := "GET"
	if e.upload > 0 {
		method = "POST"
	}
	target := "/x?s=" + strconv.Itoa(e.answer) + "&r=" + strconv.FormatUint(e.seed, 10)
	// each connection keeps to one destination, as a tunnel has to: one
	// asking an HTTP proxy for another with every request would measure how
	// fast the proxy opens connections to servers, nothing else
	host := cl.target(id % cl.origins)
	if cl.via == "http" {
		target = "http://" + host + target
	}
	head = append(head[:0], method...)
	head = append(head, ' ')
	head = append(head, target...)
	head = append(head, " HTTP/1.1\r\nHost: "...)
	head = append(head, host...)
	head = append(head, "\r\nUser-Agent: mix\r\nAccept: */*\r\n"...)
	if e.upload > 0 {
		head = append(head, "Content-Type: application/octet-stream\r\nContent-Length: "...)
		head = strconv.AppendInt(head, int64(e.upload), 10)
		head = append(head, "\r\n"...)
	}
	// half-closing ends the connection too; through an HTTP proxy it is
	// taken for a client gone, so it is tried in tunnels and relays only
	halfclose := e.end == endHalfClose && cl.via != "http"
	if e.close || halfclose {
		head = append(head, "Connection: close\r\n"...)
	}
	// what a browser carries in cookies and the like, up to the drawn size
	if pad := e.header - len(head) - len("X-Pad: \r\n\r\n"); pad > 0 {
		head = append(head, "X-Pad: "...)
		head = append(head, payload[:pad]...)
		head = append(head, "\r\n"...)
	}
	head = append(head, "\r\n"...)
	if err := send(c, r, clientWrites, head, e.upload); err != nil {
		return 0, fmt.Errorf("sending (end %d, upload %d): %w", e.end, e.upload, err)
	}
	if halfclose {
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			if err := cw.CloseWrite(); err != nil {
				return 0, err
			}
		}
	}
	gone := e.end == endAbort || e.end == endReset
	leave := func() (int, error) {
		if tc, ok := c.(*net.TCPConn); ok && e.end == endReset {
			tc.SetLinger(0)
		}
		c.Close()
		return 0, errGone
	}
	if gone && e.stop < 0 {
		return leave()
	}

	// the answer: a head, then the body, read in amounts of the reader's own
	got, want, body := 0, -1, 0
	var hbuf []byte
	for want < 0 || body < want {
		if gone && want >= 0 && body >= e.stop {
			return leave()
		}
		n := readSize(r)
		if want >= 0 {
			n = min(n, want-body)
		}
		m, err := c.Read(scratch[:n])
		if m > 0 && got == 0 && cl.measuring.Load() {
			cl.first.add(time.Since(j.start))
		}
		got += m
		if want < 0 {
			hbuf = append(hbuf, scratch[:m]...)
			if i := bytes.Index(hbuf, []byte("\r\n\r\n")); i >= 0 {
				status, _, _ := bytes.Cut(hbuf, []byte("\r\n"))
				if !bytes.Contains(status, []byte(" 200 ")) {
					return 0, errors.New("answer " + string(status))
				}
				want = contentLength(hbuf[:i])
				if want < 0 {
					return 0, errors.New("answer without a length")
				}
				body = len(hbuf) - i - 4
			}
		} else {
			body += m
		}
		if err != nil {
			if want >= 0 && body >= want {
				break
			}
			return 0, fmt.Errorf("reading (end %d, close %v, upload %d, answer %d, got %d, body %d of %d): %w",
				e.end, e.close, e.upload, e.answer, got, body, want, err)
		}
		if d := readPause(r); d > 0 {
			time.Sleep(d)
		}
	}
	if cl.measuring.Load() {
		cl.complete.add(time.Since(j.start))
	}
	return len(head) + e.upload + got, nil
}

func contentLength(h []byte) int {
	for _, line := range bytes.Split(h, []byte("\r\n"))[1:] {
		k, v, _ := bytes.Cut(line, []byte(":"))
		if strings.EqualFold(string(k), "content-length") {
			n, err := strconv.Atoi(string(bytes.TrimSpace(v)))
			if err == nil {
				return n
			}
		}
	}
	return -1
}

type summary struct {
	Pool       int     `json:"pool"`
	Opened     int     `json:"opened"`
	Exchanges  uint64  `json:"exchanges"`
	Rate       float64 `json:"rate"`
	Gbit       float64 `json:"gbit"`
	Bytes      uint64  `json:"bytes"`
	P50ms      float64 `json:"p50_ms"`
	P90ms      float64 `json:"p90_ms"`
	P99ms      float64 `json:"p99_ms"`
	FirstP50ms float64 `json:"first_p50_ms"`
	FirstP99ms float64 `json:"first_p99_ms"`
	Errors     uint64  `json:"errors"`
	Timeouts   uint64  `json:"timeouts"`
	Reconnects uint64  `json:"reconnects"`
	Late       uint64  `json:"late"`
	Aborts     uint64  `json:"aborts"`
	Resets     uint64  `json:"resets"`
	HalfCloses uint64  `json:"halfcloses"`
	DialError  string  `json:"dial_error,omitempty"`
	ExchError  string  `json:"exchange_error,omitempty"`
}

func runClient(cl *client, active int, rate float64, warmup, duration time.Duration, dialers, shards int) {
	cl.shards = make([]shard, max(shards, 1))
	cl.pos = make([]int, cl.pool)
	cl.jobs = make([]chan job, cl.pool)
	conns := make([]net.Conn, cl.pool)
	var opened atomic.Int64
	var wg sync.WaitGroup
	next := atomic.Int64{}
	for range dialers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= cl.pool {
					return
				}
				for try := 0; try < 3; try++ {
					c, err := cl.dial(i)
					if err == nil {
						conns[i] = c
						opened.Add(1)
						break
					}
					cl.dialErr.CompareAndSwap(nil, err.Error())
					time.Sleep(50 * time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
	for i := range cl.pool {
		cl.jobs[i] = make(chan job, 1)
		cl.pos[i] = -1
		if conns[i] != nil {
			cl.release(i)
		}
		go cl.worker(i, conns[i])
	}

	start := time.Now()
	measureFrom := start.Add(warmup)
	end := measureFrom.Add(duration)
	var late atomic.Uint64
	var ready sync.Once
	n := len(cl.shards)
	var dispatchers sync.WaitGroup
	for sn := range n {
		dispatchers.Add(1)
		go func() {
			defer dispatchers.Done()
			// the shard's part of the exchanges going at once and of the rate
			share := active / n
			if sn < active%n {
				share++
			}
			slots := make(chan struct{}, max(share, 1))
			for range max(share, 1) {
				slots <- struct{}{}
			}
			srate := rate / float64(n)
			arrivals := rand.New(rand.NewPCG(cl.seed, math.MaxUint64-uint64(sn)))
			at := start
			// shard sn runs exchanges sn, sn+n, sn+2n...: each the same
			// whichever shard count, drawn from its own number
			for i := uint64(sn); ; i += uint64(n) {
				if srate > 0 {
					at = at.Add(time.Duration(arrivals.ExpFloat64() / srate * float64(time.Second)))
					if d := time.Until(at); d > 0 {
						time.Sleep(d)
					}
				}
				now := time.Now()
				if now.After(measureFrom) {
					ready.Do(func() {
						cl.measuring.Store(true)
						fmt.Println("READY")
						os.Stdout.Sync()
					})
				}
				if now.After(end) {
					return
				}
				// waiting here for a slot is part of the exchange's time
				// when it was due at a given moment
				<-slots
				e, r := draw(cl.seed, i, cl.pool, &cl.churn)
				c := cl.take(sn, e.conn)
				if c < 0 {
					slots <- struct{}{}
					time.Sleep(time.Millisecond)
					continue
				}
				jstart := time.Now()
				if srate > 0 {
					jstart = at
					if time.Since(at) > 10*time.Millisecond && cl.measuring.Load() {
						late.Add(1)
					}
				}
				cl.jobs[c] <- job{e: e, r: r, start: jstart, slot: slots}
			}
		}()
	}
	dispatchers.Wait()
	cl.measuring.Store(false)
	secs := duration.Seconds()
	s := summary{Pool: cl.pool, Opened: int(opened.Load()), Exchanges: cl.done.Load(),
		Bytes: cl.bytes.Load(), Errors: cl.errs.Load(), Timeouts: cl.timeouts.Load(),
		Reconnects: cl.reconnects.Load(), Late: late.Load(),
		Aborts: cl.aborts.Load(), Resets: cl.resets.Load(), HalfCloses: cl.halfcloses.Load(),
		P50ms: cl.complete.quantile(0.5), P90ms: cl.complete.quantile(0.9),
		P99ms: cl.complete.quantile(0.99),
		FirstP50ms: cl.first.quantile(0.5), FirstP99ms: cl.first.quantile(0.99)}
	s.DialError, _ = cl.dialErr.Load().(string)
	s.ExchError, _ = cl.exchErr.Load().(string)
	s.Rate = float64(s.Exchanges) / secs
	s.Gbit = float64(s.Bytes) * 8 / secs / 1e9
	out, _ := json.Marshal(s)
	fmt.Println(string(out))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mix origin|client|tls [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "origin":
		listen := fs.String("listen", "127.0.0.1:8090", "address to answer on, its first port")
		ports := fs.Int("ports", 1, "consecutive ports to answer on")
		fs.Parse(os.Args[2:])
		if err := origin(*listen, *ports); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "tls":
		listen := fs.String("listen", "127.0.0.1:5443", "address to take connections on")
		target := fs.String("connect", "127.0.0.1:5201", "address to pass them to")
		cert := fs.String("cert", "", "certificate: take TLS and pass plain TCP on; none: the other way round")
		key := fs.String("key", "", "the certificate's key")
		fs.Parse(os.Args[2:])
		if err := wrap(*listen, *target, *cert, *key); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "client":
		cl := &client{}
		fs.StringVar(&cl.via, "via", "http", "http (an HTTP proxy), connect, socks, relay or direct")
		fs.StringVar(&cl.proxy, "proxy", "", "the proxy, or the relay, host:port")
		fs.StringVar(&cl.origin, "origin", "127.0.0.1:8090", "the origin, host:port of its first port")
		fs.IntVar(&cl.origins, "origins", 1, "the origin's ports to spread over (origin -ports)")
		sources := fs.String("sources", "", "client addresses to open connections from, comma separated")
		fs.IntVar(&cl.pool, "pool", 20000, "connections kept open")
		fs.BoolVar(&cl.errlog, "errlog", false, "print every failed exchange to stderr")
		active := fs.Int("active", 2000, "exchanges in progress at most")
		rate := fs.Float64("rate", 0, "exchanges started per second, 0 to keep -active going all the time")
		duration := fs.Duration("duration", 10*time.Second, "how long to measure")
		warmup := fs.Duration("warmup", 2*time.Second, "exchanges before measuring")
		dialers := fs.Int("dialers", 256, "connections being opened at once")
		seed := fs.Uint64("seed", 1, "seed of everything drawn")
		shards := fs.Int("shards", runtime.GOMAXPROCS(0), "dispatchers, each with its share of the pool")
		perConn := fs.Float64("per-conn", 15, "exchanges a connection carries on average before it is closed")
		fs.Float64Var(&cl.churn.abort, "abort", 0.005, "share of exchanges the client leaves with a close before the answer is in")
		fs.Float64Var(&cl.churn.reset, "reset", 0.002, "share it leaves with a reset, before the answer or during it")
		fs.Float64Var(&cl.churn.halfclose, "halfclose", 0.005, "share after which it shuts down sending and reads the answer (not through an HTTP proxy)")
		fs.Parse(os.Args[2:])
		cl.seed = *seed
		cl.churn.close = 1 / max(*perConn, 1)
		h, p, err := net.SplitHostPort(cl.origin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "-origin:", err)
			os.Exit(2)
		}
		cl.host = h
		cl.port, _ = strconv.Atoi(p)
		cl.origins = max(cl.origins, 1)
		for _, a := range strings.Split(*sources, ",") {
			if a != "" {
				cl.sources = append(cl.sources, &net.TCPAddr{IP: net.ParseIP(a)})
			}
		}
		if cl.via != "direct" && cl.proxy == "" {
			fmt.Fprintln(os.Stderr, "-proxy is needed with -via", cl.via)
			os.Exit(2)
		}
		runClient(cl, *active, *rate, *warmup, *duration, *dialers, *shards)
	default:
		fmt.Fprintln(os.Stderr, "usage: mix origin|client|tls [flags]")
		os.Exit(2)
	}
}
