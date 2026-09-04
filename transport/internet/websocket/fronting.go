package websocket

// Domain-fronting support for plaintext WebSocket.
//
// Some DPI middleboxes only inspect the FIRST HTTP request of a TCP
// connection and block the connection when that request targets a forbidden
// host (e.g. answering 302 to a captive portal). To pass such DPI, when
// Config.FrontingHost is set (plaintext "ws" only), a benign HEAD request to
// the fronting host is prepended before the real WebSocket handshake in a
// single write, and the fronting HTTP response is swallowed before the
// handshake response (101) is processed.
//
// Wire format on the wire (one TCP connection, HTTP/1.1 pipelining):
//
//	HEAD / HTTP/1.1\r\nHost: <fronting>\r\nConnection: Keep-Alive\r\n\r\n
//	GET <path> HTTP/1.1\r\nHost: <real>\r\nUpgrade: websocket\r\n...\r\n\r\n
//
// Implemented as a net.Conn wrapper hooked into gorilla's NetDial, so the
// rest of the handshake (key validation, framing) stays untouched.
//
// Concurrency: gorilla allows ONE concurrent reader AND one concurrent
// writer. Read and write state are therefore guarded by SEPARATE mutexes;
// a single shared mutex would serialize reads against writes and stall
// full-duplex traffic (blocking Read holding off Writes and vice versa).

import (
	"bytes"
	"errors"
	"strings"
	"sync"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

// maxFrontingHeadSize caps how many bytes are buffered while looking for the
// end of the fronting HTTP response head. A HEAD response carries headers
// only (a Cloudflare 301 is well under 1KB); anything larger means a broken
// peer, and accumulating without a bound would grow memory forever.
const maxFrontingHeadSize = 1 << 16

var crlfcrlf = []byte("\r\n\r\n")

// frontingConn wraps a TCP connection: the first Write prepends the fronting
// request, and reads swallow the fronting HTTP response (HEAD => headers
// only, no body) before passing subsequent bytes through.
type frontingConn struct {
	net.Conn
	writeMu  sync.Mutex
	readMu   sync.Mutex
	fronting []byte // pending fronting request bytes, sent with first Write
	discard  bool   // true until the fronting response is fully swallowed
	head     []byte // accumulator while looking for end of fronting headers
	pending  []byte // bytes already received past the fronting response
	off      int    // consumed prefix of pending
}

func newFrontingConn(conn net.Conn, host string) net.Conn {
	host = sanitizeFrontingHost(host)
	if host == "" {
		return conn
	}
	req := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: Keep-Alive\r\n\r\n"
	return &frontingConn{Conn: conn, fronting: []byte(req), discard: true}
}

func sanitizeFrontingHost(host string) string {
	// Defensive: a Host header value must not contain whitespace or CRLF.
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(host))
}

func (c *frontingConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.fronting != nil {
		data := make([]byte, 0, len(c.fronting)+len(b))
		data = append(data, c.fronting...)
		data = append(data, b...)
		c.fronting = nil
		if _, err := c.Conn.Write(data); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *frontingConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.discard {
		// Swallow exactly one HTTP response head (fronting 301). A HEAD
		// response carries no body, so headers end at \r\n\r\n. Anything
		// already received past it (pipelined 101, WS frames) is kept in
		// pending and served first.
		if err := c.swallowResponseHead(); err != nil {
			return 0, err
		}
	}
	if c.off < len(c.pending) {
		n := copy(b, c.pending[c.off:])
		c.off += n
		if c.off == len(c.pending) {
			c.pending = nil
			c.off = 0
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// swallowResponseHead consumes bytes until the end of the first HTTP response
// head. Must be called with readMu held.
func (c *frontingConn) swallowResponseHead() error {
	var tmp [2048]byte
	for {
		n, err := c.Conn.Read(tmp[:])
		if n > 0 {
			if len(c.head)+n > maxFrontingHeadSize {
				return errors.New("fronting response head too large")
			}
			c.head = append(c.head, tmp[:n]...)
			if i := bytes.Index(c.head, crlfcrlf); i >= 0 {
				c.pending = c.head[i+4:]
				c.head = nil
				c.discard = false
				return nil
			}
		}
		if err != nil {
			return err
		}
	}
}
