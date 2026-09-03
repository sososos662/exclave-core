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

import (
	"strings"
	"sync"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

// frontingConn wraps a TCP connection: the first Write prepends the fronting
// request, and reads swallow the fronting HTTP response (HEAD => headers
// only, no body) before passing subsequent bytes through.
type frontingConn struct {
	net.Conn
	mu       sync.Mutex
	fronting []byte // pending fronting request bytes, sent with first Write
	discard  bool   // true until the fronting response is fully swallowed
	head     []byte // accumulator while looking for end of fronting headers
	pending  []byte // bytes already received past the fronting response
}

func newFrontingConn(conn net.Conn, host string) net.Conn {
	host = sanitizeFrontingHost(host)
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
	c.mu.Lock()
	defer c.mu.Unlock()
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
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.discard {
		// Swallow exactly one HTTP response head (fronting 301). A HEAD
		// response carries no body, so headers end at \r\n\r\n.
		tmp := make([]byte, 1<<11)
		n, err := c.Conn.Read(tmp)
		if n > 0 {
			c.head = append(c.head, tmp[:n]...)
		}
		if err != nil && n == 0 {
			return 0, err
		}
		if i := indexDoubleCRLF(c.head); i >= 0 {
			c.pending = append([]byte{}, c.head[i+4:]...)
			c.head = nil
			c.discard = false
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = append([]byte{}, c.pending[n:]...)
		return n, nil
	}
	return c.Conn.Read(b)
}

func indexDoubleCRLF(b []byte) int {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return i
		}
	}
	return -1
}
