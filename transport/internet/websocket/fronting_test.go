package websocket

import (
	"bytes"
	"errors"
	"io"
	gonet "net"
	"sync"
	"testing"
	"time"
)

const testHandshake = "GET / HTTP/1.1\r\nHost: tgk.pp.ua\r\nUpgrade: websocket\r\n\r\n"

const test301 = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://x/\r\nContent-Length: 0\r\n\r\n"

const test101 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

func deadline(t *testing.T, c gonet.Conn) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
}

// The first Write must prepend the HEAD request in the SAME write.
func TestPrependFirstWrite(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client)
	deadline(t, server)

	fc := newFrontingConn(client, "portmone.com.ua")
	if _, ok := fc.(*frontingConn); !ok {
		t.Fatal("expected *frontingConn")
	}

	want := "HEAD / HTTP/1.1\r\nHost: portmone.com.ua\r\nConnection: Keep-Alive\r\n\r\n" + testHandshake
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		var all []byte
		for len(all) < len(want) {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			all = append(all, buf[:n]...)
		}
		got <- all
	}()

	n, err := fc.Write([]byte(testHandshake))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testHandshake) {
		t.Fatalf("short write report: %d", n)
	}

	select {
	case all := <-got:
		if !bytes.Equal(all, []byte(want)) {
			t.Fatalf("wire mismatch:\n%q", all)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for prepended write")
	}

	// Second write goes through untouched.
	go func() {
		buf := make([]byte, 64)
		n, _ := server.Read(buf)
		got <- buf[:n]
	}()
	if _, err := fc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case all := <-got:
		if string(all) != "ping" {
			t.Fatalf("second write mangled: %q", all)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for second write")
	}
}

// 301 + 101 + WS frames pipelined in ONE segment must all survive.
func TestSwallowPipelined301(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client)
	deadline(t, server)

	fc := newFrontingConn(client, "portmone.com.ua")
	frames := []byte{0x82, 0x05, 'h', 'e', 'l', 'l', 'o'}
	go func() {
		server.Write([]byte(test301 + test101 + string(frames)))
	}()

	var all []byte
	buf := make([]byte, 4096)
	for len(all) < len(test101)+len(frames) {
		n, err := fc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, buf[:n]...)
	}
	if !bytes.Equal(all, []byte(test101+string(frames))) {
		t.Fatalf("expected 101+frames, got %q", all)
	}
}

// 301 split across segments (CRLF torn apart) must still be swallowed.
func TestSwallowFragmented301(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client)
	deadline(t, server)

	fc := newFrontingConn(client, "portmone.com.ua")
	go func() {
		for i := 0; i < len(test301); i++ {
			server.Write([]byte(test301[i : i+1]))
		}
		server.Write([]byte(test101))
	}()

	var all []byte
	buf := make([]byte, 16) // tiny reads, worst case
	for len(all) < len(test101) {
		n, err := fc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, buf[:n]...)
	}
	if string(all) != test101 {
		t.Fatalf("expected 101, got %q", all)
	}
}

// Concurrent reader + writer must make progress (regression: a single shared
// mutex stalled full-duplex traffic). Run with -race.
func TestFullDuplex(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client)
	deadline(t, server)

	fc := newFrontingConn(client, "portmone.com.ua")
	go server.Write([]byte(test301 + test101))

	const chunks = 50
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64) // 1KB

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // writer
		defer wg.Done()
		for i := 0; i < chunks; i++ {
			if _, err := fc.Write(payload); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() { // reader
		defer wg.Done()
		// drain 101 (pipelined with 301) then echo stream
		buf := make([]byte, 2048)
		var head []byte
		for len(head) < len(test101) {
			n, err := fc.Read(buf)
			if err != nil {
				t.Error(err)
				return
			}
			head = append(head, buf[:n]...)
		}
		if string(head[:len(test101)]) != test101 {
			t.Errorf("handshake corrupted: %q", head)
			return
		}
	}()
	// server side: drain prepended HEAD + payload
	headReq := "HEAD / HTTP/1.1\r\nHost: portmone.com.ua\r\nConnection: Keep-Alive\r\n\r\n"
	go func() {
		buf := make([]byte, 4096)
		total := 0
		for total < len(headReq)+chunks*len(payload) {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			total += n
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("full-duplex stall: reader/writer did not finish")
	}
}

// A peer that never terminates headers must not grow memory without bound.
func TestOversizeHead(t *testing.T) {
	client, server := gonet.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client)
	deadline(t, server)

	fc := newFrontingConn(client, "portmone.com.ua")
	go func() {
		junk := bytes.Repeat([]byte("X"), maxFrontingHeadSize+1)
		server.Write(junk)
	}()
	buf := make([]byte, 4096)
	if _, err := fc.Read(buf); err == nil {
		t.Fatal("expected error for oversize head")
	}
}

// Empty/blank host disables fronting transparently.
func TestEmptyHostPassthrough(t *testing.T) {
	client, _ := gonet.Pipe()
	defer client.Close()
	if fc := newFrontingConn(client, "  \r\n "); fc != client {
		t.Fatal("blank host should return the raw conn")
	}
}

type frontingTestConn struct {
	gonet.Conn
	reader io.Reader
	write  func([]byte) (int, error)
}

func (c *frontingTestConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *frontingTestConn) Write(b []byte) (int, error) { return c.write(b) }

type frontingChunkReader struct{ io.Reader }

func (r frontingChunkReader) Read(b []byte) (int, error) {
	return r.Reader.Read(b[:min(len(b), 1500)])
}

func TestFrontingPartialWriteReportsPayloadBytes(t *testing.T) {
	wantErr := errors.New("write interrupted")
	conn := &frontingTestConn{write: func(b []byte) (int, error) {
		prefix := bytes.Index(b, crlfcrlf) + len(crlfcrlf)
		return prefix + 3, wantErr
	}}
	fc := newFrontingConn(conn, "front.example")
	n, err := fc.Write([]byte(testHandshake))
	if n != 3 || !errors.Is(err, wantErr) {
		t.Fatalf("Write = (%d, %v), want (3, interrupted)", n, err)
	}
}

func TestFrontingEmptyReadDoesNotTouchNetwork(t *testing.T) {
	fc := newFrontingConn(&frontingTestConn{reader: bytes.NewReader(nil)}, "front.example")
	n, err := fc.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestFrontingHeaderLimitExcludesPipelinedPayload(t *testing.T) {
	head := []byte("HTTP/1.1 200 OK\r\nX-Padding: ")
	head = append(head, bytes.Repeat([]byte("x"), maxFrontingHeadSize-len(head)-8)...)
	head = append(head, crlfcrlf...)
	payload := append([]byte(test101), bytes.Repeat([]byte("data"), 1024)...)
	fc := newFrontingConn(&frontingTestConn{reader: frontingChunkReader{bytes.NewReader(append(head, payload...))}}, "front.example")
	got, err := io.ReadAll(fc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("pipelined handshake or payload was lost")
	}
}
