package websocket

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	gorillaws "github.com/gorilla/websocket"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet/tls"
)

func TestFrontingDialScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fronting string
		tls      bool
		methods  []string
	}{
		{name: "fronting", fronting: "front.example", methods: []string{"HEAD", "GET"}},
		{name: "ordinary ws", methods: []string{"GET"}},
		{name: "wss ignores fronting", fronting: "front.example", tls: true, methods: []string{"GET"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan *http.Request, 2)
			serverErrors := make(chan error, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Clone(r.Context())
				if r.Method == http.MethodHead {
					w.Header().Set("Location", "https://front.example/")
					w.WriteHeader(http.StatusMovedPermanently)
					return
				}
				upgrader := gorillaws.Upgrader{}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					serverErrors <- err
					return
				}
				defer conn.Close()
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					serverErrors <- err
					return
				}
				if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					serverErrors <- err
					return
				}
				kind, payload, err := conn.ReadMessage()
				if err == nil {
					err = conn.WriteMessage(kind, payload)
				}
				serverErrors <- err
			}))
			if tc.tls {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			settings := &internet.MemoryStreamConfig{
				ProtocolName: "websocket",
				ProtocolSettings: &Config{
					Path: "/socket", FrontingHost: tc.fronting,
					Header: []*Header{{Key: "Host", Value: "backend.example"}},
				},
			}
			if tc.tls {
				settings.SecurityType = "tls"
				settings.SecuritySettings = &tls.Config{AllowInsecure: true} // local httptest certificate only
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialWebsocket(ctx, net.DestinationFromAddr(server.Listener.Addr()), settings)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			payload := []byte("fronting round trip")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("echo payload differs")
			}
			if err := <-serverErrors; err != nil {
				t.Fatal(err)
			}
			close(requests)
			var methods []string
			for request := range requests {
				methods = append(methods, request.Method)
				wantHost := "backend.example"
				if request.Method == http.MethodHead {
					wantHost = tc.fronting
				}
				if request.Host != wantHost {
					t.Fatalf("%s Host = %q, want %q", request.Method, request.Host, wantHost)
				}
			}
			if !reflect.DeepEqual(methods, tc.methods) {
				t.Fatalf("methods = %v, want %v", methods, tc.methods)
			}
		})
	}
}
