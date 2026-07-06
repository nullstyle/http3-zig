// Minimal quic-go HTTP/3 server for http3-zig's advisory third-party H3
// interop matrix.
//
// The contract mirrors interop/external_h3/run_matrix.sh:
//
//   --listen 127.0.0.1:0    UDP listen address
//   --cert tests/data/test_cert.pem
//   --key tests/data/test_key.pem
//   --root <dir>            directory served by http.FileServer
//   --max-requests N        shut down after N requests (0 = forever)
//   --max-lifetime-ms N     wallclock deadline before forced shutdown
//
// stdout protocol:
//
//   READY <port>
//
// Exit codes:
//
//   0  clean shutdown
//   2  setup / listener failure

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	cert := flag.String("cert", "tests/data/test_cert.pem", "PEM-encoded server certificate chain")
	key := flag.String("key", "tests/data/test_key.pem", "PEM-encoded server private key")
	root := flag.String("root", ".", "directory to serve")
	maxRequests := flag.Uint64("max-requests", 1, "exit after this many requests complete (0 = run until killed)")
	maxLifetimeMs := flag.Uint64("max-lifetime-ms", 30000, "wallclock cap on the server's lifetime (ms)")
	flag.Parse()

	tlsCert, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "external_h3 server (quic-go): cert load failed: %v\n", err)
		os.Exit(2)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "external_h3 server (quic-go): resolve %q failed: %v\n", *listen, err)
		os.Exit(2)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "external_h3 server (quic-go): bind %q failed: %v\n", *listen, err)
		os.Exit(2)
	}
	defer udpConn.Close()

	fileServer := http.FileServer(http.Dir(*root))
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	var remaining int64
	if *maxRequests > 0 {
		remaining = int64(*maxRequests)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
		if *maxRequests > 0 && atomic.AddInt64(&remaining, -1) <= 0 {
			go shutdown()
		}
	})

	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{http3.NextProtoH3},
			MinVersion:   tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        10 * time.Second,
			MaxIncomingStreams:    64,
			MaxIncomingUniStreams: 16,
		},
		Handler:        mux,
		MaxHeaderBytes: 64 * 1024,
	}

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("READY %d\n", port)
	_ = os.Stdout.Sync()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(udpConn)
	}()

	deadline := time.NewTimer(time.Duration(*maxLifetimeMs) * time.Millisecond)
	defer deadline.Stop()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "external_h3 server (quic-go): listener exited: %v\n", err)
			os.Exit(2)
		}
	case <-shutdownCtx.Done():
	case <-deadline.C:
	}

	shutdownDone := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(3 * time.Second):
		_ = server.Close()
	}
}
