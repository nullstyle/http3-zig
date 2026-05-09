// Echo WebTransport server used as a third-party interop peer for
// http3-zig's `wt-interop-matrix` runner.
//
// The flow this peer is asked to participate in (see
// `interop/external_wt/client.zig`):
//
//   1. Client opens a WebTransport CONNECT session against `<path>`.
//   2. Client sends one datagram with payload `hello-from-http3-zig`.
//   3. Client opens one client-initiated unidirectional stream and writes
//      `hello-uni` onto it, then finishes it.
//   4. Client sends `CLOSE_WEBTRANSPORT_SESSION` and finishes the
//      CONNECT stream.
//
// The matrix client doesn't care about echoes, but for symmetry with
// the in-tree Zig echo server (`interop/external_wt/server.zig`) we
// also:
//
//   * Echo every incoming datagram back to the peer.
//   * For every accepted uni stream, drain it and open a server-
//     initiated uni stream that writes the same bytes back.
//
// This server uses webtransport-go's master branch because that's
// where draft-ietf-webtrans-http3-15 wire compatibility lives — it
// advertises both the legacy draft-06 SETTINGS codepoint
// (`0x2b603742`) for backward compatibility and the draft-15
// `SETTINGS_WT_ENABLED = 0x2c7cf000` codepoint that http3-zig pins
// to. As of 2026-05-09 there is no tagged release on the master
// branch yet (latest tag is v0.10.0, June 2025, draft-13 only); when
// the next tag ships, swap the pseudo-version below for it.
//
// CLI surface mirrors the in-tree Zig server so the same workflow YAML
// can drive either:
//
//   --listen 127.0.0.1:0    listen address
//   --cert  tests/data/test_cert.pem
//   --key   tests/data/test_key.pem
//   --max-sessions N        exit after N sessions complete (0 = forever)
//   --max-lifetime-ms N     wallclock deadline before forced shutdown
//
// stdout protocol contract:
//
//   READY <port>\n          printed once the listener is up; the GH
//                           Actions workflow grep's for it.
//
// Exit codes:
//
//   0  clean shutdown (max_sessions reached or deadline expired)
//   1  protocol failure (a session ended badly)
//   2  setup failure (cert load, listen, ...)

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

const alpnH3 = "h3"

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	cert := flag.String("cert", "tests/data/test_cert.pem", "PEM-encoded server certificate chain")
	key := flag.String("key", "tests/data/test_key.pem", "PEM-encoded server private key")
	maxSessions := flag.Uint64("max-sessions", 1, "exit after this many sessions complete (0 = run until killed)")
	maxLifetimeMs := flag.Uint64("max-lifetime-ms", 30_000, "wallclock cap on the server's lifetime (ms)")
	flag.Parse()

	tlsCert, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "external_wt server (go): cert load failed: %v\n", err)
		os.Exit(2)
	}

	// Bind the UDP socket ourselves so we can both report the bound
	// port and pass the same connection into webtransport.Server.Serve().
	udpAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "external_wt server (go): resolve %q failed: %v\n", *listen, err)
		os.Exit(2)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "external_wt server (go): bind %q failed: %v\n", *listen, err)
		os.Exit(2)
	}
	defer udpConn.Close()

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("READY %d\n", port)
	_ = os.Stdout.Sync()

	// Track session count so we can shut down gracefully once the
	// matrix runner has done its thing. `sessionsRemaining` starts
	// at `*maxSessions` and counts down; when it hits zero we close
	// the server. `*maxSessions == 0` disables the count-based
	// shutdown (run until killed).
	var sessionsRemaining int64
	if *maxSessions > 0 {
		sessionsRemaining = int64(*maxSessions)
	}

	shutdownCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	var protocolFailure atomic.Bool

	mux := http.NewServeMux()
	wt := &webtransport.Server{
		H3: &http3.Server{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				NextProtos:   []string{alpnH3},
				MinVersion:   tls.VersionTLS13,
			},
			Handler: mux,
		},
	}
	// ConfigureHTTP3Server wires up SETTINGS_WT_ENABLED +
	// SETTINGS_ENABLE_WEBTRANSPORT_DRAFT06 + EnableDatagrams +
	// ConnContext. Without it the H3 server won't advertise WT
	// support and `Upgrade` would fail.
	webtransport.ConfigureHTTP3Server(wt.H3)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Any path is acceptable — the matrix client picks its own
		// `/wt-self-test`-style path. We just upgrade.
		session, err := wt.Upgrade(w, r)
		if err != nil {
			http.Error(w, "upgrade failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := echoSession(session); err != nil {
			// Session-level errors are reported but do not crash the
			// server — a flaky peer shouldn't take the whole
			// process down. We do mark the run as protocol-failed
			// so the harness exit code reflects reality.
			fmt.Fprintf(os.Stderr, "external_wt server (go): session failed: %v\n", err)
			protocolFailure.Store(true)
		}

		if *maxSessions > 0 {
			if atomic.AddInt64(&sessionsRemaining, -1) <= 0 {
				shutdown()
			}
		}
	})

	servErr := make(chan error, 1)
	go func() {
		servErr <- wt.Serve(udpConn)
	}()

	deadline := time.NewTimer(time.Duration(*maxLifetimeMs) * time.Millisecond)
	defer deadline.Stop()

	select {
	case err := <-servErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "external_wt server (go): listener exited: %v\n", err)
			os.Exit(2)
		}
	case <-shutdownCtx.Done():
	case <-deadline.C:
	}

	// Best-effort orderly shutdown.
	shutdownDone := make(chan struct{})
	go func() {
		_ = wt.Close()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
	}

	if protocolFailure.Load() {
		os.Exit(1)
	}
	os.Exit(0)
}

// echoSession runs the per-session echo loop:
//
//   - datagrams: read in a loop, write each one back as a datagram;
//   - uni streams: accept, drain into memory, open a server-initiated
//     uni stream and write the bytes back.
//
// Returns when the peer closes the session (clean) or when any
// send/receive call fails fatally.
func echoSession(session *webtransport.Session) error {
	ctx := session.Context()

	var wg sync.WaitGroup
	wg.Add(2)

	errCh := make(chan error, 2)

	// Datagram echo.
	go func() {
		defer wg.Done()
		for {
			payload, err := session.ReceiveDatagram(ctx)
			if err != nil {
				if isCleanShutdown(err) || ctx.Err() != nil {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("ReceiveDatagram: %w", err)
				return
			}
			if err := session.SendDatagram(payload); err != nil {
				if isCleanShutdown(err) {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("SendDatagram: %w", err)
				return
			}
		}
	}()

	// Uni-stream echo.
	go func() {
		defer wg.Done()
		for {
			stream, err := session.AcceptUniStream(ctx)
			if err != nil {
				if isCleanShutdown(err) || ctx.Err() != nil {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("AcceptUniStream: %w", err)
				return
			}
			payload, err := io.ReadAll(stream)
			if err != nil {
				errCh <- fmt.Errorf("read uni stream: %w", err)
				return
			}
			out, err := session.OpenUniStream()
			if err != nil {
				if isCleanShutdown(err) {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("OpenUniStream: %w", err)
				return
			}
			if _, err := out.Write(payload); err != nil {
				errCh <- fmt.Errorf("write uni stream: %w", err)
				_ = out.Close()
				return
			}
			if err := out.Close(); err != nil {
				errCh <- fmt.Errorf("close uni stream: %w", err)
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func isCleanShutdown(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	// webtransport-go returns *webtransport.SessionError /
	// *webtransport.ConnectionError on graceful close; we treat any
	// of those plus the various `closed` strings as benign.
	msg := err.Error()
	return strings.Contains(msg, "closed") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "session is closed") ||
		strings.Contains(msg, "Application error 0x0")
}
