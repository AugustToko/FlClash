package inspectionruntime

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCertificate(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{host},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey, Leaf: leaf}, roots
}

type fixture struct {
	runtime        *Runtime
	password       string
	roots          *x509.CertPool
	dials          atomic.Int32
	requests       atomic.Int32
	observationMu  sync.Mutex
	observations   []Observation
	captureSession atomic.Value
}

func (f *fixture) setCaptureSession(value string) {
	f.captureSession.Store(value)
}

func (f *fixture) getCaptureSession() string {
	value, _ := f.captureSession.Load().(string)
	return value
}

func (f *fixture) observationSnapshot() []Observation {
	f.observationMu.Lock()
	defer f.observationMu.Unlock()
	return append([]Observation(nil), f.observations...)
}

func newFixture(t *testing.T, originHost string, trustOrigin bool) *fixture {
	t.Helper()
	f := &fixture{}
	f.setCaptureSession("http-capture:fixture")
	upstreamCert, upstreamRoots := testCertificate(t, originHost)
	downstreamCert, downstreamRoots := testCertificate(t, "api.example.com")
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		w.Header().Set("Set-Cookie", "session=private-test-cookie")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "private-response-body")
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{upstreamCert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	if !trustOrigin {
		upstreamRoots = x509.NewCertPool()
	}
	config := Config{
		Authorize: func(ctx context.Context, host string) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if host != "api.example.com" {
				return errors.New("not allowed")
			}
			return nil
		},
		Leaf: func(ctx context.Context, host string) (*tls.Certificate, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if host != "api.example.com" {
				return nil, errors.New("not allowed")
			}
			return &downstreamCert, nil
		},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			f.dials.Add(1)
			if address != "api.example.com:443" || network != "tcp" {
				return nil, errors.New("wrong routed target")
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", origin.Listener.Addr().String())
		},
		CaptureSession: f.getCaptureSession,
		Observe: func(value Observation) {
			f.observationMu.Lock()
			f.observations = append(f.observations, value)
			f.observationMu.Unlock()
		},
		Roots: upstreamRoots,
	}
	var err error
	f.runtime, f.password, err = Start(config)
	if err != nil {
		t.Fatal(err)
	}
	f.roots = downstreamRoots
	t.Cleanup(func() {
		f.runtime.Stop()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := f.runtime.Wait(ctx); err != nil {
			t.Errorf("runtime did not stop: %v", err)
		}
	})
	return f
}

func (f *fixture) connect(t *testing.T, authority, auth, extra string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", f.runtime.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s%s\r\n", authority, authority, auth, extra)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, response
}

func (f *fixture) auth() string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("flclash:"+f.password)) + "\r\n"
}

func TestRuntimeCarriesVerifiedHTTPSOverIndependentTLSConnections(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			f := newFixture(t, "api.example.com", true)
			conn, reader, response := f.connect(t, "api.example.com:443", f.auth(), "")
			if response.StatusCode != 200 {
				t.Fatalf("CONNECT status: %d", response.StatusCode)
			}
			client := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
				RootCAs: f.roots, ServerName: "api.example.com", MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"},
			})
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if client.ConnectionState().Version != version {
				t.Fatal("wrong client TLS version")
			}
			_, err := io.WriteString(client, "GET /items?token=private-query HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer private-token\r\nConnection: close\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			result, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "GET"})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(result.Body)
			if err != nil {
				t.Fatal(err)
			}
			if result.StatusCode != 201 || string(body) != "private-response-body" || result.Header.Get("Set-Cookie") != "session=private-test-cookie" {
				t.Fatal("relay changed HTTP response")
			}
			if f.dials.Load() != 1 || f.requests.Load() != 1 {
				t.Fatal("request did not use injected routed dial path exactly once")
			}
			encoded, err := json.Marshal(f.runtime.Status())
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{f.password, "private-query", "private-token", "private-response-body", "private-test-cookie", "api.example.com", "PRIVATE KEY"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatal("runtime status retained sensitive traffic")
				}
			}
		})
	}
}

func TestRuntimeRejectsMissingOrInvalidAuthenticationBeforeDial(t *testing.T) {
	for _, auth := range []string{"", "Proxy-Authorization: Basic invalid\r\n", "Proxy-Authorization: Basic YTpi\r\nProxy-Authorization: Basic YTpi\r\n"} {
		f := newFixture(t, "api.example.com", true)
		_, _, response := f.connect(t, "api.example.com:443", auth, "")
		if response.StatusCode != 407 || f.dials.Load() != 0 {
			t.Fatalf("unexpected auth result: %d, %d dials", response.StatusCode, f.dials.Load())
		}
	}
}

func TestRuntimeRejectsUnsafeCONNECTTargetsBeforeDial(t *testing.T) {
	for _, authority := range []string{"api.example.com:80", "127.0.0.1:443", "[::1]:443", "localhost:443", "co.uk:443", "outside.example.com:443", "api.example.com.:443", "api.example.com:0443", "user@api.example.com:443"} {
		t.Run(authority, func(t *testing.T) {
			f := newFixture(t, "api.example.com", true)
			_, _, response := f.connect(t, authority, f.auth(), "")
			if response.StatusCode == 200 || f.dials.Load() != 0 {
				t.Fatal("unsafe CONNECT was dialed")
			}
		})
	}
}

func TestRuntimeRejectsCONNECTBodiesBeforeDial(t *testing.T) {
	for _, extra := range []string{"Content-Length: 0\r\n", "Content-Length: 12\r\n", "Transfer-Encoding: chunked\r\n"} {
		f := newFixture(t, "api.example.com", true)
		_, _, response := f.connect(t, "api.example.com:443", f.auth(), extra)
		if response.StatusCode == 200 || f.dials.Load() != 0 {
			t.Fatal("body-bearing CONNECT was dialed")
		}
	}
}

func TestRuntimeUpstreamCertificateFailureNeverReleasesApplicationPayload(t *testing.T) {
	for _, scenario := range []struct {
		host  string
		trust bool
	}{{"wrong.example.com", true}, {"api.example.com", false}} {
		f := newFixture(t, scenario.host, scenario.trust)
		_, _, response := f.connect(t, "api.example.com:443", f.auth(), "")
		if response.StatusCode != 502 || f.requests.Load() != 0 {
			t.Fatal("unverified upstream accepted application request")
		}
	}
}

func TestRuntimeRequiresMatchingSNIAndHTTP1ALPN(t *testing.T) {
	for _, scenario := range []struct {
		host      string
		protocols []string
	}{{"other.example.com", []string{"http/1.1"}}, {"api.example.com", []string{"h2"}}} {
		f := newFixture(t, "api.example.com", true)
		conn, reader, response := f.connect(t, "api.example.com:443", f.auth(), "")
		if response.StatusCode != 200 {
			t.Fatal("valid CONNECT failed")
		}
		client := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{RootCAs: f.roots, ServerName: scenario.host, MinVersion: tls.VersionTLS12, NextProtos: scenario.protocols})
		if err := client.Handshake(); err == nil {
			t.Fatal("invalid client TLS negotiated")
		}
		if f.requests.Load() != 0 {
			t.Fatal("invalid TLS client reached HTTP origin")
		}
	}
}

func TestRuntimeStopClosesPreauthClientsAndListener(t *testing.T) {
	f := newFixture(t, "api.example.com", true)
	conn, err := net.DialTimeout("tcp", f.runtime.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f.runtime.Stop()
	f.runtime.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.runtime.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if f.runtime.Status().State != "stopped" || f.runtime.Status().Active != 0 {
		t.Fatal("stopped runtime remains active")
	}
	late, err := net.DialTimeout("tcp", f.runtime.address, 100*time.Millisecond)
	if err == nil {
		late.Close()
		t.Fatal("stopped listener accepted connection")
	}
	if f.dials.Load() != 0 {
		t.Fatal("preauth client dialed upstream")
	}
}

func TestRuntimeListenerAndCredentialAreBounded(t *testing.T) {
	f := newFixture(t, "api.example.com", true)
	host, _, err := net.SplitHostPort(f.runtime.Status().Address)
	if err != nil || host != "127.0.0.1" || len(f.password) != 64 || len(f.runtime.Status().ID) != 32 {
		t.Fatal("invalid listener or credential")
	}
	if f.runtime.Status().ExpiresAt.Sub(time.Now()) > SessionLifetime {
		t.Fatal("unbounded runtime lifetime")
	}
}

func TestConnectHeaderBoundsAndMalformedLines(t *testing.T) {
	for _, input := range []string{strings.Repeat("x", MaxConnectHeader+1), "CONNECT a:443 HTTP/1.1\n\n", "CONNECT a:443 HTTP/1.1\r\nBroken\r\n\r\n"} {
		if _, err := readConnect(bufio.NewReaderSize(strings.NewReader(input), MaxConnectHeader)); err == nil {
			t.Fatal("malformed header accepted")
		}
	}
}

func TestConnectRejectsHiddenHostMismatchAndFoldedFields(t *testing.T) {
	for _, headers := range []string{
		"Host: different.example.com:443\r\n",
		"Host: api.example.com:443\r\nHost: api.example.com:443\r\n",
		"Host: api.example.com:443\r\n X-Folded: hidden\r\n",
		"",
	} {
		input := "CONNECT api.example.com:443 HTTP/1.1\r\n" + headers + "\r\n"
		if _, err := readConnect(bufio.NewReader(strings.NewReader(input))); err == nil {
			t.Fatalf("unsafe raw Host headers accepted: %q", headers)
		}
	}
}

func TestRuntimeRevocationInterruptsEstablishedRelay(t *testing.T) {
	f := newFixture(t, "api.example.com", true)
	conn, reader, response := f.connect(t, "api.example.com:443", f.auth(), "")
	if response.StatusCode != 200 {
		t.Fatal("valid CONNECT failed")
	}
	client := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{RootCAs: f.roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	f.runtime.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.runtime.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if f.runtime.Status().Active != 0 {
		t.Fatal("revoked relay retained clients")
	}
	if f.requests.Load() != 0 {
		t.Fatal("idle relay sent HTTP data")
	}
}

func TestRuntimeBoundsIdleUnauthenticatedClients(t *testing.T) {
	f := newFixture(t, "api.example.com", true)
	for i := 0; i < MaxClients+3; i++ {
		conn, err := net.DialTimeout("tcp", f.runtime.address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}
	deadline := time.Now().Add(time.Second)
	for f.runtime.Status().Active < MaxClients && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active := f.runtime.Status().Active; active != MaxClients {
		t.Fatalf("unexpected active client count %d", active)
	}
	if f.dials.Load() != 0 {
		t.Fatal("unauthenticated clients dialed")
	}
	f.runtime.Stop()
}

func TestRuntimeKeepsResponseReadableAfterClientTLSHalfClose(t *testing.T) {
	f := newFixture(t, "api.example.com", true)
	conn, reader, response := f.connect(t, "api.example.com:443", f.auth(), "")
	if response.StatusCode != 200 {
		t.Fatal("CONNECT failed")
	}
	client := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{RootCAs: f.roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(result.Body)
	if err != nil || string(body) != "private-response-body" {
		t.Fatal("client half-close truncated response")
	}
}

func TestRuntimePublishesCaptureMetadataWithoutPayloads(t *testing.T) {
	f := newFixture(t, "api.example.com", true)
	conn, reader, response := f.connect(t, "api.example.com:443", f.auth(), "")
	if response.StatusCode != http.StatusOK {
		t.Fatal("CONNECT failed")
	}
	client := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
		RootCAs: f.roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	responseReader := bufio.NewReader(client)
	requests := []struct {
		target string
		close  bool
	}{
		{target: "/private-one?token=first-secret"},
		{target: "/private-two?token=second-secret", close: true},
	}
	for index, request := range requests {
		connection := ""
		if request.close {
			connection = "Connection: close\r\n"
		}
		if _, err := fmt.Fprintf(
			client,
			"GET %s HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer secret-%d\r\n%s\r\n",
			request.target,
			index+1,
			connection,
		); err != nil {
			t.Fatal(err)
		}
		result, err := http.ReadResponse(
			responseReader,
			&http.Request{Method: http.MethodGet},
		)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(result.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = result.Body.Close()
		if result.StatusCode != http.StatusCreated ||
			string(body) != "private-response-body" ||
			result.Header.Get("Set-Cookie") != "session=private-test-cookie" {
			t.Fatal("relay changed a keep-alive HTTP response")
		}
	}

	deadline := time.Now().Add(time.Second)
	var observations []Observation
	for time.Now().Before(deadline) {
		observations = f.observationSnapshot()
		if len(observations) != 0 && observations[len(observations)-1].State != "running" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(observations) < 6 {
		t.Fatalf("observation count = %d, want incremental timeline and terminal events", len(observations))
	}
	started, completed := observations[0], observations[len(observations)-1]
	firstRequestIndex := -1
	firstResponseIndex := -1
	secondRequestIndex := -1
	secondResponseIndex := -1
	for index, observation := range observations {
		if observation.SessionID != "http-capture:fixture" ||
			observation.ConnectionID == "" || observation.ConnectionID != started.ConnectionID ||
			observation.RuntimeID != f.runtime.id || observation.Host != "api.example.com" {
			t.Fatalf("observation identity changed at %d: %#v", index, observation)
		}
		if len(observation.HTTPTransactions) >= 1 && firstRequestIndex == -1 {
			firstRequestIndex = index
		}
		if len(observation.HTTPTransactions) >= 1 &&
			observation.HTTPTransactions[0].Response != nil && firstResponseIndex == -1 {
			firstResponseIndex = index
		}
		if len(observation.HTTPTransactions) >= 2 && secondRequestIndex == -1 {
			secondRequestIndex = index
		}
		if len(observation.HTTPTransactions) >= 2 &&
			observation.HTTPTransactions[1].Response != nil && secondResponseIndex == -1 {
			secondResponseIndex = index
		}
	}
	if started.State != "running" || completed.State != "completed" ||
		firstRequestIndex <= 0 || firstResponseIndex <= firstRequestIndex ||
		secondRequestIndex <= firstResponseIndex || secondResponseIndex <= secondRequestIndex ||
		len(completed.HTTPTransactions) != 2 || completed.HTTPTransactionsTruncated {
		t.Fatalf("unexpected timeline lifecycle: %#v", observations)
	}
	for index, target := range []string{"/private-one", "/private-two"} {
		transaction := completed.HTTPTransactions[index]
		if transaction.Sequence != index+1 || transaction.Request.Method != "GET" ||
			transaction.Request.Target != target ||
			transaction.Request.Host != "api.example.com" ||
			!slices.Contains(transaction.Request.HeaderNames, "authorization") ||
			transaction.Response == nil ||
			transaction.Response.StatusCode != http.StatusCreated ||
			!slices.Contains(transaction.Response.HeaderNames, "set-cookie") ||
			transaction.Response.ObservedAfterMilliseconds <
				transaction.RequestObservedAfterMilliseconds {
			t.Fatalf("unexpected transaction %d: %#v", index+1, transaction)
		}
	}
	if (completed.DownstreamTLSVersion != "TLS 1.2" && completed.DownstreamTLSVersion != "TLS 1.3") ||
		completed.UpstreamTLSVersion == "" || completed.ALPN != "http/1.1" ||
		completed.Uploaded == 0 || completed.Downloaded == 0 ||
		completed.CompletedAt == nil || completed.CompletedAt.Before(completed.StartedAt) ||
		f.requests.Load() != 2 {
		t.Fatalf("unexpected terminal observation: %#v", completed)
	}
	encoded, err := json.Marshal(observations)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"first-secret", "second-secret", "Bearer secret-1", "Bearer secret-2",
		"private-response-body", "private-test-cookie", f.password,
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("capture metadata retained %q", secret)
		}
	}
}

func TestRuntimeStopsHTTPMetadataWhenCaptureSessionChanges(t *testing.T) {
	f := newFixture(t, "api.example.com", true)
	conn, reader, response := f.connect(t, "api.example.com:443", f.auth(), "")
	if response.StatusCode != http.StatusOK {
		t.Fatal("CONNECT failed")
	}
	client := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
		RootCAs: f.roots, ServerName: "api.example.com", MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	f.setCaptureSession("http-capture:new-session")
	if _, err := io.WriteString(client, "GET /private?token=secret HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	result, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(result.Body); err != nil {
		t.Fatal(err)
	}
	_ = result.Body.Close()
	deadline := time.Now().Add(time.Second)
	var observations []Observation
	for time.Now().Before(deadline) {
		observations = f.observationSnapshot()
		if len(observations) != 0 && observations[len(observations)-1].State != "running" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(observations) < 2 || observations[0].SessionID != "http-capture:fixture" {
		t.Fatalf("missing original lifecycle observations: %#v", observations)
	}
	for _, observation := range observations {
		if len(observation.HTTPTransactions) != 0 ||
			observation.HTTPTransactionsTruncated {
			t.Fatalf("stale capture session retained HTTP metadata: %#v", observation)
		}
	}
}

func TestRuntimeCaptureSessionIsSnapshottedAndOptional(t *testing.T) {
	f := newFixture(t, "api.example.com", false)
	f.setCaptureSession("")
	_, _, response := f.connect(t, "api.example.com:443", f.auth(), "")
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.StatusCode)
	}
	if len(f.observationSnapshot()) != 0 {
		t.Fatal("runtime emitted capture metadata without an active session")
	}

	f.setCaptureSession("http-capture:session-a")
	_, _, response = f.connect(t, "api.example.com:443", f.auth(), "")
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.StatusCode)
	}
	deadline := time.Now().Add(time.Second)
	for len(f.observationSnapshot()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	observations := f.observationSnapshot()
	if len(observations) != 2 || observations[0].SessionID != "http-capture:session-a" ||
		observations[1].SessionID != "http-capture:session-a" ||
		observations[1].State != "failed" || observations[1].FailureKind != "upstream-tls" {
		t.Fatalf("unexpected failed observations: %#v", observations)
	}
}
