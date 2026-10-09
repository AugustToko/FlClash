package inspectionruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	MaxClients         = 16
	MaxConnectHeader   = 8192
	SessionLifetime    = 10 * time.Minute
	ConnectionLifetime = 120 * time.Second
	HandshakeTimeout   = 5 * time.Second
)

type Config struct {
	ID                    string
	Authorize             func(context.Context, string) error
	Leaf                  func(context.Context, string) (*tls.Certificate, error)
	Dial                  func(context.Context, string, string) (net.Conn, error)
	CaptureSession        func() string
	CaptureSessionChanged func() <-chan struct{}
	CapturePolicy         func() CapturePolicy
	Observe               func(Observation)
	Roots                 *x509.CertPool
}

type Observation struct {
	SessionID                               string                       `json:"sessionId"`
	ConnectionID                            string                       `json:"connectionId"`
	RuntimeID                               string                       `json:"runtimeId"`
	Host                                    string                       `json:"host"`
	State                                   string                       `json:"state"`
	StartedAt                               time.Time                    `json:"startedAt"`
	CompletedAt                             *time.Time                   `json:"completedAt,omitempty"`
	DownstreamTLSVersion                    string                       `json:"downstreamTlsVersion,omitempty"`
	UpstreamTLSVersion                      string                       `json:"upstreamTlsVersion,omitempty"`
	ALPN                                    string                       `json:"alpn,omitempty"`
	Uploaded                                uint64                       `json:"uploaded"`
	Downloaded                              uint64                       `json:"downloaded"`
	FailureKind                             string                       `json:"failureKind,omitempty"`
	DownstreamTLSCompletedAfterMilliseconds int64                        `json:"downstreamTlsCompletedAfterMilliseconds,omitempty"`
	UpstreamDialCompletedAfterMilliseconds  int64                        `json:"upstreamDialCompletedAfterMilliseconds,omitempty"`
	UpstreamTLSCompletedAfterMilliseconds   int64                        `json:"upstreamTlsCompletedAfterMilliseconds,omitempty"`
	CapturePolicy                           *CapturePolicy               `json:"capturePolicy,omitempty"`
	HTTPTransactions                        []HTTPTransactionObservation `json:"httpTransactions,omitempty"`
	HTTPTransactionsTruncated               bool                         `json:"httpTransactionsTruncated,omitempty"`
	HTTP2Streams                            []HTTP2StreamObservation     `json:"http2Streams,omitempty"`
	HTTP2StreamsTruncated                   bool                         `json:"http2StreamsTruncated,omitempty"`
	HTTP2GoAway                             *HTTP2GoAwayObservation      `json:"http2GoAway,omitempty"`
}

type Status struct {
	ID         string    `json:"id"`
	State      string    `json:"state"`
	Address    string    `json:"address"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Active     int       `json:"active"`
	Accepted   uint64    `json:"accepted"`
	Completed  uint64    `json:"completed"`
	Failed     uint64    `json:"failed"`
	Uploaded   uint64    `json:"uploaded"`
	Downloaded uint64    `json:"downloaded"`
}

type Runtime struct {
	config               Config
	id                   string
	address              string
	expiresAt            time.Time
	authHash             [32]byte
	ctx                  context.Context
	cancel               context.CancelFunc
	listener             net.Listener
	mu                   sync.Mutex
	clients              map[net.Conn]context.CancelFunc
	accepted             uint64
	completed            uint64
	failed               uint64
	uploaded             uint64
	downloaded           uint64
	observationSequence  uint64
	captureBudgetMu      sync.Mutex
	captureBodyBySession map[string]int
	done                 chan struct{}
	workers              sync.WaitGroup
	stopOnce             sync.Once
}

func Start(config Config) (*Runtime, string, error) {
	if config.Authorize == nil || config.Leaf == nil || config.Dial == nil {
		return nil, "", errors.New("inspection runtime requires authorization, leaf and routed dial callbacks")
	}
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, "", errors.New("inspection runtime entropy unavailable")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", errors.New("inspection loopback listener unavailable")
	}
	id := hex.EncodeToString(entropy[:16])
	if config.ID != "" {
		decoded, decodeErr := hex.DecodeString(config.ID)
		if decodeErr != nil || len(decoded) != 16 || strings.ToLower(config.ID) != config.ID {
			_ = listener.Close()
			return nil, "", errors.New("invalid runtime identity")
		}
		id = config.ID
	}
	password := hex.EncodeToString(entropy[16:])
	expiresAt := time.Now().UTC().Add(SessionLifetime)
	ctx, cancel := context.WithDeadline(context.Background(), expiresAt)
	r := &Runtime{
		config: config, id: id,
		address: listener.Addr().String(), expiresAt: expiresAt,
		authHash: sha256.Sum256([]byte("Basic " + base64.StdEncoding.EncodeToString([]byte("flclash:"+password)))),
		ctx:      ctx, cancel: cancel, listener: listener,
		clients:              make(map[net.Conn]context.CancelFunc),
		captureBodyBySession: make(map[string]int), done: make(chan struct{}),
	}
	context.AfterFunc(ctx, r.Stop)
	go r.accept()
	return r, password, nil
}

func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := "running"
	if r.ctx.Err() != nil {
		state = "stopped"
	}
	return Status{
		ID: r.id, State: state, Address: r.address, ExpiresAt: r.expiresAt,
		Active: len(r.clients), Accepted: r.accepted, Completed: r.completed,
		Failed: r.failed, Uploaded: r.uploaded, Downloaded: r.downloaded,
	}
}

func (r *Runtime) Stop() {
	r.stopOnce.Do(func() {
		r.cancel()
		_ = r.listener.Close()
		r.mu.Lock()
		for conn, cancel := range r.clients {
			cancel()
			_ = conn.Close()
		}
		r.mu.Unlock()
	})
}

func (r *Runtime) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runtime) accept() {
	defer func() {
		if recover() != nil {
			r.Stop()
		}
		r.workers.Wait()
		close(r.done)
	}()
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			r.Stop()
			return
		}
		r.mu.Lock()
		if r.ctx.Err() != nil || len(r.clients) >= MaxClients {
			r.mu.Unlock()
			_ = conn.Close()
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, ConnectionLifetime)
		r.clients[conn] = cancel
		r.accepted++
		r.workers.Add(1)
		r.mu.Unlock()
		go r.serve(ctx, cancel, conn)
	}
}

func (r *Runtime) serve(ctx context.Context, cancel context.CancelFunc, conn net.Conn) {
	var failure error
	defer r.workers.Done()
	defer func() {
		if recover() != nil {
			failure = errors.New("inspection connection failed")
		}
		cancel()
		_ = conn.Close()
		r.mu.Lock()
		delete(r.clients, conn)
		if failure != nil {
			r.failed++
		} else {
			r.completed++
		}
		r.mu.Unlock()
	}()
	failure = r.exchange(ctx, conn)
}

func readConnect(reader *bufio.Reader) (*http.Request, error) {
	var header bytes.Buffer
	for header.Len() <= MaxConnectHeader {
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) < 2 || line[len(line)-2] != '\r' || header.Len()+len(line) > MaxConnectHeader {
			return nil, errors.New("invalid CONNECT header")
		}
		header.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header.Bytes())))
			if err != nil {
				return nil, errors.New("invalid CONNECT request")
			}
			hostCount := 0
			for _, raw := range strings.Split(header.String(), "\r\n")[1:] {
				if raw == "" {
					continue
				}
				if raw[0] == ' ' || raw[0] == '\t' {
					return nil, errors.New("folded CONNECT header is unsupported")
				}
				name, value, ok := strings.Cut(raw, ":")
				if !ok {
					return nil, errors.New("invalid CONNECT field")
				}
				if strings.EqualFold(name, "Host") {
					hostCount++
					if strings.TrimSpace(value) != request.RequestURI {
						return nil, errors.New("CONNECT Host mismatch")
					}
				}
				if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") {
					return nil, errors.New("CONNECT body framing is unsupported")
				}
			}
			if hostCount != 1 {
				return nil, errors.New("CONNECT requires exactly one Host")
			}
			return request, nil
		}
	}
	return nil, errors.New("CONNECT header exceeds limit")
}

func connectHost(request *http.Request) (string, error) {
	if request.Method != http.MethodConnect || request.Proto != "HTTP/1.1" ||
		request.Host != request.RequestURI || request.URL.Host != request.RequestURI ||
		request.URL.Scheme != "" || request.URL.User != nil || request.URL.Path != "" ||
		request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		len(request.Header.Values("Content-Length")) != 0 || len(request.Header.Values("Transfer-Encoding")) != 0 {
		return "", errors.New("CONNECT requires a bodyless DNS authority")
	}
	host, port, err := net.SplitHostPort(request.RequestURI)
	if err != nil || port != "443" || len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", errors.New("CONNECT requires a DNS host on port 443")
	}
	host = strings.ToLower(host)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid CONNECT DNS host")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("invalid CONNECT DNS host")
			}
		}
	}
	return host, nil
}

func reject(conn net.Conn, status int) error {
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	challenge := ""
	if status == http.StatusProxyAuthRequired {
		challenge = "Proxy-Authenticate: Basic realm=\"FlClash local inspection\"\r\n"
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status), challenge)
	return errors.New("inspection CONNECT rejected")
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return ""
	}
}

func (r *Runtime) captureSession() (session string) {
	if r.config.CaptureSession == nil || r.config.Observe == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			session = ""
		}
	}()
	session = strings.TrimSpace(r.config.CaptureSession())
	if len(session) > 128 || !strings.HasPrefix(session, "http-capture:") {
		return ""
	}
	return session
}

func (r *Runtime) capturePolicy(session string) (policy CapturePolicy) {
	if session == "" || r.config.CapturePolicy == nil {
		return CapturePolicy{}
	}
	defer func() {
		if recover() != nil {
			policy = CapturePolicy{}
		}
	}()
	return r.config.CapturePolicy().Normalize()
}

func (r *Runtime) reserveBodyCapture(
	observation *runtimeObservation,
	requested int,
) int {
	if observation == nil || requested <= 0 {
		return 0
	}
	observation.bodyBudgetMu.Lock()
	defer observation.bodyBudgetMu.Unlock()
	connectionRemaining := observation.policy.ConnectionBodyLimit() -
		observation.capturedBodyBytes
	if connectionRemaining <= 0 {
		return 0
	}
	if requested > connectionRemaining {
		requested = connectionRemaining
	}
	sessionID := observation.value.SessionID
	sessionLimit := observation.policy.SessionBodyLimit()
	if sessionID == "" || sessionLimit <= 0 {
		return 0
	}
	r.captureBudgetMu.Lock()
	defer r.captureBudgetMu.Unlock()
	for existing := range r.captureBodyBySession {
		if existing != sessionID {
			delete(r.captureBodyBySession, existing)
		}
	}
	sessionRemaining := sessionLimit - r.captureBodyBySession[sessionID]
	if sessionRemaining <= 0 {
		return 0
	}
	if requested > sessionRemaining {
		requested = sessionRemaining
	}
	observation.capturedBodyBytes += requested
	r.captureBodyBySession[sessionID] += requested
	return requested
}

func (r *Runtime) captureSessionChangeSignal() (signal <-chan struct{}) {
	if r.config.CaptureSessionChanged == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			signal = nil
		}
	}()
	return r.config.CaptureSessionChanged()
}

func (r *Runtime) publishObservation(value Observation) {
	if r.config.Observe == nil {
		return
	}
	defer func() { _ = recover() }()
	r.config.Observe(value)
}

type runtimeObservation struct {
	mu                sync.Mutex
	publishMu         sync.Mutex
	bodyBudgetMu      sync.Mutex
	value             Observation
	policy            CapturePolicy
	capturedBodyBytes int
	finished          bool
}

func cloneHTTPRequestObservation(value *HTTPRequestObservation) *HTTPRequestObservation {
	if value == nil {
		return nil
	}
	result := *value
	result.HeaderNames = append([]string(nil), value.HeaderNames...)
	result.Headers = cloneHTTPHeaderObservations(value.Headers)
	return &result
}

func cloneHTTPResponseObservation(value *HTTPResponseObservation) *HTTPResponseObservation {
	if value == nil {
		return nil
	}
	result := *value
	result.InformationalStatusCodes = append([]int(nil), value.InformationalStatusCodes...)
	result.HeaderNames = append([]string(nil), value.HeaderNames...)
	result.Headers = cloneHTTPHeaderObservations(value.Headers)
	return &result
}

func cloneObservation(value Observation) Observation {
	if value.CapturePolicy != nil {
		policy := value.CapturePolicy.Normalize()
		value.CapturePolicy = &policy
	}
	value.HTTPTransactions = cloneHTTPTransactionObservations(value.HTTPTransactions)
	value.HTTP2Streams = cloneHTTP2StreamObservations(value.HTTP2Streams)
	value.HTTP2GoAway = cloneHTTP2GoAwayObservation(value.HTTP2GoAway)
	return value
}

func (r *Runtime) beginObservation(host string) *runtimeObservation {
	session := r.captureSession()
	if session == "" {
		return nil
	}
	policy := r.capturePolicy(session)
	r.mu.Lock()
	r.observationSequence++
	sequence := r.observationSequence
	r.mu.Unlock()
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", r.id, sequence)))
	value := Observation{
		SessionID: session, ConnectionID: hex.EncodeToString(digest[:16]),
		RuntimeID: r.id, Host: host, State: "running", StartedAt: time.Now().UTC(),
		CapturePolicy: &policy,
	}
	observation := &runtimeObservation{value: value, policy: policy}
	r.publishObservation(cloneObservation(value))
	return observation
}

func (r *Runtime) updateObservation(observation *runtimeObservation, update func(*Observation)) {
	if observation == nil || update == nil {
		return
	}
	activeSession := r.captureSession()
	observation.mu.Lock()
	if observation.finished || observation.value.SessionID != activeSession {
		observation.mu.Unlock()
		return
	}
	update(&observation.value)
	snapshot := cloneObservation(observation.value)
	observation.publishMu.Lock()
	observation.mu.Unlock()
	r.publishObservation(snapshot)
	observation.publishMu.Unlock()
}

func (r *Runtime) publishHTTPTransactions(
	observation *runtimeObservation,
	transactions []HTTPTransactionObservation,
	truncated bool,
) {
	if observation == nil {
		return
	}
	activeSession := r.captureSession()
	observation.mu.Lock()
	if observation.finished || observation.value.SessionID != activeSession {
		observation.mu.Unlock()
		return
	}
	observation.value.HTTPTransactions = cloneHTTPTransactionObservations(transactions)
	observation.value.HTTPTransactionsTruncated =
		observation.value.HTTPTransactionsTruncated || truncated
	snapshot := cloneObservation(observation.value)
	observation.publishMu.Lock()
	observation.mu.Unlock()
	r.publishObservation(snapshot)
	observation.publishMu.Unlock()
}

func (r *Runtime) publishHTTP2Streams(
	observation *runtimeObservation,
	streams []HTTP2StreamObservation,
	truncated bool,
	goAway *HTTP2GoAwayObservation,
) {
	if observation == nil {
		return
	}
	activeSession := r.captureSession()
	observation.mu.Lock()
	if observation.finished || observation.value.SessionID != activeSession {
		observation.mu.Unlock()
		return
	}
	observation.value.HTTP2Streams = cloneHTTP2StreamObservations(streams)
	observation.value.HTTP2StreamsTruncated =
		observation.value.HTTP2StreamsTruncated || truncated
	observation.value.HTTP2GoAway = cloneHTTP2GoAwayObservation(goAway)
	snapshot := cloneObservation(observation.value)
	observation.publishMu.Lock()
	observation.mu.Unlock()
	r.publishObservation(snapshot)
	observation.publishMu.Unlock()
}

func (r *Runtime) finishObservation(
	observation *runtimeObservation,
	failure error,
	failureKind string,
	uploaded uint64,
	downloaded uint64,
) {
	if observation == nil {
		return
	}
	observation.mu.Lock()
	if observation.finished {
		observation.mu.Unlock()
		return
	}
	observation.finished = true
	completedAt := time.Now().UTC()
	observation.value.CompletedAt = &completedAt
	observation.value.Uploaded = uploaded
	observation.value.Downloaded = downloaded
	if failure == nil {
		observation.value.State = "completed"
	} else {
		observation.value.State = "failed"
		observation.value.FailureKind = failureKind
	}
	snapshot := cloneObservation(observation.value)
	observation.publishMu.Lock()
	observation.mu.Unlock()
	r.publishObservation(snapshot)
	observation.publishMu.Unlock()
}

func (observation *runtimeObservation) startedAt() time.Time {
	if observation == nil {
		return time.Time{}
	}
	observation.mu.Lock()
	defer observation.mu.Unlock()
	return observation.value.StartedAt
}

func (observation *runtimeObservation) host() string {
	if observation == nil {
		return ""
	}
	observation.mu.Lock()
	defer observation.mu.Unlock()
	return observation.value.Host
}

func (observation *runtimeObservation) activeFor(sessionID string) bool {
	if observation == nil || sessionID == "" {
		return false
	}
	observation.mu.Lock()
	defer observation.mu.Unlock()
	return !observation.finished && observation.value.SessionID == sessionID
}

func (r *Runtime) exchange(ctx context.Context, conn net.Conn) (failure error) {
	var observation *runtimeObservation
	var uploaded uint64
	var downloaded uint64
	failureKind := ""
	defer func() {
		r.finishObservation(observation, failure, failureKind, uploaded, downloaded)
	}()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	reader := bufio.NewReaderSize(conn, MaxConnectHeader)
	request, err := readConnect(reader)
	if err != nil {
		failure = reject(conn, http.StatusBadRequest)
		return failure
	}
	defer request.Body.Close()
	values := request.Header.Values("Proxy-Authorization")
	if len(values) != 1 || len(values[0]) > 256 {
		failure = reject(conn, http.StatusProxyAuthRequired)
		return failure
	}
	provided := sha256.Sum256([]byte(values[0]))
	if subtle.ConstantTimeCompare(provided[:], r.authHash[:]) != 1 {
		failure = reject(conn, http.StatusProxyAuthRequired)
		return failure
	}
	host, err := connectHost(request)
	if err != nil {
		failure = reject(conn, http.StatusBadRequest)
		return failure
	}
	if err := r.config.Authorize(ctx, host); err != nil || ctx.Err() != nil {
		failure = reject(conn, http.StatusForbidden)
		return failure
	}
	observation = r.beginObservation(host)
	failureKind = "upstream-dial"
	rawUpstream, err := r.config.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		failure = reject(conn, http.StatusBadGateway)
		return failure
	}
	defer rawUpstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = rawUpstream.Close() })
	defer stopUpstream()
	var upstreamDialCompletedAfterMilliseconds int64
	if observation != nil {
		upstreamDialCompletedAfterMilliseconds = elapsedMilliseconds(observation.startedAt())
	}
	upstream := tls.Client(rawUpstream, &tls.Config{
		ServerName: host, RootCAs: r.config.Roots, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"}, SessionTicketsDisabled: true,
	})
	failureKind = "upstream-tls"
	_ = rawUpstream.SetDeadline(time.Now().Add(HandshakeTimeout))
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, HandshakeTimeout)
	err = upstream.HandshakeContext(handshakeCtx)
	cancelHandshake()
	_ = rawUpstream.SetDeadline(time.Time{})
	if err != nil {
		failure = reject(conn, http.StatusBadGateway)
		return failure
	}
	peer := upstream.ConnectionState()
	protocol := peer.NegotiatedProtocol
	if protocol == "" {
		protocol = "http/1.1"
	}
	if len(peer.VerifiedChains) == 0 ||
		(protocol != "http/1.1" && protocol != "h2") {
		failure = reject(conn, http.StatusBadGateway)
		return failure
	}
	r.updateObservation(observation, func(value *Observation) {
		value.UpstreamTLSVersion = tlsVersionName(peer.Version)
		value.UpstreamDialCompletedAfterMilliseconds = upstreamDialCompletedAfterMilliseconds
		value.UpstreamTLSCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
		value.ALPN = protocol
	})
	failureKind = "leaf"
	leaf, err := r.config.Leaf(ctx, host)
	if err != nil || leaf == nil || ctx.Err() != nil {
		failure = reject(conn, http.StatusForbidden)
		return failure
	}
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		failure = err
		return failure
	}
	downstream := tls.Server(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
		Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{protocol}, SessionTicketsDisabled: true,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if strings.ToLower(hello.ServerName) != host || ctx.Err() != nil {
				return nil, errors.New("inspection SNI does not match CONNECT host")
			}
			if len(hello.SupportedProtos) == 0 {
				if protocol == "h2" {
					return nil, errors.New("inspection client did not advertise negotiated HTTP/2")
				}
			} else {
				found := false
				for _, candidate := range hello.SupportedProtos {
					found = found || candidate == protocol
				}
				if !found {
					return nil, errors.New("inspection client and upstream ALPN do not match")
				}
			}
			return nil, r.config.Authorize(ctx, host)
		},
	})
	failureKind = "downstream-tls"
	handshakeCtx, cancelHandshake = context.WithTimeout(ctx, HandshakeTimeout)
	err = downstream.HandshakeContext(handshakeCtx)
	cancelHandshake()
	if err != nil {
		failure = errors.New("inspection client handshake failed")
		return failure
	}
	downstreamState := downstream.ConnectionState()
	downstreamProtocol := downstreamState.NegotiatedProtocol
	if downstreamProtocol == "" {
		downstreamProtocol = "http/1.1"
	}
	if downstreamProtocol != protocol {
		failure = errors.New("inspection client and upstream protocol mismatch")
		return failure
	}
	r.updateObservation(observation, func(value *Observation) {
		value.DownstreamTLSVersion = tlsVersionName(downstreamState.Version)
		value.DownstreamTLSCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
	})
	failureKind = "authorization-revoked"
	if err := r.config.Authorize(ctx, host); err != nil || ctx.Err() != nil {
		failure = errors.New("inspection authorization revoked")
		return failure
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	_ = rawUpstream.SetDeadline(deadline)
	failureKind = "relay"
	uploaded, downloaded, failure = r.relay(
		ctx, downstream, upstream, conn, rawUpstream, protocol, observation,
	)
	return failure
}

type httpMetadataTimeline interface {
	ObserveRequest([]byte)
	ObserveResponse([]byte)
	FinishRequest()
	FinishResponse()
	Abort()
}

func (r *Runtime) watchHTTPTimeline(
	ctx context.Context,
	observation *runtimeObservation,
	timeline httpMetadataTimeline,
	signal <-chan struct{},
	done <-chan struct{},
) {
	if observation == nil || timeline == nil || signal == nil {
		return
	}
	if !observation.activeFor(r.captureSession()) {
		timeline.Abort()
		return
	}
	select {
	case <-ctx.Done():
		timeline.Abort()
	case <-done:
	case <-signal:
		timeline.Abort()
	}
}

func (r *Runtime) watchHTTP1Timeline(
	ctx context.Context,
	observation *runtimeObservation,
	timeline *http1MetadataTimeline,
	signal <-chan struct{},
	done <-chan struct{},
) {
	r.watchHTTPTimeline(ctx, observation, timeline, signal, done)
}

func (r *Runtime) relay(
	ctx context.Context,
	client *tls.Conn,
	upstream *tls.Conn,
	rawClient net.Conn,
	rawUpstream net.Conn,
	protocol string,
	observation *runtimeObservation,
) (uint64, uint64, error) {
	type copied struct {
		upload bool
		n      int64
		err    error
	}
	results := make(chan copied, 2)
	var requestReader io.Reader = client
	var responseReader io.Reader = upstream
	var requestMetadataReader *metadataObservingReader
	var responseMetadataReader *metadataObservingReader
	if observation != nil {
		var timeline httpMetadataTimeline
		if protocol == "h2" {
			timeline = newHTTP2MetadataTimeline(
				observation.startedAt(),
				observation.host(),
				observation.policy,
				func(requested int) int {
					return r.reserveBodyCapture(observation, requested)
				},
				func(streams []HTTP2StreamObservation, truncated bool, goAway *HTTP2GoAwayObservation) {
					if observation.activeFor(r.captureSession()) {
						r.publishHTTP2Streams(observation, streams, truncated, goAway)
					}
				},
			)
		} else {
			timeline = newHTTP1MetadataTimelineWithPolicy(
				observation.startedAt(),
				observation.host(),
				observation.policy,
				func(requested int) int {
					return r.reserveBodyCapture(observation, requested)
				},
				func(transactions []HTTPTransactionObservation, truncated bool) {
					if observation.activeFor(r.captureSession()) {
						r.publishHTTPTransactions(observation, transactions, truncated)
					}
				},
			)
		}
		timelineDone := make(chan struct{})
		defer close(timelineDone)
		changeSignal := r.captureSessionChangeSignal()
		go r.watchHTTPTimeline(
			ctx, observation, timeline, changeSignal, timelineDone,
		)
		requestMetadataReader = &metadataObservingReader{
			reader: client,
			observe: func(data []byte) {
				if !observation.activeFor(r.captureSession()) {
					timeline.Abort()
					return
				}
				timeline.ObserveRequest(data)
			},
			finish: func() {
				if !observation.activeFor(r.captureSession()) {
					timeline.Abort()
					return
				}
				timeline.FinishRequest()
			},
			abort: timeline.Abort,
		}
		requestReader = requestMetadataReader
		responseMetadataReader = &metadataObservingReader{
			reader: upstream,
			observe: func(data []byte) {
				if !observation.activeFor(r.captureSession()) {
					timeline.Abort()
					return
				}
				timeline.ObserveResponse(data)
			},
			finish: func() {
				if !observation.activeFor(r.captureSession()) {
					timeline.Abort()
					return
				}
				timeline.FinishResponse()
			},
			abort: timeline.Abort,
		}
		responseReader = responseMetadataReader
	}
	copyOne := func(dst *tls.Conn, src io.Reader, metadataReader *metadataObservingReader, upload bool) {
		result := copied{upload: upload}
		defer func() {
			if metadataReader != nil {
				metadataReader.Finish()
			}
			if recover() != nil {
				result.err = errors.New("inspection relay failed")
			}
			results <- result
		}()
		result.n, result.err = io.CopyBuffer(dst, src, make([]byte, 16*1024))
	}
	go copyOne(upstream, requestReader, requestMetadataReader, true)
	go copyOne(client, responseReader, responseMetadataReader, false)
	first := <-results
	var second copied
	if first.upload && first.err == nil {
		_ = upstream.CloseWrite()
		second = <-results
		_ = rawClient.Close()
		_ = rawUpstream.Close()
	} else {
		_ = rawClient.Close()
		_ = rawUpstream.Close()
		second = <-results
	}
	var uploaded uint64
	var downloaded uint64
	for _, result := range []copied{first, second} {
		if result.upload {
			uploaded += uint64(result.n)
		} else {
			downloaded += uint64(result.n)
		}
	}
	r.mu.Lock()
	r.uploaded += uploaded
	r.downloaded += downloaded
	r.mu.Unlock()
	if ctx.Err() != nil {
		return uploaded, downloaded, ctx.Err()
	}
	if first.err != nil && !errors.Is(first.err, net.ErrClosed) {
		return uploaded, downloaded, first.err
	}
	if second.err != nil && !errors.Is(second.err, net.ErrClosed) {
		return uploaded, downloaded, second.err
	}
	return uploaded, downloaded, nil
}
