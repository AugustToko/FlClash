from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if old not in text:
        raise RuntimeError(f"missing replacement in {path}: {old[:120]!r}")
    path.write_text(text.replace(old, new, 1))


def patch_http_observer() -> None:
    (ROOT / "core/http_observer.go").write_text(r'''package main

import (
	"sync"

	"core/inspectionruntime"
	"github.com/metacubex/mihomo/component/observer"
)

var httpObservationChangeMu sync.Mutex
var httpObservationChange = make(chan struct{})
var httpObservationPolicyMu sync.RWMutex
var httpObservationPolicy inspectionruntime.CapturePolicy

func httpObservationChangeSignal() <-chan struct{} {
	httpObservationChangeMu.Lock()
	defer httpObservationChangeMu.Unlock()
	return httpObservationChange
}

func publishHTTPObservationChange() {
	httpObservationChangeMu.Lock()
	close(httpObservationChange)
	httpObservationChange = make(chan struct{})
	httpObservationChangeMu.Unlock()
}

func currentHTTPObservationPolicy() inspectionruntime.CapturePolicy {
	httpObservationPolicyMu.RLock()
	defer httpObservationPolicyMu.RUnlock()
	return httpObservationPolicy.Normalize()
}

func setHTTPObservationPolicy(policy inspectionruntime.CapturePolicy) bool {
	policy = policy.Normalize()
	httpObservationPolicyMu.Lock()
	changed := !sameHTTPObservationPolicy(httpObservationPolicy, policy)
	httpObservationPolicy = policy
	httpObservationPolicyMu.Unlock()
	return changed
}

func sameHTTPObservationPolicy(
	left inspectionruntime.CapturePolicy,
	right inspectionruntime.CapturePolicy,
) bool {
	left = left.Normalize()
	right = right.Normalize()
	if left.HeaderValues != right.HeaderValues ||
		left.SensitiveHeaderValues != right.SensitiveHeaderValues ||
		left.BodyMode != right.BodyMode ||
		left.MaxBodyBytes != right.MaxBodyBytes ||
		len(left.RedactedHeaderNames) != len(right.RedactedHeaderNames) {
		return false
	}
	for index := range left.RedactedHeaderNames {
		if left.RedactedHeaderNames[index] != right.RedactedHeaderNames[index] {
			return false
		}
	}
	return true
}

type HTTPObservationParams struct {
	Enabled   bool                            `json:"enabled"`
	SessionID string                          `json:"sessionId"`
	Policy    inspectionruntime.CapturePolicy `json:"policy"`
}

func handleSetHTTPObservationEnabled(params HTTPObservationParams) bool {
	previousEnabled := observer.Enabled()
	previousSession := observer.SessionID()
	policy := params.Policy
	if !params.Enabled {
		policy = inspectionruntime.CapturePolicy{}
	}
	policyChanged := setHTTPObservationPolicy(policy)
	observer.Configure(params.Enabled, params.SessionID)
	enabled := observer.Enabled()
	session := observer.SessionID()
	if enabled != previousEnabled || session != previousSession || policyChanged {
		publishHTTPObservationChange()
	}
	return enabled
}

func disableHTTPObservation() {
	handleSetHTTPObservationEnabled(HTTPObservationParams{})
}

func init() {
	registerMethod(setHTTPObservationEnabledMethod, withArguments(func(params *HTTPObservationParams, response MethodResponse) {
		response.success(handleSetHTTPObservationEnabled(*params))
	}))
}
''')


def patch_tls_runtime() -> None:
    path = ROOT / "core/tls_inspection_runtime.go"
    replace_once(path,
'''\tCapturesPayload            bool                     `json:"capturesPayload"`
\tChangesSystemProxy         bool                     `json:"changesSystemProxy"`
''',
'''\tCapturesPayload            bool                            `json:"capturesPayload"`
\tCapturePolicy              inspectionruntime.CapturePolicy `json:"capturePolicy"`
\tChangesSystemProxy         bool                            `json:"changesSystemProxy"`
''')
    replace_once(path,
'''func tlsInspectionRuntimeStatusLocked() TLSInspectionRuntimeStatus {
\tresult := TLSInspectionRuntimeStatus{
\t\tRuntime: inspectionruntime.Status{State: "stopped"},
\t\tMode:    "loopback-connect-http1", Capacity: inspectionruntime.MaxClients,
\t\tConnectionLifetimeSeconds: int64(inspectionruntime.ConnectionLifetime / time.Second),
\t}
''',
'''func tlsInspectionRuntimeStatusLocked() TLSInspectionRuntimeStatus {
\tpolicy := currentHTTPObservationPolicy()
\tresult := TLSInspectionRuntimeStatus{
\t\tRuntime: inspectionruntime.Status{State: "stopped"},
\t\tMode:    "loopback-connect-http1-h2", Capacity: inspectionruntime.MaxClients,
\t\tConnectionLifetimeSeconds: int64(inspectionruntime.ConnectionLifetime / time.Second),
\t\tCapturesPayload: policy.BodyMode != inspectionruntime.CaptureBodyNone,
\t\tCapturePolicy: policy,
\t}
''')
    replace_once(path,
'''\t\tCaptureSessionChanged: httpObservationChangeSignal,
\t\tObserve: func(value inspectionruntime.Observation) {
''',
'''\t\tCaptureSessionChanged: httpObservationChangeSignal,
\t\tCapturePolicy: currentHTTPObservationPolicy,
\t\tObserve: func(value inspectionruntime.Observation) {
''')


def patch_runtime_contract() -> None:
    path = ROOT / "core/inspectionruntime/runtime.go"
    replacements = [
        ('''\tCaptureSession        func() string
\tCaptureSessionChanged func() <-chan struct{}
\tObserve               func(Observation)
''', '''\tCaptureSession        func() string
\tCaptureSessionChanged func() <-chan struct{}
\tCapturePolicy         func() CapturePolicy
\tObserve               func(Observation)
'''),
        ('''\tFailureKind               string                       `json:"failureKind,omitempty"`
\tHTTPTransactions          []HTTPTransactionObservation `json:"httpTransactions,omitempty"`
\tHTTPTransactionsTruncated bool                         `json:"httpTransactionsTruncated,omitempty"`
''', '''\tFailureKind                              string                       `json:"failureKind,omitempty"`
\tDownstreamTLSCompletedAfterMilliseconds int64                        `json:"downstreamTlsCompletedAfterMilliseconds,omitempty"`
\tUpstreamDialCompletedAfterMilliseconds  int64                        `json:"upstreamDialCompletedAfterMilliseconds,omitempty"`
\tUpstreamTLSCompletedAfterMilliseconds   int64                        `json:"upstreamTlsCompletedAfterMilliseconds,omitempty"`
\tCapturePolicy                            *CapturePolicy               `json:"capturePolicy,omitempty"`
\tHTTPTransactions                         []HTTPTransactionObservation `json:"httpTransactions,omitempty"`
\tHTTPTransactionsTruncated                bool                         `json:"httpTransactionsTruncated,omitempty"`
\tHTTP2Streams                             []HTTP2StreamObservation     `json:"http2Streams,omitempty"`
\tHTTP2StreamsTruncated                    bool                         `json:"http2StreamsTruncated,omitempty"`
\tHTTP2GoAway                              *HTTP2GoAwayObservation      `json:"http2GoAway,omitempty"`
'''),
        ('''\tobservationSequence uint64
\tdone                chan struct{}
''', '''\tobservationSequence  uint64
\tcaptureBudgetMu      sync.Mutex
\tcaptureBodyBySession map[string]int
\tdone                 chan struct{}
'''),
        ('''\t\tclients: make(map[net.Conn]context.CancelFunc), done: make(chan struct{}),
''', '''\t\tclients: make(map[net.Conn]context.CancelFunc),
\t\tcaptureBodyBySession: make(map[string]int), done: make(chan struct{}),
'''),
        ('''type runtimeObservation struct {
\tmu        sync.Mutex
\tpublishMu sync.Mutex
\tvalue     Observation
\tfinished  bool
}
''', '''type runtimeObservation struct {
\tmu                sync.Mutex
\tpublishMu         sync.Mutex
\tbodyBudgetMu      sync.Mutex
\tvalue             Observation
\tpolicy            CapturePolicy
\tcapturedBodyBytes int
\tfinished          bool
}
'''),
        ('''\tresult := *value
\tresult.HeaderNames = append([]string(nil), value.HeaderNames...)
\treturn &result
}

func cloneHTTPResponseObservation''', '''\tresult := *value
\tresult.HeaderNames = append([]string(nil), value.HeaderNames...)
\tresult.Headers = cloneHTTPHeaderObservations(value.Headers)
\treturn &result
}

func cloneHTTPResponseObservation'''),
        ('''\tresult.InformationalStatusCodes = append([]int(nil), value.InformationalStatusCodes...)
\tresult.HeaderNames = append([]string(nil), value.HeaderNames...)
\treturn &result
}
''', '''\tresult.InformationalStatusCodes = append([]int(nil), value.InformationalStatusCodes...)
\tresult.HeaderNames = append([]string(nil), value.HeaderNames...)
\tresult.Headers = cloneHTTPHeaderObservations(value.Headers)
\treturn &result
}
'''),
        ('''func cloneObservation(value Observation) Observation {
\tvalue.HTTPTransactions = cloneHTTPTransactionObservations(value.HTTPTransactions)
\treturn value
}
''', '''func cloneObservation(value Observation) Observation {
\tif value.CapturePolicy != nil {
\t\tpolicy := value.CapturePolicy.Normalize()
\t\tvalue.CapturePolicy = &policy
\t}
\tvalue.HTTPTransactions = cloneHTTPTransactionObservations(value.HTTPTransactions)
\tvalue.HTTP2Streams = cloneHTTP2StreamObservations(value.HTTP2Streams)
\tvalue.HTTP2GoAway = cloneHTTP2GoAwayObservation(value.HTTP2GoAway)
\treturn value
}
'''),
        ('''func (r *Runtime) beginObservation(host string) *runtimeObservation {
\tsession := r.captureSession()
\tif session == "" {
\t\treturn nil
\t}
''', '''func (r *Runtime) beginObservation(host string) *runtimeObservation {
\tsession := r.captureSession()
\tif session == "" {
\t\treturn nil
\t}
\tpolicy := r.capturePolicy(session)
'''),
        ('''\tvalue := Observation{
\t\tSessionID: session, ConnectionID: hex.EncodeToString(digest[:16]),
\t\tRuntimeID: r.id, Host: host, State: "running", StartedAt: time.Now().UTC(),
\t}
\tobservation := &runtimeObservation{value: value}
''', '''\tvalue := Observation{
\t\tSessionID: session, ConnectionID: hex.EncodeToString(digest[:16]),
\t\tRuntimeID: r.id, Host: host, State: "running", StartedAt: time.Now().UTC(),
\t\tCapturePolicy: &policy,
\t}
\tobservation := &runtimeObservation{value: value, policy: policy}
'''),
    ]
    text = path.read_text()
    for old, new in replacements:
        if old not in text:
            raise RuntimeError(f"missing runtime replacement: {old[:100]!r}")
        text = text.replace(old, new, 1)
    marker = '''func (r *Runtime) captureSessionChangeSignal() (signal <-chan struct{}) {
'''
    insert = '''func (r *Runtime) capturePolicy(session string) (policy CapturePolicy) {
\tif session == "" || r.config.CapturePolicy == nil {
\t\treturn CapturePolicy{}
\t}
\tdefer func() {
\t\tif recover() != nil {
\t\t\tpolicy = CapturePolicy{}
\t\t}
\t}()
\treturn r.config.CapturePolicy().Normalize()
}

func (r *Runtime) reserveBodyCapture(
\tobservation *runtimeObservation,
\trequested int,
) int {
\tif observation == nil || requested <= 0 {
\t\treturn 0
\t}
\tobservation.bodyBudgetMu.Lock()
\tdefer observation.bodyBudgetMu.Unlock()
\tconnectionRemaining := observation.policy.ConnectionBodyLimit() -
\t\tobservation.capturedBodyBytes
\tif connectionRemaining <= 0 {
\t\treturn 0
\t}
\tif requested > connectionRemaining {
\t\trequested = connectionRemaining
\t}
\tsessionID := observation.value.SessionID
\tsessionLimit := observation.policy.SessionBodyLimit()
\tif sessionID == "" || sessionLimit <= 0 {
\t\treturn 0
\t}
\tr.captureBudgetMu.Lock()
\tdefer r.captureBudgetMu.Unlock()
\tfor existing := range r.captureBodyBySession {
\t\tif existing != sessionID {
\t\t\tdelete(r.captureBodyBySession, existing)
\t\t}
\t}
\tsessionRemaining := sessionLimit - r.captureBodyBySession[sessionID]
\tif sessionRemaining <= 0 {
\t\treturn 0
\t}
\tif requested > sessionRemaining {
\t\trequested = sessionRemaining
\t}
\tobservation.capturedBodyBytes += requested
\tr.captureBodyBySession[sessionID] += requested
\treturn requested
}

'''
    if marker not in text:
        raise RuntimeError("capture signal marker missing")
    text = text.replace(marker, insert + marker, 1)
    path.write_text(text)


def patch_runtime_publish_and_exchange() -> None:
    path = ROOT / "core/inspectionruntime/runtime.go"
    text = path.read_text()
    marker = '''func (r *Runtime) finishObservation(
'''
    insert = '''func (r *Runtime) publishHTTP2Streams(
\tobservation *runtimeObservation,
\tstreams []HTTP2StreamObservation,
\ttruncated bool,
\tgoAway *HTTP2GoAwayObservation,
) {
\tif observation == nil {
\t\treturn
\t}
\tactiveSession := r.captureSession()
\tobservation.mu.Lock()
\tif observation.finished || observation.value.SessionID != activeSession {
\t\tobservation.mu.Unlock()
\t\treturn
\t}
\tobservation.value.HTTP2Streams = cloneHTTP2StreamObservations(streams)
\tobservation.value.HTTP2StreamsTruncated =
\t\tobservation.value.HTTP2StreamsTruncated || truncated
\tobservation.value.HTTP2GoAway = cloneHTTP2GoAwayObservation(goAway)
\tsnapshot := cloneObservation(observation.value)
\tobservation.publishMu.Lock()
\tobservation.mu.Unlock()
\tr.publishObservation(snapshot)
\tobservation.publishMu.Unlock()
}

'''
    if marker not in text:
        raise RuntimeError("finish observation marker missing")
    text = text.replace(marker, insert + marker, 1)

    start = text.index('\tobservation = r.beginObservation(host)\n')
    end_marker = '''\tuploaded, downloaded, failure = r.relay(
\t\tctx, downstream, upstream, conn, rawUpstream, observation,
\t)
\treturn failure
'''
    end = text.index(end_marker, start) + len(end_marker)
    exchange = '''\tobservation = r.beginObservation(host)
\tfailureKind = "leaf"
\tleaf, err := r.config.Leaf(ctx, host)
\tif err != nil || leaf == nil || ctx.Err() != nil {
\t\tfailure = reject(conn, http.StatusForbidden)
\t\treturn failure
\t}
\t_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
\tif _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\\r\\n\\r\\n"); err != nil {
\t\tfailure = err
\t\treturn failure
\t}
\tdownstream := tls.Server(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
\t\tCertificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12,
\t\tNextProtos: []string{"h2", "http/1.1"}, SessionTicketsDisabled: true,
\t\tGetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
\t\t\tif strings.ToLower(hello.ServerName) != host || ctx.Err() != nil {
\t\t\t\treturn nil, errors.New("inspection SNI does not match CONNECT host")
\t\t\t}
\t\t\tif len(hello.SupportedProtos) != 0 {
\t\t\t\tfound := false
\t\t\t\tfor _, protocol := range hello.SupportedProtos {
\t\t\t\t\tfound = found || protocol == "h2" || protocol == "http/1.1"
\t\t\t\t}
\t\t\t\tif !found {
\t\t\t\t\treturn nil, errors.New("inspection runtime supports HTTP/1.1 and HTTP/2 only")
\t\t\t\t}
\t\t\t}
\t\t\treturn nil, r.config.Authorize(ctx, host)
\t\t},
\t})
\tfailureKind = "downstream-tls"
\thandshakeCtx, cancelHandshake := context.WithTimeout(ctx, HandshakeTimeout)
\terr = downstream.HandshakeContext(handshakeCtx)
\tcancelHandshake()
\tif err != nil {
\t\tfailure = errors.New("inspection client handshake failed")
\t\treturn failure
\t}
\tdownstreamState := downstream.ConnectionState()
\tprotocol := downstreamState.NegotiatedProtocol
\tif protocol == "" {
\t\tprotocol = "http/1.1"
\t}
\tif protocol != "http/1.1" && protocol != "h2" {
\t\tfailure = errors.New("inspection client selected an unsupported protocol")
\t\treturn failure
\t}
\tr.updateObservation(observation, func(value *Observation) {
\t\tvalue.DownstreamTLSVersion = tlsVersionName(downstreamState.Version)
\t\tvalue.DownstreamTLSCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
\t\tvalue.ALPN = protocol
\t})
\tfailureKind = "upstream-dial"
\trawUpstream, err := r.config.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
\tif err != nil {
\t\tfailure = errors.New("inspection upstream dial failed")
\t\treturn failure
\t}
\tdefer rawUpstream.Close()
\tstopUpstream := context.AfterFunc(ctx, func() { _ = rawUpstream.Close() })
\tdefer stopUpstream()
\tr.updateObservation(observation, func(value *Observation) {
\t\tvalue.UpstreamDialCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
\t})
\tupstream := tls.Client(rawUpstream, &tls.Config{
\t\tServerName: host, RootCAs: r.config.Roots, MinVersion: tls.VersionTLS12,
\t\tNextProtos: []string{protocol}, SessionTicketsDisabled: true,
\t})
\tfailureKind = "upstream-tls"
\t_ = rawUpstream.SetDeadline(time.Now().Add(HandshakeTimeout))
\thandshakeCtx, cancelHandshake = context.WithTimeout(ctx, HandshakeTimeout)
\terr = upstream.HandshakeContext(handshakeCtx)
\tcancelHandshake()
\t_ = rawUpstream.SetDeadline(time.Time{})
\tif err != nil {
\t\tfailure = errors.New("inspection upstream handshake failed")
\t\treturn failure
\t}
\tpeer := upstream.ConnectionState()
\tprotocolMatches := peer.NegotiatedProtocol == protocol ||
\t\tprotocol == "http/1.1" && peer.NegotiatedProtocol == ""
\tif len(peer.VerifiedChains) == 0 || !protocolMatches {
\t\tfailure = errors.New("inspection upstream protocol mismatch")
\t\treturn failure
\t}
\tr.updateObservation(observation, func(value *Observation) {
\t\tvalue.UpstreamTLSVersion = tlsVersionName(peer.Version)
\t\tvalue.UpstreamTLSCompletedAfterMilliseconds = elapsedMilliseconds(value.StartedAt)
\t})
\tfailureKind = "authorization-revoked"
\tif err := r.config.Authorize(ctx, host); err != nil || ctx.Err() != nil {
\t\tfailure = errors.New("inspection authorization revoked")
\t\treturn failure
\t}
\tdeadline, _ := ctx.Deadline()
\t_ = conn.SetDeadline(deadline)
\t_ = rawUpstream.SetDeadline(deadline)
\tfailureKind = "relay"
\tuploaded, downloaded, failure = r.relay(
\t\tctx, downstream, upstream, conn, rawUpstream, protocol, observation,
\t)
\treturn failure
'''
    text = text[:start] + exchange + text[end:]

    old_watch = '''func (r *Runtime) watchHTTP1Timeline(
\tctx context.Context,
\tobservation *runtimeObservation,
\ttimeline *http1MetadataTimeline,
\tsignal <-chan struct{},
\tdone <-chan struct{},
) {
'''
    new_watch = '''type httpMetadataTimeline interface {
\tObserveRequest([]byte)
\tObserveResponse([]byte)
\tFinishRequest()
\tFinishResponse()
\tAbort()
}

func (r *Runtime) watchHTTPTimeline(
\tctx context.Context,
\tobservation *runtimeObservation,
\ttimeline httpMetadataTimeline,
\tsignal <-chan struct{},
\tdone <-chan struct{},
) {
'''
    if old_watch not in text:
        raise RuntimeError("watch timeline signature missing")
    text = text.replace(old_watch, new_watch, 1)
    text = text.replace(
'''\trawClient net.Conn,
\trawUpstream net.Conn,
\tobservation *runtimeObservation,
''',
'''\trawClient net.Conn,
\trawUpstream net.Conn,
\tprotocol string,
\tobservation *runtimeObservation,
''', 1)

    relay_start = text.index('func (r *Runtime) relay(')
    block_start = text.index('\tif observation != nil {\n', relay_start)
    block_end = text.index('\tcopyOne := func(', block_start)
    relay_block = '''\tif observation != nil {
\t\tvar timeline httpMetadataTimeline
\t\tif protocol == "h2" {
\t\t\ttimeline = newHTTP2MetadataTimeline(
\t\t\t\tobservation.startedAt(),
\t\t\t\tobservation.host(),
\t\t\t\tobservation.policy,
\t\t\t\tfunc(requested int) int {
\t\t\t\t\treturn r.reserveBodyCapture(observation, requested)
\t\t\t\t},
\t\t\t\tfunc(streams []HTTP2StreamObservation, truncated bool, goAway *HTTP2GoAwayObservation) {
\t\t\t\t\tif observation.activeFor(r.captureSession()) {
\t\t\t\t\t\tr.publishHTTP2Streams(observation, streams, truncated, goAway)
\t\t\t\t\t}
\t\t\t\t},
\t\t\t)
\t\t} else {
\t\t\ttimeline = newHTTP1MetadataTimelineWithPolicy(
\t\t\t\tobservation.startedAt(),
\t\t\t\tobservation.host(),
\t\t\t\tobservation.policy,
\t\t\t\tfunc(requested int) int {
\t\t\t\t\treturn r.reserveBodyCapture(observation, requested)
\t\t\t\t},
\t\t\t\tfunc(transactions []HTTPTransactionObservation, truncated bool) {
\t\t\t\t\tif observation.activeFor(r.captureSession()) {
\t\t\t\t\t\tr.publishHTTPTransactions(observation, transactions, truncated)
\t\t\t\t\t}
\t\t\t\t},
\t\t\t)
\t\t}
\t\ttimelineDone := make(chan struct{})
\t\tdefer close(timelineDone)
\t\tchangeSignal := r.captureSessionChangeSignal()
\t\tgo r.watchHTTPTimeline(
\t\t\tctx, observation, timeline, changeSignal, timelineDone,
\t\t)
\t\trequestMetadataReader = &metadataObservingReader{
\t\t\treader: client,
\t\t\tobserve: func(data []byte) {
\t\t\t\tif !observation.activeFor(r.captureSession()) {
\t\t\t\t\ttimeline.Abort()
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\ttimeline.ObserveRequest(data)
\t\t\t},
\t\t\tfinish: func() {
\t\t\t\tif !observation.activeFor(r.captureSession()) {
\t\t\t\t\ttimeline.Abort()
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\ttimeline.FinishRequest()
\t\t\t},
\t\t\tabort: timeline.Abort,
\t\t}
\t\trequestReader = requestMetadataReader
\t\tresponseMetadataReader = &metadataObservingReader{
\t\t\treader: upstream,
\t\t\tobserve: func(data []byte) {
\t\t\t\tif !observation.activeFor(r.captureSession()) {
\t\t\t\t\ttimeline.Abort()
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\ttimeline.ObserveResponse(data)
\t\t\t},
\t\t\tfinish: func() {
\t\t\t\tif !observation.activeFor(r.captureSession()) {
\t\t\t\t\ttimeline.Abort()
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\ttimeline.FinishResponse()
\t\t\t},
\t\t\tabort: timeline.Abort,
\t\t}
\t\tresponseReader = responseMetadataReader
\t}
'''
    text = text[:block_start] + relay_block + text[block_end:]
    path.write_text(text)


def patch_all() -> None:
    patch_http_observer()
    patch_tls_runtime()
    patch_runtime_contract()
    patch_runtime_publish_and_exchange()
