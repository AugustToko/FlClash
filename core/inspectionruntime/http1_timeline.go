package inspectionruntime

import (
	"bytes"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxHTTPMetadataTransactions = 32
	maxHTTPChunkLineBytes       = 1024
)

// HTTPTransactionObservation is one bounded request/response metadata pair on
// an inspected HTTP/1 connection. Sequence is contiguous and one-based.
type HTTPTransactionObservation struct {
	Sequence                           int                      `json:"sequence"`
	RequestObservedAfterMilliseconds   int64                    `json:"requestObservedAfterMilliseconds"`
	RequestCompletedAfterMilliseconds  int64                    `json:"requestCompletedAfterMilliseconds,omitempty"`
	ResponseCompletedAfterMilliseconds int64                    `json:"responseCompletedAfterMilliseconds,omitempty"`
	Request                            HTTPRequestObservation   `json:"request"`
	RequestBody                        *HTTPBodyObservation     `json:"requestBody,omitempty"`
	Response                           *HTTPResponseObservation `json:"response,omitempty"`
	ResponseBody                       *HTTPBodyObservation     `json:"responseBody,omitempty"`
}

type httpBodyMode uint8

const (
	httpBodyNone httpBodyMode = iota
	httpBodyFixed
	httpBodyChunked
	httpBodyUntilClose
)

type httpBodyPlan struct {
	mode              httpBodyMode
	length            int64
	terminalAfterBody bool
	contentType       string
	contentEncoding   string
}

type httpFramingHeaders struct {
	contentLength     *int64
	transferCodings   []string
	contentType       string
	contentEncoding   string
	connectionClose   bool
	connectionKeep    bool
	connectionUpgrade bool
	upgradePresent    bool
}

type httpRequestStreamState struct {
	header            []byte
	mode              httpBodyMode
	remaining         int64
	chunked           httpChunkedBodySkipper
	body              *bodyCaptureAccumulator
	transactionIndex  int
	terminalAfterBody bool
	stopped           bool
}

type httpResponseStreamState struct {
	header                 []byte
	mode                   httpBodyMode
	remaining              int64
	chunked                httpChunkedBodySkipper
	body                   *bodyCaptureAccumulator
	transactionIndex       int
	terminalAfterBody      bool
	informational          []int
	informationalTruncated bool
	observedHeaderBytes    int
	stopped                bool
}

type http1MetadataTimeline struct {
	mu           sync.Mutex
	publishMu    sync.Mutex
	startedAt    time.Time
	expectedHost string
	request      httpRequestStreamState
	response     httpResponseStreamState
	transactions []HTTPTransactionObservation
	policy       CapturePolicy
	reserveBody  func(int) int
	truncated    bool
	stopped      bool
	publish      func([]HTTPTransactionObservation, bool)
}

func newHTTP1MetadataTimeline(
	startedAt time.Time,
	expectedHost string,
	publish func([]HTTPTransactionObservation, bool),
) *http1MetadataTimeline {
	return newHTTP1MetadataTimelineWithPolicy(
		startedAt,
		expectedHost,
		CapturePolicy{},
		nil,
		publish,
	)
}

func newHTTP1MetadataTimelineWithPolicy(
	startedAt time.Time,
	expectedHost string,
	policy CapturePolicy,
	reserveBody func(int) int,
	publish func([]HTTPTransactionObservation, bool),
) *http1MetadataTimeline {
	return &http1MetadataTimeline{
		startedAt:    startedAt,
		expectedHost: expectedHost,
		request: httpRequestStreamState{
			header: make([]byte, 0, 1024), transactionIndex: -1,
		},
		response: httpResponseStreamState{
			header: make([]byte, 0, 1024), transactionIndex: -1,
		},
		transactions: make([]HTTPTransactionObservation, 0, 4),
		policy:       policy.Normalize(),
		reserveBody:  reserveBody,
		publish:      publish,
	}
}

func cloneHTTPTransactionObservations(
	values []HTTPTransactionObservation,
) []HTTPTransactionObservation {
	if len(values) == 0 {
		return nil
	}
	result := make([]HTTPTransactionObservation, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Request = *cloneHTTPRequestObservation(&value.Request)
		result[index].RequestBody = cloneHTTPBodyObservation(value.RequestBody)
		result[index].Response = cloneHTTPResponseObservation(value.Response)
		result[index].ResponseBody = cloneHTTPBodyObservation(value.ResponseBody)
	}
	return result
}

func (t *http1MetadataTimeline) publishLocked() {
	if t.publish == nil {
		t.mu.Unlock()
		return
	}
	snapshot := cloneHTTPTransactionObservations(t.transactions)
	truncated := t.truncated
	t.publishMu.Lock()
	t.mu.Unlock()
	defer t.publishMu.Unlock()
	t.publish(snapshot, truncated)
}

func (t *http1MetadataTimeline) ObserveRequest(data []byte) {
	if t == nil || len(data) == 0 {
		return
	}
	t.mu.Lock()
	changed := t.observeRequestLocked(data)
	if changed {
		t.publishLocked()
		return
	}
	t.mu.Unlock()
}

func (t *http1MetadataTimeline) ObserveResponse(data []byte) {
	if t == nil || len(data) == 0 {
		return
	}
	t.mu.Lock()
	changed := t.observeResponseLocked(data)
	if changed {
		t.publishLocked()
		return
	}
	t.mu.Unlock()
}

func (t *http1MetadataTimeline) FinishRequest() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.stopped || t.request.stopped {
		t.mu.Unlock()
		return
	}
	if t.request.mode == httpBodyNone && len(t.request.header) == 0 {
		t.request.stopped = true
		t.mu.Unlock()
		return
	}
	changed := t.failClosedLocked()
	if changed {
		t.publishLocked()
		return
	}
	t.mu.Unlock()
}

func (t *http1MetadataTimeline) FinishResponse() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.stopped || t.response.stopped {
		t.mu.Unlock()
		return
	}
	if t.response.mode == httpBodyUntilClose {
		changed := t.completeResponseBodyLocked(false)
		changed = t.stopNormallyLocked() || changed
		if changed {
			t.publishLocked()
			return
		}
		t.mu.Unlock()
		return
	}
	if t.response.mode == httpBodyNone &&
		len(t.response.header) == 0 &&
		len(t.response.informational) == 0 {
		if t.hasPendingResponseLocked() {
			changed := t.failClosedLocked()
			if changed {
				t.publishLocked()
				return
			}
			t.mu.Unlock()
			return
		}
		t.response.stopped = true
		t.mu.Unlock()
		return
	}
	changed := t.finishPartialResponseLocked()
	if changed {
		t.publishLocked()
		return
	}
	t.mu.Unlock()
}

func (t *http1MetadataTimeline) Abort() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.clearLocked()
	t.transactions = nil
	t.stopped = true
	t.request.stopped = true
	t.response.stopped = true
	t.mu.Unlock()
}

func (t *http1MetadataTimeline) observeRequestLocked(data []byte) bool {
	if t.stopped || t.request.stopped {
		return false
	}
	changed := false
	for len(data) > 0 && !t.stopped && !t.request.stopped {
		switch t.request.mode {
		case httpBodyNone:
			block, rest, complete, overflow := consumeHTTPMetadataHeader(
				&t.request.header,
				data,
			)
			data = rest
			if !complete && !overflow {
				continue
			}
			if overflow {
				if value, valid := parseHTTPRequestMetadata(block, false, true); valid &&
					validHTTPTransactionRequest(block, false, value, t.expectedHost) {
					t.appendRequestLocked(value)
					changed = true
				}
				return t.failClosedLocked() || changed
			}
			request, plan, valid := parseHTTPRequestEnvelope(block)
			if !valid ||
				!validHTTPTransactionRequest(block, true, request, t.expectedHost) {
				return t.failClosedLocked() || changed
			}
			request.Headers, request.HeaderValuesTruncated =
				captureHTTP1HeaderValues(block, true, t.policy)
			resetHTTPMetadataHeader(&t.request.header)
			t.appendRequestLocked(request)
			changed = true
			if t.response.stopped {
				return t.failClosedLocked() || changed
			}
			if len(t.transactions) >= maxHTTPMetadataTransactions {
				t.truncated = true
				t.request.stopped = true
				clearHTTPRequestStreamState(&t.request)
				return true
			}
			if t.beginRequestBodyLocked(plan) {
				changed = true
			}
			if plan.mode == httpBodyNone {
				resetHTTPRequestBodyState(&t.request)
				if plan.terminalAfterBody {
					t.request.stopped = true
					clearHTTPRequestStreamState(&t.request)
					return changed
				}
				continue
			}
		case httpBodyFixed:
			consumed := int64(len(data))
			if consumed > t.request.remaining {
				consumed = t.request.remaining
			}
			t.request.body.Observe(data[:int(consumed)])
			data = data[consumed:]
			t.request.remaining -= consumed
			if t.request.remaining != 0 {
				continue
			}
			terminal := t.request.terminalAfterBody
			if t.completeRequestBodyLocked(false) {
				changed = true
			}
			resetHTTPRequestBodyState(&t.request)
			if terminal {
				t.request.stopped = true
				return changed
			}
		case httpBodyChunked:
			rest, complete, invalid := t.request.chunked.consumeObserved(
				data,
				t.request.body.Observe,
			)
			data = rest
			if invalid {
				return t.failClosedLocked() || changed
			}
			if !complete {
				continue
			}
			terminal := t.request.terminalAfterBody
			if t.completeRequestBodyLocked(false) {
				changed = true
			}
			resetHTTPRequestBodyState(&t.request)
			if terminal {
				t.request.stopped = true
				return changed
			}
		default:
			return t.failClosedLocked() || changed
		}
	}
	return changed
}

func (t *http1MetadataTimeline) observeResponseLocked(data []byte) bool {
	if t.stopped || t.response.stopped {
		return false
	}
	changed := false
	for len(data) > 0 && !t.stopped && !t.response.stopped {
		switch t.response.mode {
		case httpBodyNone:
			block, rest, complete, overflow := consumeHTTPMetadataHeader(
				&t.response.header,
				data,
			)
			data = rest
			if !complete && !overflow {
				continue
			}
			if overflow {
				if t.attachPartialResponseLocked(block, true) {
					changed = true
				}
				return t.failClosedLocked() || changed
			}
			method, ok := t.nextResponseMethodLocked()
			if !ok {
				return t.failClosedLocked() || changed
			}
			response, plan, informational, valid := parseHTTPResponseEnvelope(
				block,
				method,
			)
			headerValues, headerValuesTruncated :=
				captureHTTP1HeaderValues(block, true, t.policy)
			resetHTTPMetadataHeader(&t.response.header)
			t.response.observedHeaderBytes = boundedHTTPObservedBytes(
				t.response.observedHeaderBytes,
				len(block),
			)
			if !valid {
				return t.failClosedLocked() || changed
			}
			if informational {
				if len(t.response.informational) < maxHTTPInformationalStatusCodes {
					t.response.informational = append(
						t.response.informational,
						response.StatusCode,
					)
				} else {
					t.response.informationalTruncated = true
				}
				continue
			}
			response.InformationalStatusCodes = append(
				[]int(nil),
				t.response.informational...,
			)
			response.InformationalStatusCodesTruncated =
				t.response.informationalTruncated
			response.ObservedBytes = t.response.observedHeaderBytes
			response.ObservedAfterMilliseconds = elapsedMilliseconds(t.startedAt)
			response.Headers = headerValues
			response.HeaderValuesTruncated = headerValuesTruncated
			resetHTTPResponseHeaderState(&t.response)
			if !t.attachResponseLocked(response) {
				return t.failClosedLocked() || changed
			}
			changed = true
			if t.beginResponseBodyLocked(plan) {
				changed = true
			}
			if plan.mode == httpBodyNone {
				resetHTTPResponseBodyState(&t.response)
				if plan.terminalAfterBody {
					return t.stopNormallyLocked() || changed
				}
				continue
			}
		case httpBodyFixed:
			consumed := int64(len(data))
			if consumed > t.response.remaining {
				consumed = t.response.remaining
			}
			t.response.body.Observe(data[:int(consumed)])
			data = data[consumed:]
			t.response.remaining -= consumed
			if t.response.remaining != 0 {
				continue
			}
			terminal := t.response.terminalAfterBody
			if t.completeResponseBodyLocked(false) {
				changed = true
			}
			resetHTTPResponseBodyState(&t.response)
			if terminal {
				return t.stopNormallyLocked() || changed
			}
		case httpBodyChunked:
			rest, complete, invalid := t.response.chunked.consumeObserved(
				data,
				t.response.body.Observe,
			)
			data = rest
			if invalid {
				return t.failClosedLocked() || changed
			}
			if !complete {
				continue
			}
			terminal := t.response.terminalAfterBody
			if t.completeResponseBodyLocked(false) {
				changed = true
			}
			resetHTTPResponseBodyState(&t.response)
			if terminal {
				return t.stopNormallyLocked() || changed
			}
		case httpBodyUntilClose:
			t.response.body.Observe(data)
			data = nil
		default:
			return t.failClosedLocked() || changed
		}
	}
	return changed
}

func (t *http1MetadataTimeline) appendRequestLocked(
	request *HTTPRequestObservation,
) {
	if request == nil {
		return
	}
	t.transactions = append(t.transactions, HTTPTransactionObservation{
		Sequence:                         len(t.transactions) + 1,
		RequestObservedAfterMilliseconds: elapsedMilliseconds(t.startedAt),
		Request:                          *cloneHTTPRequestObservation(request),
	})
	t.request.transactionIndex = len(t.transactions) - 1
}

func (t *http1MetadataTimeline) beginRequestBodyLocked(plan httpBodyPlan) bool {
	t.request.mode = plan.mode
	t.request.remaining = plan.length
	t.request.terminalAfterBody = plan.terminalAfterBody
	t.request.body = newBodyCaptureAccumulator(
		t.policy,
		plan.contentType,
		plan.contentEncoding,
		t.reserveBody,
	)
	if plan.mode == httpBodyChunked {
		t.request.chunked.reset()
	}
	if plan.mode == httpBodyNone {
		return t.completeRequestBodyLocked(false)
	}
	return false
}

func (t *http1MetadataTimeline) completeRequestBodyLocked(truncated bool) bool {
	index := t.request.transactionIndex
	if index < 0 || index >= len(t.transactions) {
		return false
	}
	body := t.request.body.Finish()
	if body != nil {
		body.Truncated = body.Truncated || truncated
		t.transactions[index].RequestBody = body
	}
	t.transactions[index].RequestCompletedAfterMilliseconds =
		elapsedMilliseconds(t.startedAt)
	if t.request.body != nil {
		t.request.body.Clear()
	}
	t.request.body = nil
	t.request.transactionIndex = -1
	return true
}

func (t *http1MetadataTimeline) beginResponseBodyLocked(plan httpBodyPlan) bool {
	t.response.mode = plan.mode
	t.response.remaining = plan.length
	t.response.terminalAfterBody = plan.terminalAfterBody
	t.response.body = newBodyCaptureAccumulator(
		t.policy,
		plan.contentType,
		plan.contentEncoding,
		t.reserveBody,
	)
	if plan.mode == httpBodyChunked {
		t.response.chunked.reset()
	}
	if plan.mode == httpBodyNone {
		return t.completeResponseBodyLocked(false)
	}
	return false
}

func (t *http1MetadataTimeline) completeResponseBodyLocked(truncated bool) bool {
	index := t.response.transactionIndex
	if index < 0 || index >= len(t.transactions) {
		return false
	}
	body := t.response.body.Finish()
	if body != nil {
		body.Truncated = body.Truncated || truncated
		t.transactions[index].ResponseBody = body
	}
	t.transactions[index].ResponseCompletedAfterMilliseconds =
		elapsedMilliseconds(t.startedAt)
	if t.response.body != nil {
		t.response.body.Clear()
	}
	t.response.body = nil
	t.response.transactionIndex = -1
	return true
}

func (t *http1MetadataTimeline) nextResponseMethodLocked() (string, bool) {
	for index := range t.transactions {
		if t.transactions[index].Response == nil {
			return t.transactions[index].Request.Method, true
		}
	}
	return "", false
}

func (t *http1MetadataTimeline) attachResponseLocked(
	response *HTTPResponseObservation,
) bool {
	if response == nil {
		return false
	}
	for index := range t.transactions {
		if t.transactions[index].Response != nil {
			continue
		}
		t.transactions[index].Response = cloneHTTPResponseObservation(response)
		t.response.transactionIndex = index
		return true
	}
	return false
}

func (t *http1MetadataTimeline) attachPartialResponseLocked(
	data []byte,
	boundReached bool,
) bool {
	method, ok := t.nextResponseMethodLocked()
	if !ok {
		return false
	}
	_ = method
	value, valid := parseHTTPResponseMetadata(data, false, true)
	if valid && value.StatusCode >= 100 && value.StatusCode < 200 &&
		value.StatusCode != 101 {
		if len(t.response.informational) < maxHTTPInformationalStatusCodes {
			t.response.informational = append(
				t.response.informational,
				value.StatusCode,
			)
		} else {
			t.response.informationalTruncated = true
		}
		value = &HTTPResponseObservation{}
	} else if !valid {
		if len(t.response.informational) == 0 {
			return false
		}
		value = &HTTPResponseObservation{}
	}
	value.InformationalStatusCodes = append(
		[]int(nil),
		t.response.informational...,
	)
	value.InformationalStatusCodesTruncated =
		t.response.informationalTruncated
	value.ObservedBytes = boundedHTTPObservedBytes(
		t.response.observedHeaderBytes,
		len(data),
	)
	value.ObservedAfterMilliseconds = elapsedMilliseconds(t.startedAt)
	value.Truncated = true
	if boundReached {
		value.HeaderNamesTruncated = true
	}
	return t.attachResponseLocked(value)
}

func (t *http1MetadataTimeline) finishPartialResponseLocked() bool {
	changed := false
	if len(t.response.header) != 0 || len(t.response.informational) != 0 {
		changed = t.attachPartialResponseLocked(t.response.header, false)
	}
	return t.failClosedLocked() || changed
}

func (t *http1MetadataTimeline) failClosedLocked() bool {
	changed := !t.truncated
	if t.request.transactionIndex >= 0 {
		changed = t.completeRequestBodyLocked(true) || changed
	}
	if t.response.transactionIndex >= 0 {
		changed = t.completeResponseBodyLocked(true) || changed
	}
	t.truncated = true
	t.clearLocked()
	t.stopped = true
	t.request.stopped = true
	t.response.stopped = true
	return changed
}

func (t *http1MetadataTimeline) stopNormallyLocked() bool {
	changed := false
	if t.response.transactionIndex >= 0 {
		changed = t.completeResponseBodyLocked(false)
	}
	if t.request.transactionIndex >= 0 {
		changed = t.completeRequestBodyLocked(true) || changed
	}
	if t.hasPendingResponseLocked() && !t.truncated {
		t.truncated = true
		changed = true
	}
	t.clearLocked()
	t.stopped = true
	t.request.stopped = true
	t.response.stopped = true
	return changed
}

func (t *http1MetadataTimeline) hasPendingResponseLocked() bool {
	for index := range t.transactions {
		if t.transactions[index].Response == nil {
			return true
		}
	}
	return false
}

func (t *http1MetadataTimeline) clearLocked() {
	clearHTTPRequestStreamState(&t.request)
	clearHTTPResponseStreamState(&t.response)
}

func consumeHTTPMetadataHeader(
	buffer *[]byte,
	data []byte,
) (block []byte, rest []byte, complete bool, overflow bool) {
	for index, value := range data {
		if len(*buffer) >= maxHTTPMetadataBytes {
			return *buffer, data[index:], false, true
		}
		*buffer = append(*buffer, value)
		if len(*buffer) >= len(httpHeaderTerminator) &&
			bytes.Equal(
				(*buffer)[len(*buffer)-len(httpHeaderTerminator):],
				httpHeaderTerminator,
			) {
			return *buffer, data[index+1:], true, false
		}
	}
	if len(*buffer) >= maxHTTPMetadataBytes {
		return *buffer, nil, false, true
	}
	return nil, nil, false, false
}

func boundedHTTPObservedBytes(current, added int) int {
	if current >= maxHTTPMetadataBytes || added >= maxHTTPMetadataBytes-current {
		return maxHTTPMetadataBytes
	}
	return current + added
}

func resetHTTPMetadataHeader(buffer *[]byte) {
	clearHTTPMetadataBuffer(*buffer)
	*buffer = make([]byte, 0, 1024)
}

func resetHTTPRequestBodyState(state *httpRequestStreamState) {
	state.mode = httpBodyNone
	state.remaining = 0
	state.chunked.clear()
	if state.body != nil {
		state.body.Clear()
	}
	state.body = nil
	state.transactionIndex = -1
	state.terminalAfterBody = false
}

func resetHTTPResponseHeaderState(state *httpResponseStreamState) {
	state.informational = nil
	state.informationalTruncated = false
	state.observedHeaderBytes = 0
}

func resetHTTPResponseBodyState(state *httpResponseStreamState) {
	state.mode = httpBodyNone
	state.remaining = 0
	state.chunked.clear()
	if state.body != nil {
		state.body.Clear()
	}
	state.body = nil
	state.transactionIndex = -1
	state.terminalAfterBody = false
}

func clearHTTPRequestStreamState(state *httpRequestStreamState) {
	clearHTTPMetadataBuffer(state.header)
	state.header = nil
	state.chunked.clear()
	if state.body != nil {
		state.body.Clear()
	}
	state.body = nil
	state.remaining = 0
	state.transactionIndex = -1
	state.terminalAfterBody = false
}

func clearHTTPResponseStreamState(state *httpResponseStreamState) {
	clearHTTPMetadataBuffer(state.header)
	state.header = nil
	state.chunked.clear()
	if state.body != nil {
		state.body.Clear()
	}
	state.body = nil
	state.remaining = 0
	state.transactionIndex = -1
	state.terminalAfterBody = false
	state.informational = nil
	state.informationalTruncated = false
	state.observedHeaderBytes = 0
}

func validHTTPTransactionRequest(
	data []byte,
	complete bool,
	request *HTTPRequestObservation,
	expectedHost string,
) bool {
	if !validHTTPTransactionHost(request, expectedHost) {
		return false
	}
	lines, valid := metadataHeaderLines(data, complete)
	if !valid || len(lines) == 0 {
		return false
	}
	parts := bytes.Split(lines[0], []byte{' '})
	if len(parts) != 3 {
		return false
	}
	rawHost, hostPresent, valid := rawHTTPHostHeader(lines[1:])
	if !valid {
		return false
	}
	if request.Method == "CONNECT" {
		targetHost, targetPort, valid := parseHTTPAuthority(string(parts[1]), 0)
		if !valid || targetHost != request.Target || !hostPresent {
			return false
		}
		host, port, valid := parseHTTPAuthority(rawHost, 0)
		return valid && host == targetHost && port == targetPort
	}

	var host string
	var port int
	if hostPresent {
		host, port, valid = parseHTTPAuthority(rawHost, 443)
		if !valid || host != expectedHost || port != 443 {
			return false
		}
	}
	rawTarget := string(parts[1])
	if rawTarget == "*" || strings.HasPrefix(rawTarget, "/") {
		return true
	}
	parsed, err := url.ParseRequestURI(rawTarget)
	if err != nil || parsed.User != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	targetHost := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if targetHost == "" || targetHost != expectedHost {
		return false
	}
	targetPort := 443
	if parsed.Port() != "" {
		value, err := strconv.Atoi(parsed.Port())
		if err != nil || value < 1 || value > 65535 {
			return false
		}
		targetPort = value
	}
	if targetPort != 443 {
		return false
	}
	return !hostPresent || (host == targetHost && port == targetPort)
}

func validHTTPTransactionHost(
	request *HTTPRequestObservation,
	expectedHost string,
) bool {
	if request == nil || request.HostTruncated {
		return false
	}
	if request.Method == "CONNECT" {
		return request.Host != "" && request.Host == request.Target
	}
	if request.Version == "HTTP/1.1" && request.Host == "" {
		return false
	}
	return request.Host == "" || request.Host == expectedHost
}

func rawHTTPHostHeader(lines [][]byte) (string, bool, bool) {
	var host string
	found := false
	for _, line := range lines {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return "", false, false
		}
		if !strings.EqualFold(string(line[:colon]), "host") {
			continue
		}
		if found {
			return "", false, false
		}
		found = true
		host = trimHTTPOptionalWhitespace(string(line[colon+1:]))
	}
	return host, found, true
}

func parseHTTPAuthority(value string, defaultPort int) (string, int, bool) {
	value = trimHTTPOptionalWhitespace(value)
	if value == "" || strings.TrimSpace(value) != value {
		return "", 0, false
	}
	hostValue := value
	port := defaultPort
	if splitHost, splitPort, err := net.SplitHostPort(value); err == nil {
		if splitPort == "" {
			return "", 0, false
		}
		parsedPort, err := strconv.Atoi(splitPort)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return "", 0, false
		}
		hostValue = splitHost
		port = parsedPort
	} else if strings.Contains(value, ":") {
		return "", 0, false
	}
	if port == 0 {
		return "", 0, false
	}
	host, truncated, valid := normalizeHTTPMetadataHost([]byte(hostValue))
	if !valid || truncated || host == "" {
		return "", 0, false
	}
	return host, port, true
}

func parseHTTPRequestEnvelope(
	data []byte,
) (*HTTPRequestObservation, httpBodyPlan, bool) {
	value, valid := parseHTTPRequestMetadata(data, true, false)
	if !valid {
		return nil, httpBodyPlan{}, false
	}
	lines, valid := metadataHeaderLines(data, true)
	if !valid || len(lines) == 0 {
		return nil, httpBodyPlan{}, false
	}
	headers, valid := parseHTTPFramingHeaders(lines[1:])
	if !valid {
		return nil, httpBodyPlan{}, false
	}
	plan, valid := requestBodyPlan(value.Method, value.Version, headers)
	if !valid {
		return nil, httpBodyPlan{}, false
	}
	plan.contentType = headers.contentType
	plan.contentEncoding = headers.contentEncoding
	return value, plan, true
}

func parseHTTPResponseEnvelope(
	data []byte,
	requestMethod string,
) (*HTTPResponseObservation, httpBodyPlan, bool, bool) {
	value, valid := parseHTTPResponseMetadata(data, true, false)
	if !valid {
		return nil, httpBodyPlan{}, false, false
	}
	lines, valid := metadataHeaderLines(data, true)
	if !valid || len(lines) == 0 {
		return nil, httpBodyPlan{}, false, false
	}
	headers, valid := parseHTTPFramingHeaders(lines[1:])
	if !valid {
		return nil, httpBodyPlan{}, false, false
	}
	if value.StatusCode >= 100 && value.StatusCode < 200 && value.StatusCode != 101 {
		if headers.contentLength != nil || len(headers.transferCodings) != 0 {
			return nil, httpBodyPlan{}, false, false
		}
		return value, httpBodyPlan{}, true, true
	}
	plan, valid := responseBodyPlan(
		requestMethod,
		value.StatusCode,
		value.Version,
		headers,
	)
	if !valid {
		return nil, httpBodyPlan{}, false, false
	}
	plan.contentType = headers.contentType
	plan.contentEncoding = headers.contentEncoding
	return value, plan, false, true
}

func parseHTTPFramingHeaders(lines [][]byte) (httpFramingHeaders, bool) {
	result := httpFramingHeaders{}
	var contentLength *int64
	for _, line := range lines {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			return httpFramingHeaders{}, false
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 ||
			!validHTTPToken(line[:colon]) ||
			!validHTTPFieldValue(line[colon+1:]) {
			return httpFramingHeaders{}, false
		}
		name := strings.ToLower(string(line[:colon]))
		value := trimHTTPOptionalWhitespace(string(line[colon+1:]))
		switch name {
		case "content-length":
			parsed, valid := parseHTTPContentLengths(value, contentLength)
			if !valid {
				return httpFramingHeaders{}, false
			}
			contentLength = parsed
		case "transfer-encoding":
			codings, valid := parseHTTPTransferCodings(value)
			if !valid {
				return httpFramingHeaders{}, false
			}
			result.transferCodings = append(result.transferCodings, codings...)
		case "content-type":
			if result.contentType == "" {
				result.contentType = value
			}
		case "content-encoding":
			if result.contentEncoding == "" {
				result.contentEncoding = value
			}
		case "connection":
			tokens, valid := parseHTTPCommaTokens(value)
			if !valid {
				return httpFramingHeaders{}, false
			}
			for _, token := range tokens {
				switch token {
				case "close":
					result.connectionClose = true
				case "keep-alive":
					result.connectionKeep = true
				case "upgrade":
					result.connectionUpgrade = true
				}
			}
		case "upgrade":
			if value == "" {
				return httpFramingHeaders{}, false
			}
			result.upgradePresent = true
		}
	}
	result.contentLength = contentLength
	if contentLength != nil && len(result.transferCodings) != 0 {
		return httpFramingHeaders{}, false
	}
	return result, true
}

func parseHTTPContentLengths(
	value string,
	existing *int64,
) (*int64, bool) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return nil, false
	}
	current := existing
	for _, part := range parts {
		part = trimHTTPOptionalWhitespace(part)
		if part == "" {
			return nil, false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return nil, false
			}
		}
		parsed, err := strconv.ParseUint(part, 10, 63)
		if err != nil || parsed > math.MaxInt64 {
			return nil, false
		}
		length := int64(parsed)
		if current != nil && *current != length {
			return nil, false
		}
		copy := length
		current = &copy
	}
	return current, true
}

func parseHTTPTransferCodings(value string) ([]string, bool) {
	parts, valid := splitHTTPCommaValues(value)
	if !valid {
		return nil, false
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		index := 0
		for index < len(part) && isHTTPTokenByte(part[index]) {
			index++
		}
		if index == 0 {
			return nil, false
		}
		token := strings.ToLower(part[:index])
		rest := []byte(part[index:])
		if len(rest) != 0 {
			if token == "chunked" || !validHTTPParameters(rest, false) {
				return nil, false
			}
		}
		result = append(result, token)
	}
	return result, true
}

func splitHTTPCommaValues(value string) ([]string, bool) {
	result := make([]string, 0, strings.Count(value, ",")+1)
	start := 0
	quoted := false
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if quoted {
			if escaped {
				if !validHTTPQuotedPairByte(character) {
					return nil, false
				}
				escaped = false
				continue
			}
			switch character {
			case '\\':
				escaped = true
			case '"':
				quoted = false
			default:
				if !validHTTPQuotedTextByte(character) {
					return nil, false
				}
			}
			continue
		}
		switch character {
		case '"':
			quoted = true
		case ',':
			part := trimHTTPOptionalWhitespace(value[start:index])
			if part == "" {
				return nil, false
			}
			result = append(result, part)
			start = index + 1
		}
	}
	if quoted || escaped {
		return nil, false
	}
	part := trimHTTPOptionalWhitespace(value[start:])
	if part == "" {
		return nil, false
	}
	return append(result, part), true
}

func parseHTTPCommaTokens(value string) ([]string, bool) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return nil, false
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		token := trimHTTPOptionalWhitespace(part)
		if token == "" || !validHTTPToken([]byte(token)) {
			return nil, false
		}
		result = append(result, strings.ToLower(token))
	}
	return result, true
}

func requestBodyPlan(
	method string,
	version string,
	headers httpFramingHeaders,
) (httpBodyPlan, bool) {
	terminal := headers.connectionClose ||
		(version == "HTTP/1.0" && !headers.connectionKeep)
	if version == "HTTP/1.0" && len(headers.transferCodings) != 0 {
		return httpBodyPlan{}, false
	}
	if method == "CONNECT" {
		if len(headers.transferCodings) != 0 ||
			(headers.contentLength != nil && *headers.contentLength != 0) {
			return httpBodyPlan{}, false
		}
		return httpBodyPlan{mode: httpBodyNone, terminalAfterBody: true}, true
	}
	if headers.connectionUpgrade != headers.upgradePresent {
		return httpBodyPlan{}, false
	}
	if headers.connectionUpgrade {
		terminal = true
	}
	if len(headers.transferCodings) != 0 {
		if len(headers.transferCodings) != 1 ||
			headers.transferCodings[0] != "chunked" {
			return httpBodyPlan{}, false
		}
		return httpBodyPlan{
			mode:              httpBodyChunked,
			terminalAfterBody: terminal,
		}, true
	}
	if headers.contentLength != nil && *headers.contentLength > 0 {
		return httpBodyPlan{
			mode:              httpBodyFixed,
			length:            *headers.contentLength,
			terminalAfterBody: terminal,
		}, true
	}
	return httpBodyPlan{
		mode:              httpBodyNone,
		terminalAfterBody: terminal,
	}, true
}

func responseBodyPlan(
	requestMethod string,
	statusCode int,
	version string,
	headers httpFramingHeaders,
) (httpBodyPlan, bool) {
	terminal := headers.connectionClose ||
		(version == "HTTP/1.0" && !headers.connectionKeep)
	if version == "HTTP/1.0" && len(headers.transferCodings) != 0 {
		return httpBodyPlan{}, false
	}
	if statusCode == 101 {
		if !headers.connectionUpgrade || !headers.upgradePresent ||
			headers.contentLength != nil || len(headers.transferCodings) != 0 {
			return httpBodyPlan{}, false
		}
		return httpBodyPlan{mode: httpBodyNone, terminalAfterBody: true}, true
	}
	if requestMethod == "CONNECT" && statusCode >= 200 && statusCode < 300 {
		if headers.contentLength != nil || len(headers.transferCodings) != 0 {
			return httpBodyPlan{}, false
		}
		return httpBodyPlan{mode: httpBodyNone, terminalAfterBody: true}, true
	}
	if statusCode == 204 {
		if headers.contentLength != nil || len(headers.transferCodings) != 0 {
			return httpBodyPlan{}, false
		}
		return httpBodyPlan{mode: httpBodyNone, terminalAfterBody: terminal}, true
	}
	if statusCode == 205 {
		if len(headers.transferCodings) != 0 ||
			(headers.contentLength != nil && *headers.contentLength != 0) {
			return httpBodyPlan{}, false
		}
		if headers.contentLength != nil {
			return httpBodyPlan{mode: httpBodyNone, terminalAfterBody: terminal}, true
		}
		return httpBodyPlan{mode: httpBodyUntilClose, terminalAfterBody: true}, true
	}
	if requestMethod == "HEAD" || statusCode == 304 {
		return httpBodyPlan{mode: httpBodyNone, terminalAfterBody: terminal}, true
	}
	if len(headers.transferCodings) != 0 {
		chunkedIndex := -1
		for index, coding := range headers.transferCodings {
			if coding == "chunked" {
				if chunkedIndex != -1 {
					return httpBodyPlan{}, false
				}
				chunkedIndex = index
			}
		}
		if chunkedIndex >= 0 {
			if chunkedIndex != len(headers.transferCodings)-1 {
				return httpBodyPlan{}, false
			}
			return httpBodyPlan{
				mode:              httpBodyChunked,
				terminalAfterBody: terminal,
			}, true
		}
		return httpBodyPlan{mode: httpBodyUntilClose, terminalAfterBody: true}, true
	}
	if headers.contentLength != nil {
		if *headers.contentLength == 0 {
			return httpBodyPlan{mode: httpBodyNone, terminalAfterBody: terminal}, true
		}
		return httpBodyPlan{
			mode:              httpBodyFixed,
			length:            *headers.contentLength,
			terminalAfterBody: terminal,
		}, true
	}
	return httpBodyPlan{mode: httpBodyUntilClose, terminalAfterBody: true}, true
}

type httpChunkPhase uint8

const (
	httpChunkSize httpChunkPhase = iota
	httpChunkData
	httpChunkDataCRLF
	httpChunkTrailers
)

type httpChunkedBodySkipper struct {
	phase     httpChunkPhase
	line      []byte
	remaining int64
	crlfRead  int
	trailers  []byte
}

func (s *httpChunkedBodySkipper) reset() {
	s.clear()
	s.phase = httpChunkSize
	s.line = make([]byte, 0, 32)
}

func (s *httpChunkedBodySkipper) clear() {
	clearHTTPMetadataBuffer(s.line)
	clearHTTPMetadataBuffer(s.trailers)
	s.line = nil
	s.trailers = nil
	s.remaining = 0
	s.crlfRead = 0
	s.phase = httpChunkSize
}

func (s *httpChunkedBodySkipper) consume(
	data []byte,
) (rest []byte, complete bool, invalid bool) {
	return s.consumeObserved(data, nil)
}

func (s *httpChunkedBodySkipper) consumeObserved(
	data []byte,
	observe func([]byte),
) (rest []byte, complete bool, invalid bool) {
	for len(data) > 0 {
		switch s.phase {
		case httpChunkSize:
			value := data[0]
			data = data[1:]
			if len(s.line) >= maxHTTPChunkLineBytes {
				return data, false, true
			}
			s.line = append(s.line, value)
			if len(s.line) < 2 ||
				s.line[len(s.line)-2] != '\r' ||
				s.line[len(s.line)-1] != '\n' {
				continue
			}
			size, valid := parseHTTPChunkSize(s.line[:len(s.line)-2])
			clearHTTPMetadataBuffer(s.line)
			s.line = s.line[:0]
			if !valid {
				return data, false, true
			}
			if size == 0 {
				s.phase = httpChunkTrailers
				s.trailers = make([]byte, 0, 128)
				continue
			}
			s.remaining = size
			s.phase = httpChunkData
		case httpChunkData:
			consumed := int64(len(data))
			if consumed > s.remaining {
				consumed = s.remaining
			}
			if observe != nil && consumed > 0 {
				observe(data[:int(consumed)])
			}
			data = data[consumed:]
			s.remaining -= consumed
			if s.remaining == 0 {
				s.phase = httpChunkDataCRLF
				s.crlfRead = 0
			}
		case httpChunkDataCRLF:
			expected := byte('\r')
			if s.crlfRead == 1 {
				expected = '\n'
			}
			if data[0] != expected {
				return data[1:], false, true
			}
			data = data[1:]
			s.crlfRead++
			if s.crlfRead == 2 {
				s.phase = httpChunkSize
				s.crlfRead = 0
			}
		case httpChunkTrailers:
			value := data[0]
			data = data[1:]
			if len(s.trailers) >= maxHTTPMetadataBytes {
				return data, false, true
			}
			s.trailers = append(s.trailers, value)
			if len(s.trailers) == 2 &&
				bytes.Equal(s.trailers, httpLineTerminator) {
				s.clear()
				return data, true, false
			}
			if len(s.trailers) >= len(httpHeaderTerminator) &&
				bytes.HasSuffix(s.trailers, httpHeaderTerminator) {
				lines, valid := metadataHeaderLines(s.trailers, true)
				if !valid {
					return data, false, true
				}
				if !validHTTPChunkTrailers(lines) {
					return data, false, true
				}
				s.clear()
				return data, true, false
			}
		default:
			return data, false, true
		}
	}
	return data, false, false
}

func validHTTPChunkTrailers(lines [][]byte) bool {
	names, _, _, _, valid := parseHTTPHeaderNames(lines, false)
	if !valid {
		return false
	}
	for _, name := range names {
		switch name {
		case "content-length", "trailer", "transfer-encoding":
			return false
		}
	}
	return true
}

func trimHTTPOptionalWhitespace(value string) string {
	return strings.Trim(value, " \t")
}

func validHTTPChunkExtensions(value []byte) bool {
	return validHTTPParameters(value, true)
}

func validHTTPParameters(value []byte, allowBare bool) bool {
	index := 0
	seen := false
	for {
		for index < len(value) && isHTTPOptionalWhitespace(value[index]) {
			index++
		}
		if index == len(value) {
			return seen
		}
		if value[index] != ';' {
			return false
		}
		index++
		for index < len(value) && isHTTPOptionalWhitespace(value[index]) {
			index++
		}
		nameStart := index
		for index < len(value) && isHTTPTokenByte(value[index]) {
			index++
		}
		if index == nameStart {
			return false
		}
		seen = true
		for index < len(value) && isHTTPOptionalWhitespace(value[index]) {
			index++
		}
		if index == len(value) || value[index] == ';' {
			if !allowBare {
				return false
			}
			continue
		}
		if value[index] != '=' {
			return false
		}
		index++
		for index < len(value) && isHTTPOptionalWhitespace(value[index]) {
			index++
		}
		if index >= len(value) {
			return false
		}
		if value[index] == '"' {
			var valid bool
			index, valid = consumeHTTPQuotedString(value, index)
			if !valid {
				return false
			}
		} else {
			valueStart := index
			for index < len(value) && isHTTPTokenByte(value[index]) {
				index++
			}
			if index == valueStart {
				return false
			}
		}
		for index < len(value) && isHTTPOptionalWhitespace(value[index]) {
			index++
		}
		if index < len(value) && value[index] != ';' {
			return false
		}
	}
}

func consumeHTTPQuotedString(value []byte, index int) (int, bool) {
	if index >= len(value) || value[index] != '"' {
		return index, false
	}
	index++
	for index < len(value) {
		character := value[index]
		switch character {
		case '"':
			return index + 1, true
		case '\\':
			index++
			if index >= len(value) || !validHTTPQuotedPairByte(value[index]) {
				return index, false
			}
			index++
		default:
			if !validHTTPQuotedTextByte(character) {
				return index, false
			}
			index++
		}
	}
	return index, false
}

func isHTTPOptionalWhitespace(character byte) bool {
	return character == ' ' || character == '\t'
}

func isHTTPTokenByte(character byte) bool {
	switch {
	case character >= 'a' && character <= 'z':
	case character >= 'A' && character <= 'Z':
	case character >= '0' && character <= '9':
	case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)):
	default:
		return false
	}
	return true
}

func validHTTPQuotedTextByte(character byte) bool {
	return character == '\t' || character == ' ' || character == '!' ||
		(character >= '#' && character <= '[') ||
		(character >= ']' && character <= '~') || character >= 0x80
}

func validHTTPQuotedPairByte(character byte) bool {
	return character == '\t' || character == ' ' ||
		(character >= '!' && character <= '~') || character >= 0x80
}

func parseHTTPChunkSize(line []byte) (int64, bool) {
	if len(line) == 0 {
		return 0, false
	}
	if semicolon := bytes.IndexByte(line, ';'); semicolon >= 0 {
		if semicolon == 0 || !validHTTPChunkExtensions(line[semicolon:]) {
			return 0, false
		}
		line = bytes.Trim(line[:semicolon], " \t")
	}
	if len(line) == 0 || len(line) > 16 {
		return 0, false
	}
	for _, character := range line {
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(string(line), 16, 63)
	if err != nil || value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true
}
