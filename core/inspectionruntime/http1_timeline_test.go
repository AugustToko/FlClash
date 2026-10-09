package inspectionruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type httpTimelineSnapshot struct {
	transactions []HTTPTransactionObservation
	truncated    bool
}

type httpTimelineRecorder struct {
	mu        sync.Mutex
	snapshots []httpTimelineSnapshot
}

func (r *httpTimelineRecorder) publish(
	transactions []HTTPTransactionObservation,
	truncated bool,
) {
	r.mu.Lock()
	r.snapshots = append(r.snapshots, httpTimelineSnapshot{
		transactions: cloneHTTPTransactionObservations(transactions),
		truncated:    truncated,
	})
	r.mu.Unlock()
}

func (r *httpTimelineRecorder) latest(t *testing.T) httpTimelineSnapshot {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.snapshots) == 0 {
		t.Fatal("timeline did not publish")
	}
	value := r.snapshots[len(r.snapshots)-1]
	value.transactions = cloneHTTPTransactionObservations(value.transactions)
	return value
}

func observeOneByteAtATime(observe func([]byte), data []byte) {
	for _, value := range data {
		observe([]byte{value})
	}
}

func TestHTTP1TimelineCapturesSequentialFixedAndChunkedTransactions(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(time.Now().Add(-time.Second), "api.example.com", recorder.publish)
	requests := "POST /one?token=private-query HTTP/1.1\r\n" +
		"Host: api.example.com\r\nContent-Length: 4\r\nAuthorization: Bearer private-token\r\n\r\nDATA" +
		"POST /two#private-fragment HTTP/1.1\r\nHost: api.example.com\r\n" +
		"Transfer-Encoding: chunked\r\nCookie: private-cookie\r\n\r\n" +
		"4\r\nBODY\r\n0\r\nX-Private-Trailer: private-trailer\r\n\r\n" +
		"GET /three HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	responses := "HTTP/1.1 100 Continue\r\nX-Interim: private-interim\r\n\r\n" +
		"HTTP/1.1 201 Secret Created\r\nContent-Length: 3\r\nSet-Cookie: private-response-cookie\r\n\r\nONE" +
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Secret: private-value\r\n\r\n" +
		"3\r\nTWO\r\n0\r\nX-Private-Trailer: private-response-trailer\r\n\r\n" +
		"HTTP/1.1 204 No Content\r\nX-Final: private-final\r\n\r\n"
	observeOneByteAtATime(timeline.ObserveRequest, []byte(requests))
	observeOneByteAtATime(timeline.ObserveResponse, []byte(responses))
	timeline.FinishRequest()
	timeline.FinishResponse()

	latest := recorder.latest(t)
	if latest.truncated || len(latest.transactions) != 3 {
		t.Fatalf("unexpected timeline: %#v", latest)
	}
	first, second, third := latest.transactions[0], latest.transactions[1], latest.transactions[2]
	if first.Sequence != 1 || first.Request.Target != "/one" ||
		first.Response == nil || first.Response.StatusCode != 201 ||
		!slices.Equal(first.Response.InformationalStatusCodes, []int{100}) {
		t.Fatalf("unexpected first transaction: %#v", first)
	}
	if second.Sequence != 2 || second.Request.Target != "/two" ||
		second.Response == nil || second.Response.StatusCode != 200 {
		t.Fatalf("unexpected second transaction: %#v", second)
	}
	if third.Sequence != 3 || third.Request.Target != "/three" ||
		third.Response == nil || third.Response.StatusCode != 204 {
		t.Fatalf("unexpected third transaction: %#v", third)
	}
	encoded, err := json.Marshal(latest)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"private-query", "private-fragment", "private-token", "private-cookie",
		"private-trailer", "Secret Created", "private-response-cookie",
		"private-value", "private-response-trailer", "private-final", "DATA", "BODY",
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("timeline retained %q: %s", secret, encoded)
		}
	}
}

func TestHTTP1TimelineValidatesAbsoluteTargetsAndHostPorts(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		request    string
		valid      bool
		wantTarget string
	}{
		{
			name: "matching absolute HTTPS target",
			request: "GET https://api.example.com:443/items?secret=value HTTP/1.1\r\n" +
				"Host: api.example.com\r\n\r\n",
			valid: true, wantTarget: "/items",
		},
		{
			name: "matching explicit HTTPS Host port",
			request: "GET /items HTTP/1.1\r\n" +
				"Host: api.example.com:443\r\n\r\n",
			valid: true, wantTarget: "/items",
		},
		{
			name: "mismatched absolute authority",
			request: "GET https://other.example.com/items HTTP/1.1\r\n" +
				"Host: api.example.com\r\n\r\n",
		},
		{
			name: "cleartext absolute scheme inside TLS",
			request: "GET http://api.example.com/items HTTP/1.1\r\n" +
				"Host: api.example.com\r\n\r\n",
		},
		{
			name: "wrong Host port inside TLS",
			request: "GET /items HTTP/1.1\r\n" +
				"Host: api.example.com:80\r\n\r\n",
		},
		{
			name: "CONNECT authority port mismatch",
			request: "CONNECT proxy.example.com:443 HTTP/1.1\r\n" +
				"Host: proxy.example.com:444\r\n\r\n",
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			recorder := &httpTimelineRecorder{}
			timeline := newHTTP1MetadataTimeline(
				time.Now(),
				"api.example.com",
				recorder.publish,
			)
			timeline.ObserveRequest([]byte(scenario.request))
			latest := recorder.latest(t)
			if scenario.valid {
				if latest.truncated || len(latest.transactions) != 1 ||
					latest.transactions[0].Request.Target != scenario.wantTarget {
					t.Fatalf("valid request was rejected: %#v", latest)
				}
				return
			}
			if !latest.truncated || len(latest.transactions) != 0 {
				t.Fatalf("ambiguous request authority crossed the contract: %#v", latest)
			}
		})
	}
}

func TestHTTP1TimelineRejectsMismatchedHostWhenRequestHeaderOverflows(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	request := "GET /overflow HTTP/1.1\r\n" +
		"Host: other.example.com\r\n" +
		"X-Padding: " + strings.Repeat("private", maxHTTPMetadataBytes) + "\r\n"
	timeline.ObserveRequest([]byte(request))
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 0 {
		t.Fatalf("overflowing mismatched Host crossed the runtime contract: %#v", latest)
	}
}

func TestHTTP1TimelineMarksMissingResponsesAsTruncated(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"GET /missing HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	timeline.FinishResponse()
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 1 ||
		latest.transactions[0].Response != nil {
		t.Fatalf("response EOF did not preserve an explicit incomplete timeline: %#v", latest)
	}
}

func TestHTTP1TimelineMarksTerminalResponseWithPipelinedRequestsAsTruncated(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"GET /first HTTP/1.1\r\nHost: api.example.com\r\n\r\n" +
			"GET /queued HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	timeline.ObserveResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
	))
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 2 ||
		latest.transactions[0].Response == nil ||
		latest.transactions[1].Response != nil {
		t.Fatalf("terminal response hid an unmatched pipelined request: %#v", latest)
	}
}

func TestHTTP1TimelineMarksRequestAfterResponseEOFTruncated(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"GET /first HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	timeline.ObserveResponse([]byte(
		"HTTP/1.1 204 No Content\r\n\r\n",
	))
	timeline.FinishResponse()
	timeline.ObserveRequest([]byte(
		"GET /after-eof HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 2 ||
		latest.transactions[0].Response == nil ||
		latest.transactions[1].Request.Target != "/after-eof" ||
		latest.transactions[1].Response != nil {
		t.Fatalf("response EOF hid an unmatched request tail: %#v", latest)
	}
}

func TestHTTP1TimelineKeepsOverflowingInformationalResponseNonFinal(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"GET /hints HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	response := append(
		[]byte("HTTP/1.1 103 Early Hints\r\nX-Large: "),
		bytes.Repeat([]byte{'x'}, maxHTTPMetadataBytes)...,
	)
	timeline.ObserveResponse(response)
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 1 ||
		latest.transactions[0].Response == nil {
		t.Fatalf("overflowing informational response was not retained safely: %#v", latest)
	}
	observed := latest.transactions[0].Response
	if observed.StatusCode != 0 || observed.Version != "" ||
		!observed.Truncated ||
		!slices.Equal(observed.InformationalStatusCodes, []int{103}) {
		t.Fatalf("informational response became a final response: %#v", observed)
	}
}

func TestHTTP1TimelineBoundsInformationalStatusesAndObservedBytes(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
	timeline.ObserveRequest([]byte("GET /hints HTTP/1.1\r\nHost: api.example.com\r\n\r\n"))
	var responses strings.Builder
	for index, status := range []int{100, 102, 103, 103, 103, 103, 103, 103, 103, 103} {
		fmt.Fprintf(
			&responses,
			"HTTP/1.1 %d Informational\r\nX-Padding-%d: %s\r\n\r\n",
			status,
			index,
			strings.Repeat("private", 550),
		)
	}
	responses.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Final: private-final\r\n\r\n")
	timeline.ObserveResponse([]byte(responses.String()))
	latest := recorder.latest(t)
	if latest.truncated || len(latest.transactions) != 1 ||
		latest.transactions[0].Response == nil {
		t.Fatalf("unexpected informational timeline: %#v", latest)
	}
	response := latest.transactions[0].Response
	if !slices.Equal(response.InformationalStatusCodes, []int{100, 102, 103, 103, 103, 103, 103, 103}) ||
		!response.InformationalStatusCodesTruncated ||
		response.ObservedBytes != maxHTTPMetadataBytes {
		t.Fatalf("informational bounds not enforced: %#v", response)
	}
	encoded, err := json.Marshal(latest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "Informational") {
		t.Fatalf("informational timeline retained values: %s", encoded)
	}
}

func TestHTTP1TimelinePublishesImmutableSnapshots(t *testing.T) {
	var snapshots [][]HTTPTransactionObservation
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		func(transactions []HTTPTransactionObservation, _ bool) {
			snapshots = append(snapshots, transactions)
			if len(snapshots) == 1 {
				transactions[0].Request.HeaderNames[0] = "mutated-caller-copy"
			}
		},
	)
	timeline.ObserveRequest([]byte(
		"GET /immutable HTTP/1.1\r\nHost: api.example.com\r\nX-Test: private\r\n\r\n",
	))
	timeline.ObserveResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Response: private\r\n\r\n",
	))
	if len(snapshots) != 2 || snapshots[0][0].Response != nil ||
		snapshots[1][0].Response == nil ||
		!slices.Equal(snapshots[1][0].Request.HeaderNames, []string{"host", "x-test"}) {
		t.Fatalf("timeline snapshots share mutable state: %#v", snapshots)
	}
}

func TestHTTP1TimelineRejectsConnectHostBeyondDNSBound(t *testing.T) {
	host := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 62),
	}, ".")
	if len(host) != 254 {
		t.Fatalf("test host length = %d", len(host))
	}
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
	timeline.ObserveRequest([]byte(fmt.Sprintf(
		"CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n",
		host,
		host,
	)))
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 0 {
		t.Fatalf("overlong CONNECT host crossed the wire contract: %#v", latest)
	}
}

func TestHTTP1TimelineCorrelatesPipelinedHeadAndNoBodyResponses(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
	timeline.ObserveRequest([]byte(
		"GET /a HTTP/1.1\r\nHost: api.example.com\r\n\r\n" +
			"HEAD /b HTTP/1.1\r\nHost: api.example.com\r\n\r\n" +
			"GET /c HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n",
	))
	timeline.ObserveResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nONE" +
			"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n" +
			"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n",
	))
	latest := recorder.latest(t)
	if latest.truncated || len(latest.transactions) != 3 {
		t.Fatalf("unexpected pipelined timeline: %#v", latest)
	}
	for index, status := range []int{200, 200, 304} {
		if latest.transactions[index].Sequence != index+1 ||
			latest.transactions[index].Response == nil ||
			latest.transactions[index].Response.StatusCode != status {
			t.Fatalf("unexpected response %d: %#v", index, latest.transactions[index])
		}
	}
}

func TestHTTP1TimelinePublishesTruncationWhenTerminalBodyCompletesLater(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"GET /first HTTP/1.1\r\nHost: api.example.com\r\n\r\n" +
			"GET /queued HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	timeline.ObserveResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n",
	))
	beforeBody := recorder.latest(t)
	if beforeBody.truncated || len(beforeBody.transactions) != 2 ||
		beforeBody.transactions[0].Response == nil {
		t.Fatalf("terminal response header produced an invalid prefix: %#v", beforeBody)
	}
	timeline.ObserveResponse([]byte("ONE"))
	afterBody := recorder.latest(t)
	if !afterBody.truncated || len(afterBody.transactions) != 2 ||
		afterBody.transactions[1].Response != nil {
		t.Fatalf("terminal body completion did not publish the unmatched tail: %#v", afterBody)
	}
}

func TestHTTP1TimelineStopsNormallyForCloseDelimitedUpgradeAndConnect(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		request  string
		response string
		status   int
	}{
		{
			name:     "close-delimited",
			request:  "GET /close HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			response: "HTTP/1.1 200 OK\r\nConnection: close\r\nX-Secret: private\r\n\r\nprivate-body",
			status:   200,
		},
		{
			name:     "upgrade",
			request:  "GET /socket HTTP/1.1\r\nHost: api.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nopaque-client-private",
			response: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nopaque-private",
			status:   101,
		},
		{
			name:     "connect",
			request:  "CONNECT tunnel.example.com:443 HTTP/1.1\r\nHost: tunnel.example.com:443\r\n\r\nopaque-client-private",
			response: "HTTP/1.1 200 Connection Established\r\n\r\nopaque-private",
			status:   200,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			recorder := &httpTimelineRecorder{}
			timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
			timeline.ObserveRequest([]byte(scenario.request))
			timeline.ObserveResponse([]byte(scenario.response))
			timeline.FinishRequest()
			timeline.FinishResponse()
			latest := recorder.latest(t)
			if latest.truncated || len(latest.transactions) != 1 ||
				latest.transactions[0].Response == nil ||
				latest.transactions[0].Response.StatusCode != scenario.status {
				t.Fatalf("unexpected terminal timeline: %#v", latest)
			}
			encoded, err := json.Marshal(latest)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "private") ||
				strings.Contains(string(encoded), "Switching Protocols") ||
				strings.Contains(string(encoded), "Connection Established") {
				t.Fatalf("terminal timeline retained values: %s", encoded)
			}
		})
	}
}

func TestHTTP1TimelineRejectsForbiddenBodyFraming(t *testing.T) {
	responseScenarios := []struct {
		name     string
		request  string
		response string
	}{
		{
			name:     "informational content length",
			request:  "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			response: "HTTP/1.1 100 Continue\r\nContent-Length: 1\r\n\r\n",
		},
		{
			name: "switching protocols content length",
			request: "GET /socket HTTP/1.1\r\nHost: api.example.com\r\n" +
				"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
			response: "HTTP/1.1 101 Switching Protocols\r\n" +
				"Connection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name: "connect success transfer encoding",
			request: "CONNECT api.example.com:443 HTTP/1.1\r\n" +
				"Host: api.example.com:443\r\n\r\n",
			response: "HTTP/1.1 200 Connection Established\r\n" +
				"Transfer-Encoding: chunked\r\n\r\n",
		},
		{
			name:     "no content content length",
			request:  "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			response: "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:     "reset content nonzero length",
			request:  "POST /reset HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
			response: "HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\n",
		},
		{
			name:     "HTTP 1.0 transfer encoding",
			request:  "GET / HTTP/1.0\r\nHost: api.example.com\r\n\r\n",
			response: "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
		},
	}
	for _, scenario := range responseScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			recorder := &httpTimelineRecorder{}
			timeline := newHTTP1MetadataTimeline(
				time.Now(),
				"api.example.com",
				recorder.publish,
			)
			timeline.ObserveRequest([]byte(scenario.request))
			timeline.ObserveResponse([]byte(scenario.response))
			latest := recorder.latest(t)
			if !latest.truncated || len(latest.transactions) != 1 ||
				latest.transactions[0].Response != nil {
				t.Fatalf("forbidden response framing crossed the observer: %#v", latest)
			}
		})
	}

	t.Run("HTTP 1.0 request transfer encoding", func(t *testing.T) {
		recorder := &httpTimelineRecorder{}
		timeline := newHTTP1MetadataTimeline(
			time.Now(),
			"api.example.com",
			recorder.publish,
		)
		timeline.ObserveRequest([]byte(
			"POST / HTTP/1.0\r\nHost: api.example.com\r\n" +
				"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		))
		latest := recorder.latest(t)
		if !latest.truncated || len(latest.transactions) != 0 {
			t.Fatalf("HTTP/1.0 transfer framing was accepted: %#v", latest)
		}
	})

	t.Run("reset content zero length remains valid", func(t *testing.T) {
		recorder := &httpTimelineRecorder{}
		timeline := newHTTP1MetadataTimeline(
			time.Now(),
			"api.example.com",
			recorder.publish,
		)
		timeline.ObserveRequest([]byte(
			"POST /reset HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
		))
		timeline.ObserveResponse([]byte(
			"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n",
		))
		latest := recorder.latest(t)
		if latest.truncated || len(latest.transactions) != 1 ||
			latest.transactions[0].Response == nil ||
			latest.transactions[0].Response.StatusCode != 205 {
			t.Fatalf("valid zero-length 205 response was rejected: %#v", latest)
		}
	})
}

func TestHTTP1TimelineFailsClosedOnAmbiguousFraming(t *testing.T) {
	for _, request := range []string{
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nDATA",
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nDATA",
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: gzip\r\n\r\nDATA",
	} {
		recorder := &httpTimelineRecorder{}
		timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
		timeline.ObserveRequest([]byte(request))
		latest := recorder.latest(t)
		if !latest.truncated || len(latest.transactions) != 0 {
			t.Fatalf("ambiguous framing did not fail closed: %#v", latest)
		}
	}

	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
	timeline.ObserveRequest([]byte(
		"POST /chunked HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"not-hex\r\nprivate",
	))
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 1 {
		t.Fatalf("malformed chunking did not retain only safe request metadata: %#v", latest)
	}
}

func TestHTTP1TimelineRejectsForbiddenChunkTrailers(t *testing.T) {
	for _, trailer := range []string{
		"Content-Length: 0\r\n",
		"Transfer-Encoding: chunked\r\n",
		"Trailer: X-Later\r\n",
	} {
		recorder := &httpTimelineRecorder{}
		timeline := newHTTP1MetadataTimeline(
			time.Now(),
			"api.example.com",
			recorder.publish,
		)
		timeline.ObserveRequest([]byte(
			"POST /chunked HTTP/1.1\r\nHost: api.example.com\r\n" +
				"Transfer-Encoding: chunked\r\n\r\n" +
				"1\r\nX\r\n0\r\n" + trailer + "\r\n",
		))
		latest := recorder.latest(t)
		if !latest.truncated || len(latest.transactions) != 1 ||
			latest.transactions[0].Request.Target != "/chunked" {
			t.Fatalf("forbidden chunk trailer was accepted: trailer=%q timeline=%#v", trailer, latest)
		}
	}

	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"POST /chunked HTTP/1.1\r\nHost: api.example.com\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"1\r\nX\r\n0\r\nX-Checksum: private-value\r\n\r\n" +
			"GET /next HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	latest := recorder.latest(t)
	if latest.truncated || len(latest.transactions) != 2 ||
		latest.transactions[1].Request.Target != "/next" {
		t.Fatalf("safe chunk trailer broke request framing: %#v", latest)
	}
}

func TestHTTPChunkExtensionsUseStrictHTTPGrammar(t *testing.T) {
	for _, line := range []string{
		"4;foo",
		"4;foo=bar;quoted=\"a\\\"b\"",
		"4;empty=\"\"",
		"4 ; foo = bar ; quoted = \"a\\\"b\" ",
		"4;\tfoo\t=\tbar\t;\tbare",
	} {
		if size, valid := parseHTTPChunkSize([]byte(line)); !valid || size != 4 {
			t.Fatalf("valid chunk extension %q was rejected: size=%d valid=%v", line, size, valid)
		}
	}
	for _, line := range []string{
		"4;",
		"4;=value",
		"4;name=",
		"4;name==value",
		"4;name=\"unterminated",
		"4;\u00a0name=value",
		"4;name=\u00a0value",
	} {
		if _, valid := parseHTTPChunkSize([]byte(line)); valid {
			t.Fatalf("malformed chunk extension %q was accepted", line)
		}
	}
}

func TestHTTPTransferCodingsUseStrictParameterGrammar(t *testing.T) {
	for _, scenario := range []struct {
		value string
		want  []string
	}{
		{value: "gzip, chunked", want: []string{"gzip", "chunked"}},
		{value: "gzip ; level = 9 , chunked", want: []string{"gzip", "chunked"}},
		{value: "custom; note=\"a,b\", chunked", want: []string{"custom", "chunked"}},
	} {
		value, valid := parseHTTPTransferCodings(scenario.value)
		if !valid || !slices.Equal(value, scenario.want) {
			t.Fatalf("valid transfer coding %q was rejected: %#v valid=%v", scenario.value, value, valid)
		}
	}
	for _, value := range []string{
		"chunked;foo=bar",
		"gzip;foo, chunked",
		"gzip;foo==bar, chunked",
		"gzip;foo=\"unterminated, chunked",
		"gzip;foo=\x00, chunked",
		"gzip;\u00a0foo=bar, chunked",
	} {
		if _, valid := parseHTTPTransferCodings(value); valid {
			t.Fatalf("malformed transfer coding %q was accepted", value)
		}
	}
}

func TestHTTP1TimelineRejectsHostMismatchAndMalformedChunkExtension(t *testing.T) {
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n",
		"GET / HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: \u00a0api.example.com\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: \u00a04\r\n\r\nDATA",
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n1;bad=\x00\r\nX\r\n0\r\n\r\n",
	} {
		recorder := &httpTimelineRecorder{}
		timeline := newHTTP1MetadataTimeline(
			time.Now(),
			"api.example.com",
			recorder.publish,
		)
		timeline.ObserveRequest([]byte(request))
		latest := recorder.latest(t)
		if !latest.truncated {
			t.Fatalf("unsafe request did not fail closed: %#v", latest)
		}
	}
}

func TestHTTP1TimelineRejectsAmbiguousUpgradeRequest(t *testing.T) {
	for _, request := range []string{
		"GET /socket HTTP/1.1\r\nHost: api.example.com\r\nConnection: Upgrade\r\n\r\n",
		"GET /socket HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\n\r\n",
	} {
		recorder := &httpTimelineRecorder{}
		timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
		timeline.ObserveRequest([]byte(request))
		latest := recorder.latest(t)
		if !latest.truncated || len(latest.transactions) != 0 {
			t.Fatalf("ambiguous upgrade request did not fail closed: %#v", latest)
		}
	}
}

func TestHTTP1TimelineRejectsTruncatedHTTP10Host(t *testing.T) {
	host := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 62),
	}, ".")
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
	timeline.ObserveRequest([]byte(fmt.Sprintf(
		"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
		host,
	)))
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 0 {
		t.Fatalf("truncated HTTP/1.0 Host crossed the runtime contract: %#v", latest)
	}
}

func TestHTTP1TimelineContinuesAfterExplicitZeroLengthResetContent(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"GET /reset HTTP/1.1\r\nHost: api.example.com\r\n\r\n" +
			"GET /next HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	timeline.ObserveResponse([]byte(
		"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n" +
			"HTTP/1.1 204 No Content\r\n\r\n",
	))
	latest := recorder.latest(t)
	if latest.truncated || len(latest.transactions) != 2 ||
		latest.transactions[0].Response == nil ||
		latest.transactions[0].Response.StatusCode != 205 ||
		latest.transactions[1].Response == nil ||
		latest.transactions[1].Response.StatusCode != 204 {
		t.Fatalf("explicit zero-length 205 consumed the following response: %#v", latest)
	}
}

func TestHTTP1TimelineTreatsUnframedResetContentAsCloseDelimited(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(
		time.Now(),
		"api.example.com",
		recorder.publish,
	)
	timeline.ObserveRequest([]byte(
		"GET /reset HTTP/1.1\r\nHost: api.example.com\r\n\r\n" +
			"GET /next HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	))
	timeline.ObserveResponse([]byte(
		"HTTP/1.1 205 Reset Content\r\n\r\n" +
			"HTTP/1.1 204 No Content\r\n\r\n",
	))
	timeline.FinishResponse()
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != 2 ||
		latest.transactions[0].Response == nil ||
		latest.transactions[0].Response.StatusCode != 205 ||
		latest.transactions[1].Response != nil {
		t.Fatalf("unframed 205 was incorrectly treated as reusable: %#v", latest)
	}
}

func TestHTTP1TimelineCapsTransactions(t *testing.T) {
	recorder := &httpTimelineRecorder{}
	timeline := newHTTP1MetadataTimeline(time.Now(), "api.example.com", recorder.publish)
	var requests strings.Builder
	for index := 0; index < maxHTTPMetadataTransactions+4; index++ {
		fmt.Fprintf(&requests, "GET /%d?secret=%d HTTP/1.1\r\nHost: api.example.com\r\n\r\n", index, index)
	}
	timeline.ObserveRequest([]byte(requests.String()))
	latest := recorder.latest(t)
	if !latest.truncated || len(latest.transactions) != maxHTTPMetadataTransactions {
		t.Fatalf("transaction cap not enforced: %#v", latest)
	}
	for index, transaction := range latest.transactions {
		if transaction.Sequence != index+1 || transaction.Request.Target != fmt.Sprintf("/%d", index) {
			t.Fatalf("unexpected capped transaction %d: %#v", index, transaction)
		}
	}
}

func TestRuntimeCaptureSessionSignalClearsTransientTimelineImmediately(t *testing.T) {
	activeSession := "http-capture:session-a"
	signal := make(chan struct{})
	runtime := &Runtime{config: Config{
		CaptureSession:        func() string { return activeSession },
		CaptureSessionChanged: func() <-chan struct{} { return signal },
		Observe:               func(Observation) {},
	}}
	observation := &runtimeObservation{value: Observation{
		SessionID:    activeSession,
		ConnectionID: "0123456789abcdef0123456789abcdef",
		RuntimeID:    "abcdef0123456789abcdef0123456789",
		Host:         "api.example.com",
		State:        "running",
		StartedAt:    time.Now().UTC(),
	}}
	timeline := newHTTP1MetadataTimeline(
		observation.value.StartedAt,
		observation.value.Host,
		func([]HTTPTransactionObservation, bool) {},
	)
	timeline.ObserveRequest([]byte(
		"GET /published HTTP/1.1\r\nHost: api.example.com\r\n\r\n" +
			"GET /private HTTP/1.1\r\nHost: api.example.com\r\nX-Partial: value",
	))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		runtime.watchHTTP1Timeline(ctx, observation, timeline, signal, done)
	}()
	close(signal)
	select {
	case <-watcherDone:
	case <-time.After(time.Second):
		t.Fatal("capture session signal did not abort the timeline")
	}
	timeline.mu.Lock()
	defer timeline.mu.Unlock()
	if !timeline.stopped || timeline.request.header != nil ||
		timeline.response.header != nil || len(timeline.transactions) != 0 {
		t.Fatalf("capture stop retained transient metadata: %#v", timeline)
	}
}

func TestRuntimeObservationDropsTimelineAfterCaptureSessionChanges(t *testing.T) {
	activeSession := "http-capture:session-a"
	var published []Observation
	runtime := &Runtime{config: Config{
		CaptureSession: func() string { return activeSession },
		Observe: func(value Observation) {
			published = append(published, cloneObservation(value))
		},
	}}
	observation := &runtimeObservation{value: Observation{
		SessionID:    activeSession,
		ConnectionID: "0123456789abcdef0123456789abcdef",
		RuntimeID:    "abcdef0123456789abcdef0123456789",
		Host:         "api.example.com",
		State:        "running",
		StartedAt:    time.Now().UTC(),
	}}
	activeSession = "http-capture:session-b"
	runtime.publishHTTPTransactions(observation, []HTTPTransactionObservation{{
		Sequence: 1,
		Request: HTTPRequestObservation{
			Method: "GET", Target: "/", Version: "HTTP/1.1", HeadersComplete: true,
		},
	}}, false)
	runtime.updateObservation(observation, func(value *Observation) {
		value.ALPN = "http/1.1"
	})
	if len(published) != 0 || len(observation.value.HTTPTransactions) != 0 ||
		observation.value.ALPN != "" {
		t.Fatalf("stale capture session published metadata: %#v", published)
	}
}

func TestRuntimeObservationSerializesTimelinePublications(t *testing.T) {
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondPublished := make(chan struct{}, 1)
	var publishedMu sync.Mutex
	var published []Observation
	runtime := &Runtime{config: Config{
		CaptureSession: func() string { return "http-capture:serialized" },
		Observe: func(value Observation) {
			if len(value.HTTPTransactions) == 1 {
				select {
				case <-firstEntered:
				default:
					close(firstEntered)
					<-releaseFirst
				}
			}
			if len(value.HTTPTransactions) == 2 {
				select {
				case secondPublished <- struct{}{}:
				default:
				}
			}
			publishedMu.Lock()
			published = append(published, cloneObservation(value))
			publishedMu.Unlock()
		},
	}}
	observation := &runtimeObservation{value: Observation{
		SessionID:    "http-capture:serialized",
		ConnectionID: "0123456789abcdef0123456789abcdef",
		RuntimeID:    "abcdef0123456789abcdef0123456789",
		Host:         "api.example.com",
		State:        "running",
		StartedAt:    time.Now().UTC(),
	}}
	first := []HTTPTransactionObservation{{
		Sequence: 1,
		Request: HTTPRequestObservation{
			Method: "GET", Target: "/one", Version: "HTTP/1.1", HeadersComplete: true,
		},
	}}
	second := append(cloneHTTPTransactionObservations(first), HTTPTransactionObservation{
		Sequence: 2,
		Request: HTTPRequestObservation{
			Method: "GET", Target: "/two", Version: "HTTP/1.1", HeadersComplete: true,
		},
	})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		runtime.publishHTTPTransactions(observation, first, false)
	}()
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first publication did not reach callback")
	}
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		runtime.publishHTTPTransactions(observation, second, true)
	}()
	select {
	case <-secondPublished:
		t.Fatal("second publication overtook first")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseFirst)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first publication did not finish")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second publication did not finish")
	}
	publishedMu.Lock()
	defer publishedMu.Unlock()
	if len(published) != 2 || len(published[0].HTTPTransactions) != 1 ||
		len(published[1].HTTPTransactions) != 2 ||
		!published[1].HTTPTransactionsTruncated {
		t.Fatalf("timeline publications reordered: %#v", published)
	}
}
