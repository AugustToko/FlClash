package inspectionruntime

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHTTPRequestMetadataObserverSanitizesAndDiscardsValues(t *testing.T) {
	observer := newHTTPRequestMetadataObserver()
	chunks := [][]byte{
		[]byte("GET /items?token=private-query#fragment HTTP/1.1\r\nHo"),
		[]byte("st: API.Example.com:443\r\nAuthorization: Bearer private-token\r\nCookie: session=private-cookie\r\nX-Trace: private-header-value\r\n\r\nprivate-request-body"),
	}
	var result *HTTPRequestObservation
	for index, chunk := range chunks {
		value, done := observer.Observe(chunk)
		if index == 0 && done {
			t.Fatal("request observation completed before the header boundary")
		}
		if done {
			result = value
		}
	}
	if result == nil || result.Method != "GET" || result.Target != "/items" ||
		result.Version != "HTTP/1.1" || result.Host != "api.example.com" ||
		!result.HeadersComplete || !slices.Equal(result.HeaderNames, []string{"host", "authorization", "cookie", "x-trace"}) {
		t.Fatalf("unexpected request observation: %#v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-query", "fragment", "private-token", "private-cookie", "private-header-value", "private-request-body"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("request observation retained %q: %s", secret, encoded)
		}
	}
}

func TestHTTPResponseMetadataObserverTracksInformationalAndFinalStatus(t *testing.T) {
	observer := newHTTPResponseMetadataObserver(time.Now().Add(-20 * time.Millisecond))
	chunks := [][]byte{
		[]byte("HTTP/1.1 100 Continue\r\nX-Interim: private-interim\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </private>; rel=preload\r\n\r\nHTTP/1.1 20"),
		[]byte("1 Secret Created\r\nContent-Type: text/plain\r\nSet-Cookie: session=private-cookie\r\nLocation: /private?token=secret\r\n\r\nprivate-response-body"),
	}
	var result *HTTPResponseObservation
	for index, chunk := range chunks {
		value, done := observer.Observe(chunk)
		if index == 0 && done {
			t.Fatal("response observation completed before the final header")
		}
		if done {
			result = value
		}
	}
	if result == nil || result.StatusCode != 201 || result.Version != "HTTP/1.1" ||
		!result.HeadersComplete || result.Truncated ||
		!slices.Equal(result.InformationalStatusCodes, []int{100, 103}) ||
		!slices.Equal(result.HeaderNames, []string{"content-type", "set-cookie", "location"}) ||
		result.ObservedAfterMilliseconds < 0 || result.ObservedBytes <= 0 {
		t.Fatalf("unexpected response observation: %#v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-interim", "Early Hints", "Secret Created", "private-cookie", "/private", "token=secret", "private-response-body"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("response observation retained %q: %s", secret, encoded)
		}
	}
}

func TestHTTPMetadataObserversFailClosedWithoutChangingBytes(t *testing.T) {
	input := []byte("NOT HTTP\nAuthorization: private\n\nopaque-private-body")
	observer := newHTTPRequestMetadataObserver()
	reader := &metadataObservingReader{
		reader: bytes.NewReader(input),
		observe: func(data []byte) {
			_, _ = observer.Observe(data)
		},
		finish: func() {
			value, _ := observer.Finish()
			if value != nil {
				t.Fatalf("malformed stream produced metadata: %#v", value)
			}
		},
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	reader.Finish()
	if !bytes.Equal(output, input) {
		t.Fatalf("observer changed relayed bytes: got %q want %q", output, input)
	}
}

func TestMetadataObservingReaderAbortsWhenFinishPanics(t *testing.T) {
	input := []byte("GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: private")
	observer := newHTTPRequestMetadataObserver()
	aborted := 0
	reader := &metadataObservingReader{
		reader: bytes.NewReader(input),
		observe: func(data []byte) {
			_, _ = observer.Observe(data)
		},
		finish: func() {
			panic("private finish panic")
		},
		abort: func() {
			aborted++
			observer.Abort()
		},
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	reader.Finish()
	if !bytes.Equal(output, input) {
		t.Fatal("finish panic changed relayed bytes")
	}
	if aborted != 1 || !observer.done || observer.buffer != nil {
		t.Fatalf("finish panic did not abort metadata: aborted=%d observer=%#v", aborted, observer)
	}
}

func TestMetadataObservingReaderContainsCallbackPanics(t *testing.T) {
	input := []byte("GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: private\r\n")
	observer := newHTTPRequestMetadataObserver()
	aborted := 0
	finished := 0
	reader := &metadataObservingReader{
		reader: bytes.NewReader(input),
		observe: func(data []byte) {
			_, _ = observer.Observe(data)
			panic("private callback panic")
		},
		finish: func() {
			finished++
			_, _ = observer.Finish()
		},
		abort: func() {
			aborted++
			observer.Abort()
		},
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	reader.Finish()
	if !bytes.Equal(output, input) {
		t.Fatal("callback panic changed relayed bytes")
	}
	if aborted != 1 || finished != 0 || !observer.done || observer.buffer != nil {
		t.Fatalf("panic did not immediately abort metadata: aborted=%d finished=%d observer=%#v", aborted, finished, observer)
	}
}

func TestHTTPMetadataObserversBoundTruncatedHeaders(t *testing.T) {
	request := newHTTPRequestMetadataObserver()
	requestData := append([]byte("GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Large: "), bytes.Repeat([]byte{'a'}, maxHTTPMetadataBytes)...)
	requestValue, requestDone := request.Observe(requestData)
	if !requestDone || requestValue == nil || requestValue.HeadersComplete || !requestValue.HeaderNamesTruncated || requestValue.Host != "api.example.com" {
		t.Fatalf("unexpected truncated request: %#v, done=%v", requestValue, requestDone)
	}

	response := newHTTPResponseMetadataObserver(time.Now())
	responseData := append([]byte("HTTP/1.1 200 Secret\r\nX-Large: "), bytes.Repeat([]byte{'b'}, maxHTTPMetadataBytes)...)
	responseValue, responseDone := response.Observe(responseData)
	if !responseDone || responseValue == nil || responseValue.StatusCode != 200 || responseValue.HeadersComplete || !responseValue.Truncated || responseValue.ObservedBytes != maxHTTPMetadataBytes {
		t.Fatalf("unexpected truncated response: %#v, done=%v", responseValue, responseDone)
	}
	encoded, err := json.Marshal(responseValue)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), strings.Repeat("b", 32)) || strings.Contains(string(encoded), "Secret") {
		t.Fatalf("truncated response retained values: %s", encoded)
	}
}

func TestHTTPResponseMetadataTreatsSwitchingProtocolsAsFinal(t *testing.T) {
	observer := newHTTPResponseMetadataObserver(time.Now())
	value, done := observer.Observe([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nopaque"))
	if !done || value == nil || value.StatusCode != 101 || !value.HeadersComplete || !slices.Equal(value.HeaderNames, []string{"upgrade"}) {
		t.Fatalf("unexpected 101 observation: %#v, done=%v", value, done)
	}
}
