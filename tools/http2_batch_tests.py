from pathlib import Path

from http2_batch_common import ROOT


def write_capture_policy_tests() -> None:
    (ROOT / "core/inspectionruntime/capture_policy_test.go").write_text(r'''package inspectionruntime

import "testing"

func TestCapturePolicyNormalizesAndRedactsHeaderValues(t *testing.T) {
	policy := (CapturePolicy{
		HeaderValues:          true,
		SensitiveHeaderValues: false,
		RedactedHeaderNames: []string{
			"X-Debug",
			"x-debug",
			"bad header",
		},
		BodyMode:     CaptureBodyAll,
		MaxBodyBytes: MaxCaptureBodyBytes + 1,
	}).Normalize()
	if !policy.HeaderValues || policy.SensitiveHeaderValues {
		t.Fatalf("unexpected header policy: %+v", policy)
	}
	if policy.BodyMode != CaptureBodyAll || policy.MaxBodyBytes != MaxCaptureBodyBytes {
		t.Fatalf("unexpected body policy: %+v", policy)
	}
	if len(policy.RedactedHeaderNames) != 1 || policy.RedactedHeaderNames[0] != "x-debug" {
		t.Fatalf("unexpected custom redactions: %#v", policy.RedactedHeaderNames)
	}

	values, truncated := captureRawHTTPHeaderValues([][]byte{
		[]byte("Authorization: Bearer secret"),
		[]byte("Cookie: sid=private"),
		[]byte("X-Debug: private-debug"),
		[]byte("User-Agent: FlClash-Test"),
	}, policy)
	if truncated || len(values) != 4 {
		t.Fatalf("unexpected captured headers: truncated=%t values=%#v", truncated, values)
	}
	for _, index := range []int{0, 1, 2} {
		if !values[index].Redacted || values[index].Value != "" {
			t.Fatalf("header %d was not redacted: %#v", index, values[index])
		}
	}
	if values[3].Redacted || values[3].Value != "FlClash-Test" {
		t.Fatalf("ordinary header was not retained: %#v", values[3])
	}

	policy.SensitiveHeaderValues = true
	values, truncated = captureRawHTTPHeaderValues([][]byte{
		[]byte("Authorization: Bearer authorized"),
		[]byte("X-Debug: still-private"),
	}, policy.Normalize())
	if truncated || len(values) != 2 {
		t.Fatalf("unexpected authorized capture: truncated=%t values=%#v", truncated, values)
	}
	if values[0].Redacted || values[0].Value != "Bearer authorized" {
		t.Fatalf("sensitive authorization was not honored: %#v", values[0])
	}
	if !values[1].Redacted {
		t.Fatalf("custom redaction was bypassed: %#v", values[1])
	}
}

func TestBodyCaptureAppliesTypeAndCapacityPolicy(t *testing.T) {
	budget := 5
	reserve := func(requested int) int {
		if requested > budget {
			requested = budget
		}
		budget -= requested
		return requested
	}
	capture := newBodyCaptureAccumulator(
		CapturePolicy{BodyMode: CaptureBodyAll, MaxBodyBytes: 4},
		"application/json; charset=utf-8",
		"",
		reserve,
	)
	capture.Observe([]byte("abcdef"))
	body := capture.Finish()
	if body == nil {
		t.Fatal("expected a body observation")
	}
	if body.Kind != "json" || body.Encoding != "utf8" || body.Text != "abcd" {
		t.Fatalf("unexpected body representation: %+v", body)
	}
	if body.CapturedBytes != 4 || body.ObservedBytes != 6 || !body.Truncated {
		t.Fatalf("unexpected body bounds: %+v", body)
	}

	image := newBodyCaptureAccumulator(
		CapturePolicy{BodyMode: CaptureBodyText, MaxBodyBytes: 32},
		"image/png",
		"",
		func(requested int) int { return requested },
	)
	image.Observe([]byte{0x89, 0x50, 0x4e, 0x47})
	imageBody := image.Finish()
	if imageBody == nil || imageBody.Kind != "image" ||
		imageBody.CapturedBytes != 0 || imageBody.ObservedBytes != 4 ||
		imageBody.OmittedReason != "type-not-authorized" || !imageBody.Truncated {
		t.Fatalf("unexpected type-aware omission: %+v", imageBody)
	}
}
''')


def write_http2_tests() -> None:
    (ROOT / "core/inspectionruntime/http2_timeline_test.go").write_text(r'''package inspectionruntime

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

type testHPACKEncoder struct {
	buffer  bytes.Buffer
	encoder *hpack.Encoder
}

func newTestHPACKEncoder() *testHPACKEncoder {
	value := &testHPACKEncoder{}
	value.encoder = hpack.NewEncoder(&value.buffer)
	return value
}

func (e *testHPACKEncoder) block(t *testing.T, fields ...hpack.HeaderField) []byte {
	t.Helper()
	e.buffer.Reset()
	for _, field := range fields {
		if err := e.encoder.WriteField(field); err != nil {
			t.Fatalf("encode HPACK field %q: %v", field.Name, err)
		}
	}
	return append([]byte(nil), e.buffer.Bytes()...)
}

func testHTTP2Frame(frameType byte, flags byte, streamID uint32, payload []byte) []byte {
	frame := make([]byte, 9+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = frameType
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7fffffff)
	copy(frame[9:], payload)
	return frame
}

func findObservedHeader(values []HTTPHeaderObservation, name string) *HTTPHeaderObservation {
	for index := range values {
		if values[index].Name == name {
			return &values[index]
		}
	}
	return nil
}

func TestHTTP2TimelineRetainsConcurrentStreamsAndBodies(t *testing.T) {
	var latest []HTTP2StreamObservation
	var latestTruncated bool
	var latestGoAway *HTTP2GoAwayObservation
	reserve := func(requested int) int { return requested }
	timeline := newHTTP2MetadataTimeline(
		time.Now().Add(-time.Second),
		"api.example.com",
		CapturePolicy{
			HeaderValues: true,
			BodyMode:     CaptureBodyAll,
			MaxBodyBytes: 64,
		},
		reserve,
		func(streams []HTTP2StreamObservation, truncated bool, goAway *HTTP2GoAwayObservation) {
			latest = cloneHTTP2StreamObservations(streams)
			latestTruncated = truncated
			latestGoAway = cloneHTTP2GoAwayObservation(goAway)
		},
	)

	clientEncoder := newTestHPACKEncoder()
	serverEncoder := newTestHPACKEncoder()
	clientStart := append([]byte(http2ClientPreface), testHTTP2Frame(
		http2FrameSettings,
		0,
		0,
		nil,
	)...)
	timeline.ObserveRequest(clientStart)

	requestOne := clientEncoder.block(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "api.example.com"},
		hpack.HeaderField{Name: ":path", Value: "/upload?token=secret"},
		hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"},
		hpack.HeaderField{Name: "authorization", Value: "Bearer secret", Sensitive: true},
	)
	timeline.ObserveRequest(testHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		1,
		requestOne,
	))
	requestThree := clientEncoder.block(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "api.example.com"},
		hpack.HeaderField{Name: ":path", Value: "/health"},
	)
	timeline.ObserveRequest(testHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		3,
		requestThree,
	))
	timeline.ObserveRequest(testHTTP2Frame(
		http2FrameData,
		http2FlagEndStream,
		1,
		[]byte("a=1"),
	))

	timeline.ObserveResponse(testHTTP2Frame(http2FrameSettings, 0, 0, nil))
	responseThree := serverEncoder.block(t,
		hpack.HeaderField{Name: ":status", Value: "204"},
	)
	timeline.ObserveResponse(testHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		3,
		responseThree,
	))
	responseOne := serverEncoder.block(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
	)
	timeline.ObserveResponse(testHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		1,
		responseOne,
	))
	timeline.ObserveResponse(testHTTP2Frame(
		http2FrameData,
		http2FlagEndStream,
		1,
		[]byte(`{"ok":true}`),
	))

	if latestTruncated || len(latest) != 2 {
		t.Fatalf("unexpected stream snapshot: truncated=%t streams=%#v", latestTruncated, latest)
	}
	first := latest[0]
	second := latest[1]
	if first.StreamID != 1 || first.Sequence != 1 || first.State != "closed" {
		t.Fatalf("unexpected first stream identity: %+v", first)
	}
	if second.StreamID != 3 || second.Sequence != 2 || second.State != "closed" {
		t.Fatalf("unexpected second stream identity: %+v", second)
	}
	if first.Request == nil || first.Request.Target != "/upload" || first.Request.Version != "HTTP/2" {
		t.Fatalf("unexpected request metadata: %+v", first.Request)
	}
	authorization := findObservedHeader(first.Request.Headers, "authorization")
	if authorization == nil || !authorization.Redacted || authorization.Value != "" {
		t.Fatalf("authorization was not redacted: %+v", authorization)
	}
	if first.RequestBody == nil || first.RequestBody.Kind != "form" || first.RequestBody.Text != "a=1" {
		t.Fatalf("unexpected request body: %+v", first.RequestBody)
	}
	if first.Response == nil || first.Response.StatusCode != 200 ||
		first.ResponseBody == nil || first.ResponseBody.Kind != "json" ||
		first.ResponseBody.Text != `{"ok":true}` {
		t.Fatalf("unexpected first response: response=%+v body=%+v", first.Response, first.ResponseBody)
	}
	if second.Response == nil || second.Response.StatusCode != 204 {
		t.Fatalf("out-of-order response was attached incorrectly: %+v", second.Response)
	}

	goAwayPayload := make([]byte, 8)
	binary.BigEndian.PutUint32(goAwayPayload[:4], 3)
	timeline.ObserveResponse(testHTTP2Frame(http2FrameGoAway, 0, 0, goAwayPayload))
	if latestGoAway == nil || latestGoAway.LastStreamID != 3 || latestGoAway.ErrorCode != 0 {
		t.Fatalf("unexpected GOAWAY observation: %+v", latestGoAway)
	}
}

func TestHTTP2TimelineFailsClosedOnInterleavedContinuation(t *testing.T) {
	var published bool
	var truncated bool
	timeline := newHTTP2MetadataTimeline(
		time.Now(),
		"api.example.com",
		CapturePolicy{},
		nil,
		func(_ []HTTP2StreamObservation, value bool, _ *HTTP2GoAwayObservation) {
			published = true
			truncated = value
		},
	)
	start := append([]byte(http2ClientPreface), testHTTP2Frame(
		http2FrameHeaders,
		0,
		1,
		[]byte{0x82},
	)...)
	timeline.ObserveRequest(start)
	timeline.ObserveRequest(testHTTP2Frame(http2FrameData, 0, 1, nil))
	if !published || !truncated {
		t.Fatalf("interleaved CONTINUATION was not rejected: published=%t truncated=%t", published, truncated)
	}
}
''')


def write_tests() -> None:
    write_capture_policy_tests()
    write_http2_tests()
