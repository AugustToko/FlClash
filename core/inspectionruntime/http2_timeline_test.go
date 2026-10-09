package inspectionruntime

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
