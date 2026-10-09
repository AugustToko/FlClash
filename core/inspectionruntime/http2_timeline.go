package inspectionruntime

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
)

type http2StreamState struct {
	value           HTTP2StreamObservation
	requestBody     *bodyCaptureAccumulator
	responseBody    *bodyCaptureAccumulator
	requestHeaders  bool
	responseHeaders bool
	requestEnded    bool
	responseEnded   bool
	informational   []int
}

type http2HeaderKind uint8

const (
	http2RequestHeaders http2HeaderKind = iota
	http2ResponseHeaders
	http2PushRequestHeaders
)

type http2PendingHeaders struct {
	continuationStream uint32
	targetStream       uint32
	kind               http2HeaderKind
	endStream          bool
	compressedBytes    int
	block              []byte
}

type http2DirectionState struct {
	fromClient bool
	preface    int
	buffer     []byte
	pending    *http2PendingHeaders
	collector  http2HeaderCollector
	decoder    *hpack.Decoder
	stopped    bool
}

type http2MetadataTimeline struct {
	mu           sync.Mutex
	publishMu    sync.Mutex
	startedAt    time.Time
	expectedHost string
	policy       CapturePolicy
	reserveBody  func(int) int
	client       http2DirectionState
	server       http2DirectionState
	streams      map[uint32]*http2StreamState
	ignored      map[uint32]struct{}
	order        []uint32
	goAway       *HTTP2GoAwayObservation
	truncated    bool
	stopped      bool
	publish      func([]HTTP2StreamObservation, bool, *HTTP2GoAwayObservation)
}

func newHTTP2MetadataTimeline(
	startedAt time.Time,
	expectedHost string,
	policy CapturePolicy,
	reserveBody func(int) int,
	publish func([]HTTP2StreamObservation, bool, *HTTP2GoAwayObservation),
) *http2MetadataTimeline {
	timeline := &http2MetadataTimeline{
		startedAt:    startedAt,
		expectedHost: expectedHost,
		policy:       policy.Normalize(),
		reserveBody:  reserveBody,
		client: http2DirectionState{
			fromClient: true,
			buffer:     make([]byte, 0, 16*1024),
		},
		server: http2DirectionState{
			buffer: make([]byte, 0, 16*1024),
		},
		streams: make(map[uint32]*http2StreamState),
		ignored: make(map[uint32]struct{}),
		order:   make([]uint32, 0, 8),
		publish: publish,
	}
	timeline.client.decoder = hpack.NewDecoder(
		maxHTTP2DynamicTableBytes,
		timeline.client.collector.add,
	)
	timeline.server.decoder = hpack.NewDecoder(
		maxHTTP2DynamicTableBytes,
		timeline.server.collector.add,
	)
	timeline.client.decoder.SetMaxStringLength(MaxCaptureHeaderValueBytes)
	timeline.server.decoder.SetMaxStringLength(MaxCaptureHeaderValueBytes)
	return timeline
}

func (t *http2MetadataTimeline) snapshotLocked() []HTTP2StreamObservation {
	values := make([]HTTP2StreamObservation, 0, len(t.order))
	for _, streamID := range t.order {
		if stream := t.streams[streamID]; stream != nil {
			values = append(values, stream.value)
		}
	}
	return cloneHTTP2StreamObservations(values)
}

func (t *http2MetadataTimeline) publishLocked() {
	if t.publish == nil {
		t.mu.Unlock()
		return
	}
	streams := t.snapshotLocked()
	truncated := t.truncated
	goAway := cloneHTTP2GoAwayObservation(t.goAway)
	t.publishMu.Lock()
	t.mu.Unlock()
	defer t.publishMu.Unlock()
	t.publish(streams, truncated, goAway)
}

func (t *http2MetadataTimeline) ObserveRequest(data []byte) {
	t.observe(&t.client, data)
}

func (t *http2MetadataTimeline) ObserveResponse(data []byte) {
	t.observe(&t.server, data)
}

func (t *http2MetadataTimeline) observe(direction *http2DirectionState, data []byte) {
	if t == nil || direction == nil || len(data) == 0 {
		return
	}
	t.mu.Lock()
	if t.stopped || direction.stopped {
		t.mu.Unlock()
		return
	}
	changed, invalid := t.observeLocked(direction, data)
	if invalid {
		changed = t.failClosedLocked() || changed
	}
	if changed {
		t.publishLocked()
		return
	}
	t.mu.Unlock()
}

func (t *http2MetadataTimeline) observeLocked(
	direction *http2DirectionState,
	data []byte,
) (changed bool, invalid bool) {
	if direction.fromClient && direction.preface < len(http2ClientPreface) {
		remaining := http2ClientPreface[direction.preface:]
		consumed := min(len(data), len(remaining))
		if !bytes.Equal(data[:consumed], []byte(remaining[:consumed])) {
			return false, true
		}
		direction.preface += consumed
		data = data[consumed:]
		if direction.preface < len(http2ClientPreface) {
			return false, false
		}
	}
	if len(data) != 0 {
		if len(direction.buffer)+len(data) > maxHTTP2FramePayloadBytes+9 {
			return false, true
		}
		direction.buffer = append(direction.buffer, data...)
	}
	for len(direction.buffer) >= 9 {
		length := int(direction.buffer[0])<<16 |
			int(direction.buffer[1])<<8 | int(direction.buffer[2])
		if length > maxHTTP2FramePayloadBytes {
			return changed, true
		}
		frameLength := 9 + length
		if len(direction.buffer) < frameLength {
			return changed, false
		}
		frameType := direction.buffer[3]
		flags := direction.buffer[4]
		streamID := binary.BigEndian.Uint32(direction.buffer[5:9]) & 0x7fffffff
		payload := direction.buffer[9:frameLength]
		frameChanged, frameInvalid := t.processFrameLocked(
			direction,
			frameType,
			flags,
			streamID,
			payload,
		)
		changed = changed || frameChanged
		if frameInvalid {
			return changed, true
		}
		remaining := len(direction.buffer) - frameLength
		copy(direction.buffer, direction.buffer[frameLength:])
		clear(direction.buffer[remaining:])
		direction.buffer = direction.buffer[:remaining]
	}
	return changed, false
}

func (t *http2MetadataTimeline) processFrameLocked(
	direction *http2DirectionState,
	frameType byte,
	flags byte,
	streamID uint32,
	payload []byte,
) (bool, bool) {
	if direction.pending != nil && frameType != http2FrameContinuation {
		return false, true
	}
	switch frameType {
	case http2FrameData:
		if streamID == 0 {
			return false, true
		}
		body, valid := http2Unpad(payload, flags)
		if !valid {
			return false, true
		}
		return t.observeDataLocked(
			direction.fromClient,
			streamID,
			body,
			flags&http2FlagEndStream != 0,
		)
	case http2FrameHeaders:
		if streamID == 0 {
			return false, true
		}
		fragment, valid := http2HeaderFragment(payload, flags)
		if !valid {
			return false, true
		}
		kind := http2ResponseHeaders
		if direction.fromClient {
			kind = http2RequestHeaders
		}
		return t.beginHeaderBlockLocked(
			direction,
			streamID,
			streamID,
			kind,
			flags&http2FlagEndStream != 0,
			flags&http2FlagEndHeaders != 0,
			fragment,
		)
	case http2FramePriority:
		return false, streamID == 0 || len(payload) != 5
	case http2FrameRSTStream:
		if streamID == 0 || len(payload) != 4 {
			return false, true
		}
		return t.resetStreamLocked(streamID, binary.BigEndian.Uint32(payload)), false
	case http2FrameSettings:
		if streamID != 0 ||
			flags&http2FlagAck != 0 && len(payload) != 0 ||
			flags&http2FlagAck == 0 && len(payload)%6 != 0 {
			return false, true
		}
		return false, false
	case http2FramePushPromise:
		if direction.fromClient || streamID == 0 {
			return false, true
		}
		promised, fragment, valid := http2PushPromiseFragment(payload, flags)
		if !valid || promised == 0 {
			return false, true
		}
		return t.beginHeaderBlockLocked(
			direction,
			streamID,
			promised,
			http2PushRequestHeaders,
			false,
			flags&http2FlagEndHeaders != 0,
			fragment,
		)
	case http2FramePing:
		return false, streamID != 0 || len(payload) != 8
	case http2FrameGoAway:
		if streamID != 0 || len(payload) < 8 {
			return false, true
		}
		t.goAway = &HTTP2GoAwayObservation{
			LastStreamID:              binary.BigEndian.Uint32(payload[:4]) & 0x7fffffff,
			ErrorCode:                 binary.BigEndian.Uint32(payload[4:8]),
			ObservedAfterMilliseconds: elapsedMilliseconds(t.startedAt),
		}
		return true, false
	case http2FrameWindowUpdate:
		if len(payload) != 4 || binary.BigEndian.Uint32(payload)&0x7fffffff == 0 {
			return false, true
		}
		return false, false
	case http2FrameContinuation:
		if direction.pending == nil || streamID == 0 ||
			direction.pending.continuationStream != streamID {
			return false, true
		}
		return t.continueHeaderBlockLocked(
			direction,
			flags&http2FlagEndHeaders != 0,
			payload,
		)
	default:
		return false, false
	}
}

func http2Unpad(payload []byte, flags byte) ([]byte, bool) {
	if flags&http2FlagPadded == 0 {
		return payload, true
	}
	if len(payload) == 0 {
		return nil, false
	}
	padding := int(payload[0])
	if padding >= len(payload) {
		return nil, false
	}
	return payload[1 : len(payload)-padding], true
}

func http2HeaderFragment(payload []byte, flags byte) ([]byte, bool) {
	body, valid := http2Unpad(payload, flags)
	if !valid {
		return nil, false
	}
	if flags&http2FlagPriority != 0 {
		if len(body) < 5 {
			return nil, false
		}
		body = body[5:]
	}
	return body, true
}

func http2PushPromiseFragment(payload []byte, flags byte) (uint32, []byte, bool) {
	body, valid := http2Unpad(payload, flags)
	if !valid || len(body) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(body[:4]) & 0x7fffffff, body[4:], true
}

func (t *http2MetadataTimeline) beginHeaderBlockLocked(
	direction *http2DirectionState,
	continuationStream uint32,
	targetStream uint32,
	kind http2HeaderKind,
	endStream bool,
	endHeaders bool,
	fragment []byte,
) (bool, bool) {
	if direction.pending != nil || len(fragment) > maxHTTP2HeaderBlockBytes {
		return false, true
	}
	direction.pending = &http2PendingHeaders{
		continuationStream: continuationStream,
		targetStream:       targetStream,
		kind:               kind,
		endStream:          endStream,
		compressedBytes:    len(fragment),
		block:              append(make([]byte, 0, len(fragment)), fragment...),
	}
	if !endHeaders {
		return false, false
	}
	return t.finishHeaderBlockLocked(direction)
}

func (t *http2MetadataTimeline) continueHeaderBlockLocked(
	direction *http2DirectionState,
	endHeaders bool,
	fragment []byte,
) (bool, bool) {
	pending := direction.pending
	if pending == nil || len(pending.block)+len(fragment) > maxHTTP2HeaderBlockBytes {
		return false, true
	}
	pending.compressedBytes += len(fragment)
	pending.block = append(pending.block, fragment...)
	if !endHeaders {
		return false, false
	}
	return t.finishHeaderBlockLocked(direction)
}

func (t *http2MetadataTimeline) finishHeaderBlockLocked(
	direction *http2DirectionState,
) (bool, bool) {
	pending := direction.pending
	if pending == nil {
		return false, true
	}
	direction.collector.reset(t.policy)
	_, err := direction.decoder.Write(pending.block)
	if err == nil {
		err = direction.decoder.Close()
	}
	clear(pending.block)
	pending.block = nil
	if err != nil || direction.collector.invalid {
		direction.collector.clear()
		direction.pending = nil
		return false, true
	}
	changed, valid := t.applyHeadersLocked(
		pending.kind,
		pending.targetStream,
		pending.endStream,
		pending.compressedBytes,
		&direction.collector,
	)
	direction.collector.clear()
	direction.pending = nil
	return changed, !valid
}

func (t *http2MetadataTimeline) applyHeadersLocked(
	kind http2HeaderKind,
	streamID uint32,
	endStream bool,
	compressedBytes int,
	collector *http2HeaderCollector,
) (bool, bool) {
	switch kind {
	case http2RequestHeaders:
		return t.applyRequestHeadersLocked(streamID, endStream, collector)
	case http2ResponseHeaders:
		return t.applyResponseHeadersLocked(
			streamID,
			endStream,
			compressedBytes,
			collector,
		)
	case http2PushRequestHeaders:
		_, valid := parseHTTP2RequestObservation(collector, t.expectedHost)
		if valid {
			t.ignored[streamID] = struct{}{}
		}
		return false, valid
	default:
		return false, false
	}
}

func (t *http2MetadataTimeline) applyRequestHeadersLocked(
	streamID uint32,
	endStream bool,
	collector *http2HeaderCollector,
) (bool, bool) {
	stream := t.streams[streamID]
	if stream != nil && stream.requestHeaders {
		if len(collector.pseudo) != 0 || stream.requestEnded || !endStream {
			return false, false
		}
		return t.completeRequestLocked(stream, false), true
	}
	if streamID%2 == 0 {
		return false, false
	}
	request, valid := parseHTTP2RequestObservation(collector, t.expectedHost)
	if !valid {
		return false, false
	}
	if stream == nil {
		if len(t.order) >= maxHTTP2Streams {
			t.truncated = true
			t.ignored[streamID] = struct{}{}
			return true, true
		}
		stream = &http2StreamState{
			value: HTTP2StreamObservation{
				Sequence: len(t.order) + 1,
				StreamID: streamID,
				State:    "open",
			},
		}
		t.streams[streamID] = stream
		t.order = append(t.order, streamID)
	}
	stream.value.Request = request
	stream.value.RequestObservedAfterMilliseconds = elapsedMilliseconds(t.startedAt)
	stream.requestHeaders = true
	stream.requestBody = newBodyCaptureAccumulator(
		t.policy,
		collector.contentType,
		collector.contentEncoding,
		t.reserveBody,
	)
	changed := true
	if endStream {
		changed = t.completeRequestLocked(stream, false) || changed
	}
	t.updateStreamStateLocked(stream)
	return changed, true
}

func (t *http2MetadataTimeline) applyResponseHeadersLocked(
	streamID uint32,
	endStream bool,
	compressedBytes int,
	collector *http2HeaderCollector,
) (bool, bool) {
	if _, ignored := t.ignored[streamID]; ignored {
		_, valid := parseHTTP2Status(collector.pseudo)
		return false, valid
	}
	stream := t.streams[streamID]
	if stream == nil || !stream.requestHeaders {
		return false, false
	}
	if stream.responseHeaders {
		if len(collector.pseudo) != 0 || stream.responseEnded || !endStream {
			return false, false
		}
		return t.completeResponseLocked(stream, false), true
	}
	status, valid := parseHTTP2Status(collector.pseudo)
	if !valid {
		return false, false
	}
	if status >= 100 && status < 200 {
		if status == 101 || endStream {
			return false, false
		}
		if len(stream.informational) < maxHTTPInformationalStatusCodes {
			stream.informational = append(stream.informational, status)
		}
		return true, true
	}
	response := &HTTPResponseObservation{
		Version:                           "HTTP/2",
		StatusCode:                        status,
		InformationalStatusCodes:          append([]int(nil), stream.informational...),
		HeaderNames:                       append([]string(nil), collector.headerNames...),
		Headers:                           cloneHTTPHeaderObservations(collector.headers),
		HeadersComplete:                   true,
		ObservedBytes:                     compressedBytes,
		ObservedAfterMilliseconds:         elapsedMilliseconds(t.startedAt),
		HeaderNamesTruncated:              collector.namesTruncated,
		HeaderValuesTruncated:             collector.valuesTruncated,
		InformationalStatusCodesTruncated: len(stream.informational) >= maxHTTPInformationalStatusCodes,
	}
	stream.value.Response = response
	stream.responseHeaders = true
	stream.responseBody = newBodyCaptureAccumulator(
		t.policy,
		collector.contentType,
		collector.contentEncoding,
		t.reserveBody,
	)
	changed := true
	if endStream {
		changed = t.completeResponseLocked(stream, false) || changed
	}
	t.updateStreamStateLocked(stream)
	return changed, true
}

func (t *http2MetadataTimeline) observeDataLocked(
	fromClient bool,
	streamID uint32,
	data []byte,
	endStream bool,
) (bool, bool) {
	if _, ignored := t.ignored[streamID]; ignored {
		return false, false
	}
	stream := t.streams[streamID]
	if stream == nil {
		return false, true
	}
	if fromClient {
		if !stream.requestHeaders || stream.requestEnded {
			return false, true
		}
		stream.requestBody.Observe(data)
		if endStream {
			return t.completeRequestLocked(stream, false), false
		}
		return false, false
	}
	if !stream.responseHeaders || stream.responseEnded {
		return false, true
	}
	stream.responseBody.Observe(data)
	if endStream {
		return t.completeResponseLocked(stream, false), false
	}
	return false, false
}

func (t *http2MetadataTimeline) completeRequestLocked(
	stream *http2StreamState,
	truncated bool,
) bool {
	if stream == nil || stream.requestEnded {
		return false
	}
	body := stream.requestBody.Finish()
	if body != nil {
		body.Truncated = body.Truncated || truncated
		stream.value.RequestBody = body
	}
	if stream.requestBody != nil {
		stream.requestBody.Clear()
	}
	stream.requestBody = nil
	stream.requestEnded = true
	stream.value.RequestCompletedAfterMilliseconds = elapsedMilliseconds(t.startedAt)
	t.updateStreamStateLocked(stream)
	return true
}

func (t *http2MetadataTimeline) completeResponseLocked(
	stream *http2StreamState,
	truncated bool,
) bool {
	if stream == nil || stream.responseEnded {
		return false
	}
	body := stream.responseBody.Finish()
	if body != nil {
		body.Truncated = body.Truncated || truncated
		stream.value.ResponseBody = body
	}
	if stream.responseBody != nil {
		stream.responseBody.Clear()
	}
	stream.responseBody = nil
	stream.responseEnded = true
	stream.value.ResponseCompletedAfterMilliseconds = elapsedMilliseconds(t.startedAt)
	t.updateStreamStateLocked(stream)
	return true
}

func (t *http2MetadataTimeline) updateStreamStateLocked(stream *http2StreamState) {
	if stream == nil || stream.value.State == "reset" {
		return
	}
	switch {
	case stream.requestEnded && stream.responseEnded:
		stream.value.State = "closed"
	case stream.requestEnded:
		stream.value.State = "request-ended"
	case stream.responseEnded:
		stream.value.State = "response-ended"
	default:
		stream.value.State = "open"
	}
}

func (t *http2MetadataTimeline) resetStreamLocked(streamID uint32, code uint32) bool {
	if _, ignored := t.ignored[streamID]; ignored {
		delete(t.ignored, streamID)
		return false
	}
	stream := t.streams[streamID]
	if stream == nil {
		return false
	}
	if stream.requestHeaders && !stream.requestEnded {
		t.completeRequestLocked(stream, true)
	}
	if stream.responseHeaders && !stream.responseEnded {
		t.completeResponseLocked(stream, true)
	}
	stream.value.State = "reset"
	stream.value.ResetCode = code
	return true
}

func (t *http2MetadataTimeline) FinishRequest() {
	t.finish(&t.client)
}

func (t *http2MetadataTimeline) FinishResponse() {
	t.finish(&t.server)
}

func (t *http2MetadataTimeline) finish(direction *http2DirectionState) {
	if t == nil || direction == nil {
		return
	}
	t.mu.Lock()
	if t.stopped || direction.stopped {
		t.mu.Unlock()
		return
	}
	if len(direction.buffer) != 0 || direction.pending != nil ||
		direction.fromClient && direction.preface != len(http2ClientPreface) {
		changed := t.failClosedLocked()
		if changed {
			t.publishLocked()
			return
		}
		t.mu.Unlock()
		return
	}
	direction.stopped = true
	changed := false
	for _, stream := range t.streams {
		if direction.fromClient {
			if stream.requestHeaders && !stream.requestEnded {
				changed = t.completeRequestLocked(stream, true) || changed
				t.truncated = true
			}
		} else if stream.responseHeaders && !stream.responseEnded {
			changed = t.completeResponseLocked(stream, true) || changed
			t.truncated = true
		}
	}
	if t.client.stopped && t.server.stopped {
		t.stopped = true
	}
	if changed {
		t.publishLocked()
		return
	}
	t.mu.Unlock()
}

func (t *http2MetadataTimeline) Abort() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.clearLocked()
	t.streams = nil
	t.ignored = nil
	t.order = nil
	t.goAway = nil
	t.stopped = true
	t.client.stopped = true
	t.server.stopped = true
	t.mu.Unlock()
}

func (t *http2MetadataTimeline) failClosedLocked() bool {
	changed := !t.truncated
	t.truncated = true
	for _, stream := range t.streams {
		if stream.requestHeaders && !stream.requestEnded {
			changed = t.completeRequestLocked(stream, true) || changed
		}
		if stream.responseHeaders && !stream.responseEnded {
			changed = t.completeResponseLocked(stream, true) || changed
		}
	}
	t.clearDirectionsLocked()
	t.stopped = true
	t.client.stopped = true
	t.server.stopped = true
	return changed
}

func (t *http2MetadataTimeline) clearLocked() {
	for _, stream := range t.streams {
		if stream.requestBody != nil {
			stream.requestBody.Clear()
		}
		if stream.responseBody != nil {
			stream.responseBody.Clear()
		}
		stream.requestBody = nil
		stream.responseBody = nil
		stream.value.RequestBody = nil
		stream.value.ResponseBody = nil
	}
	t.clearDirectionsLocked()
}

func (t *http2MetadataTimeline) clearDirectionsLocked() {
	clearHTTP2Direction(&t.client)
	clearHTTP2Direction(&t.server)
}

func clearHTTP2Direction(direction *http2DirectionState) {
	if direction == nil {
		return
	}
	clear(direction.buffer)
	direction.buffer = nil
	if direction.pending != nil {
		clear(direction.pending.block)
		direction.pending.block = nil
	}
	direction.pending = nil
	direction.collector.clear()
}
