package inspectionruntime

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/http2/hpack"
)

const (
	maxHTTP2Streams             = 32
	maxHTTP2FramePayloadBytes   = 1024 * 1024
	maxHTTP2HeaderBlockBytes    = 128 * 1024
	maxHTTP2DecodedHeaderBytes  = 128 * 1024
	maxHTTP2DecodedHeaderFields = 128
	maxHTTP2DynamicTableBytes   = 64 * 1024
)

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	http2FrameData         = 0x0
	http2FrameHeaders      = 0x1
	http2FramePriority     = 0x2
	http2FrameRSTStream    = 0x3
	http2FrameSettings     = 0x4
	http2FramePushPromise  = 0x5
	http2FramePing         = 0x6
	http2FrameGoAway       = 0x7
	http2FrameWindowUpdate = 0x8
	http2FrameContinuation = 0x9
)

const (
	http2FlagEndStream  = 0x1
	http2FlagAck        = 0x1
	http2FlagEndHeaders = 0x4
	http2FlagPadded     = 0x8
	http2FlagPriority   = 0x20
)

// HTTP2StreamObservation is one request/response exchange on a multiplexed
// HTTP/2 connection. StreamID is the wire stream identifier; Sequence is the
// stable order in which the observer first saw request headers.
type HTTP2StreamObservation struct {
	Sequence                           int                      `json:"sequence"`
	StreamID                           uint32                   `json:"streamId"`
	State                              string                   `json:"state"`
	RequestObservedAfterMilliseconds   int64                    `json:"requestObservedAfterMilliseconds"`
	RequestCompletedAfterMilliseconds  int64                    `json:"requestCompletedAfterMilliseconds,omitempty"`
	ResponseCompletedAfterMilliseconds int64                    `json:"responseCompletedAfterMilliseconds,omitempty"`
	ResetCode                          uint32                   `json:"resetCode,omitempty"`
	Request                            *HTTPRequestObservation  `json:"request,omitempty"`
	RequestBody                        *HTTPBodyObservation     `json:"requestBody,omitempty"`
	Response                           *HTTPResponseObservation `json:"response,omitempty"`
	ResponseBody                       *HTTPBodyObservation     `json:"responseBody,omitempty"`
}

type HTTP2GoAwayObservation struct {
	LastStreamID              uint32 `json:"lastStreamId"`
	ErrorCode                 uint32 `json:"errorCode"`
	ObservedAfterMilliseconds int64  `json:"observedAfterMilliseconds"`
}

func cloneHTTP2StreamObservations(values []HTTP2StreamObservation) []HTTP2StreamObservation {
	if len(values) == 0 {
		return nil
	}
	result := make([]HTTP2StreamObservation, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Request = cloneHTTPRequestObservation(value.Request)
		result[index].RequestBody = cloneHTTPBodyObservation(value.RequestBody)
		result[index].Response = cloneHTTPResponseObservation(value.Response)
		result[index].ResponseBody = cloneHTTPBodyObservation(value.ResponseBody)
	}
	return result
}

func cloneHTTP2GoAwayObservation(value *HTTP2GoAwayObservation) *HTTP2GoAwayObservation {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

type http2HeaderCollector struct {
	policy          CapturePolicy
	pseudo          map[string]string
	headerNames     []string
	headerNameSeen  map[string]struct{}
	headers         []HTTPHeaderObservation
	contentType     string
	contentEncoding string
	host            string
	totalBytes      int
	fieldCount      int
	regularStarted  bool
	namesTruncated  bool
	valuesTruncated bool
	invalid         bool
}

func (c *http2HeaderCollector) reset(policy CapturePolicy) {
	c.clear()
	c.policy = policy.Normalize()
	c.pseudo = make(map[string]string, 6)
	c.headerNameSeen = make(map[string]struct{}, 16)
	c.headerNames = make([]string, 0, 16)
	if c.policy.HeaderValues {
		c.headers = make([]HTTPHeaderObservation, 0, 16)
	}
}

func (c *http2HeaderCollector) add(field hpack.HeaderField) {
	if c.invalid {
		return
	}
	c.fieldCount++
	c.totalBytes += len(field.Name) + len(field.Value)
	if c.fieldCount > maxHTTP2DecodedHeaderFields ||
		c.totalBytes > maxHTTP2DecodedHeaderBytes ||
		len(field.Name) == 0 || len(field.Name) > maxHTTPMetadataHeaderNameBytes ||
		!utf8.ValidString(field.Name) || !utf8.ValidString(field.Value) {
		c.invalid = true
		return
	}
	name := field.Name
	if name != strings.ToLower(name) {
		c.invalid = true
		return
	}
	if strings.HasPrefix(name, ":") {
		if c.regularStarted || len(name) == 1 {
			c.invalid = true
			return
		}
		if _, exists := c.pseudo[name]; exists {
			c.invalid = true
			return
		}
		switch name {
		case ":method", ":scheme", ":authority", ":path", ":status", ":protocol":
			c.pseudo[name] = field.Value
		default:
			c.invalid = true
		}
		return
	}
	c.regularStarted = true
	if !validHTTPToken([]byte(name)) || !validHTTPFieldValue([]byte(field.Value)) {
		c.invalid = true
		return
	}
	switch name {
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
		c.invalid = true
		return
	case "te":
		if !strings.EqualFold(trimHTTPOptionalWhitespace(field.Value), "trailers") {
			c.invalid = true
			return
		}
	}
	if _, exists := c.headerNameSeen[name]; !exists {
		c.headerNameSeen[name] = struct{}{}
		if len(c.headerNames) < maxHTTPMetadataHeaderNames {
			c.headerNames = append(c.headerNames, name)
		} else {
			c.namesTruncated = true
		}
	}
	switch name {
	case "content-type":
		if c.contentType == "" {
			c.contentType = field.Value
		}
	case "content-encoding":
		if c.contentEncoding == "" {
			c.contentEncoding = field.Value
		}
	case "host":
		if c.host != "" {
			c.invalid = true
			return
		}
		c.host = field.Value
	}
	if !c.policy.HeaderValues {
		return
	}
	if len(c.headers) >= maxHTTPMetadataHeaderNames {
		c.valuesTruncated = true
		return
	}
	value := HTTPHeaderObservation{Name: name}
	if policyRedactsHTTPHeader(c.policy, name) {
		value.Redacted = true
	} else {
		value.Value, value.Truncated = boundedHTTPHeaderValue(field.Value)
		c.valuesTruncated = c.valuesTruncated || value.Truncated
	}
	c.headers = append(c.headers, value)
}

func (c *http2HeaderCollector) clear() {
	for key := range c.pseudo {
		c.pseudo[key] = ""
	}
	for index := range c.headers {
		c.headers[index].Value = ""
	}
	c.policy = CapturePolicy{}
	c.pseudo = nil
	c.headerNames = nil
	c.headerNameSeen = nil
	c.headers = nil
	c.contentType = ""
	c.contentEncoding = ""
	c.host = ""
	c.totalBytes = 0
	c.fieldCount = 0
	c.regularStarted = false
	c.namesTruncated = false
	c.valuesTruncated = false
	c.invalid = false
}

func parseHTTP2RequestObservation(
	collector *http2HeaderCollector,
	expectedHost string,
) (*HTTPRequestObservation, bool) {
	if collector == nil || collector.invalid {
		return nil, false
	}
	for name := range collector.pseudo {
		switch name {
		case ":method", ":scheme", ":authority", ":path", ":protocol":
		default:
			return nil, false
		}
	}
	method := collector.pseudo[":method"]
	if method == "" || len(method) > maxHTTPMetadataMethodBytes ||
		!validHTTPToken([]byte(method)) {
		return nil, false
	}
	authority := collector.pseudo[":authority"]
	if authority == "" {
		authority = collector.host
	} else if collector.host != "" && !strings.EqualFold(authority, collector.host) {
		return nil, false
	}
	if authority == "" {
		return nil, false
	}
	host, port, valid := parseHTTPAuthority(authority, 443)
	if !valid || host != expectedHost || port != 443 {
		return nil, false
	}
	var rawTarget string
	if method == "CONNECT" {
		if collector.pseudo[":protocol"] == "" {
			if collector.pseudo[":scheme"] != "" || collector.pseudo[":path"] != "" {
				return nil, false
			}
		} else if collector.pseudo[":scheme"] != "https" || collector.pseudo[":path"] == "" {
			return nil, false
		}
		rawTarget = authority
	} else {
		if collector.pseudo[":scheme"] != "https" || collector.pseudo[":path"] == "" ||
			collector.pseudo[":protocol"] != "" {
			return nil, false
		}
		rawTarget = collector.pseudo[":path"]
	}
	target, targetTruncated, valid := sanitizeHTTPRequestTarget(method, []byte(rawTarget))
	if !valid {
		return nil, false
	}
	return &HTTPRequestObservation{
		Method:                method,
		Target:                target,
		Version:               "HTTP/2",
		Host:                  host,
		HeaderNames:           append([]string(nil), collector.headerNames...),
		Headers:               cloneHTTPHeaderObservations(collector.headers),
		HeadersComplete:       true,
		TargetTruncated:       targetTruncated,
		HeaderNamesTruncated:  collector.namesTruncated,
		HeaderValuesTruncated: collector.valuesTruncated,
	}, true
}

func parseHTTP2Status(pseudo map[string]string) (int, bool) {
	if len(pseudo) != 1 {
		return 0, false
	}
	value := pseudo[":status"]
	if len(value) != 3 {
		return 0, false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	status, err := strconv.Atoi(value)
	return status, err == nil && status >= 100 && status <= 599
}
