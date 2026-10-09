package inspectionruntime

import (
	"bytes"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxHTTPMetadataBytes            = 32 * 1024
	maxHTTPMetadataHeaderNames      = 64
	maxHTTPMetadataHeaderNameBytes  = 128
	maxHTTPMetadataMethodBytes      = 16
	maxHTTPMetadataTargetBytes      = 512
	maxHTTPMetadataHostBytes        = 253
	maxHTTPInformationalStatusCodes = 8
)

var httpHeaderTerminator = []byte("\r\n\r\n")
var httpLineTerminator = []byte("\r\n")

// HTTPRequestObservation retains bounded request metadata. Header values are
// present only when the capture session explicitly authorized them.
type HTTPRequestObservation struct {
	Method                string                  `json:"method"`
	Target                string                  `json:"target"`
	Version               string                  `json:"version"`
	Host                  string                  `json:"host,omitempty"`
	HeaderNames           []string                `json:"headerNames,omitempty"`
	Headers               []HTTPHeaderObservation `json:"headers,omitempty"`
	HeadersComplete       bool                    `json:"headersComplete"`
	TargetTruncated       bool                    `json:"targetTruncated,omitempty"`
	HostTruncated         bool                    `json:"hostTruncated,omitempty"`
	HeaderNamesTruncated  bool                    `json:"headerNamesTruncated,omitempty"`
	HeaderValuesTruncated bool                    `json:"headerValuesTruncated,omitempty"`
}

// HTTPResponseObservation retains one bounded final response. Informational
// responses are bounded; reason phrases remain intentionally excluded.
type HTTPResponseObservation struct {
	Version                           string                  `json:"version,omitempty"`
	StatusCode                        int                     `json:"statusCode,omitempty"`
	InformationalStatusCodes          []int                   `json:"informationalStatusCodes,omitempty"`
	HeaderNames                       []string                `json:"headerNames,omitempty"`
	Headers                           []HTTPHeaderObservation `json:"headers,omitempty"`
	HeadersComplete                   bool                    `json:"headersComplete"`
	ObservedBytes                     int                     `json:"observedBytes"`
	ObservedAfterMilliseconds         int64                   `json:"observedAfterMilliseconds,omitempty"`
	Truncated                         bool                    `json:"truncated,omitempty"`
	HeaderNamesTruncated              bool                    `json:"headerNamesTruncated,omitempty"`
	HeaderValuesTruncated             bool                    `json:"headerValuesTruncated,omitempty"`
	InformationalStatusCodesTruncated bool                    `json:"informationalStatusCodesTruncated,omitempty"`
}

type httpRequestMetadataObserver struct {
	buffer []byte
	done   bool
}

func newHTTPRequestMetadataObserver() *httpRequestMetadataObserver {
	return &httpRequestMetadataObserver{buffer: make([]byte, 0, 1024)}
}

func (o *httpRequestMetadataObserver) Observe(data []byte) (*HTTPRequestObservation, bool) {
	if o == nil || o.done {
		return nil, true
	}
	remaining := maxHTTPMetadataBytes - len(o.buffer)
	if remaining <= 0 {
		return o.finish(false, true)
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	o.buffer = append(o.buffer, data...)
	if end := bytes.Index(o.buffer, httpHeaderTerminator); end >= 0 {
		return o.finishBlock(o.buffer[:end+len(httpHeaderTerminator)], true, false)
	}
	if len(o.buffer) >= maxHTTPMetadataBytes {
		return o.finish(false, true)
	}
	return nil, false
}

func (o *httpRequestMetadataObserver) Finish() (*HTTPRequestObservation, bool) {
	if o == nil || o.done {
		return nil, true
	}
	return o.finish(false, len(o.buffer) >= maxHTTPMetadataBytes)
}

func (o *httpRequestMetadataObserver) Abort() {
	if o == nil || o.done {
		return
	}
	o.done = true
	clearHTTPMetadataBuffer(o.buffer)
	o.buffer = nil
}

func (o *httpRequestMetadataObserver) finish(complete, truncated bool) (*HTTPRequestObservation, bool) {
	return o.finishBlock(o.buffer, complete, truncated)
}

func (o *httpRequestMetadataObserver) finishBlock(data []byte, complete, truncated bool) (*HTTPRequestObservation, bool) {
	o.done = true
	value, valid := parseHTTPRequestMetadata(data, complete, truncated)
	clearHTTPMetadataBuffer(o.buffer)
	o.buffer = nil
	if !valid {
		return nil, true
	}
	return value, true
}

type httpResponseMetadataObserver struct {
	buffer                 []byte
	totalObserved          int
	consumedHeaders        int
	informational          []int
	informationalTruncated bool
	startedAt              time.Time
	done                   bool
}

func newHTTPResponseMetadataObserver(startedAt time.Time) *httpResponseMetadataObserver {
	return &httpResponseMetadataObserver{
		buffer:    make([]byte, 0, 1024),
		startedAt: startedAt,
	}
}

func (o *httpResponseMetadataObserver) Observe(data []byte) (*HTTPResponseObservation, bool) {
	if o == nil || o.done {
		return nil, true
	}
	remaining := maxHTTPMetadataBytes - o.totalObserved
	if remaining <= 0 {
		return o.finishPartial(true)
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	o.totalObserved += len(data)
	o.buffer = append(o.buffer, data...)
	for {
		end := bytes.Index(o.buffer, httpHeaderTerminator)
		if end < 0 {
			break
		}
		blockLength := end + len(httpHeaderTerminator)
		value, valid := parseHTTPResponseMetadata(o.buffer[:blockLength], true, false)
		if !valid {
			return o.finishInvalid()
		}
		o.consumedHeaders += blockLength
		if value.StatusCode >= 100 && value.StatusCode < 200 && value.StatusCode != 101 {
			if len(o.informational) < maxHTTPInformationalStatusCodes {
				o.informational = append(o.informational, value.StatusCode)
			} else {
				o.informationalTruncated = true
			}
			clear(o.buffer[:blockLength])
			o.buffer = append(o.buffer[:0], o.buffer[blockLength:]...)
			continue
		}
		value.InformationalStatusCodes = append([]int(nil), o.informational...)
		value.InformationalStatusCodesTruncated = o.informationalTruncated
		value.ObservedBytes = o.consumedHeaders
		value.ObservedAfterMilliseconds = elapsedMilliseconds(o.startedAt)
		return o.finishValue(value)
	}
	if o.totalObserved >= maxHTTPMetadataBytes {
		return o.finishPartial(true)
	}
	return nil, false
}

func (o *httpResponseMetadataObserver) Finish() (*HTTPResponseObservation, bool) {
	if o == nil || o.done {
		return nil, true
	}
	return o.finishPartial(false)
}

func (o *httpResponseMetadataObserver) Abort() {
	if o == nil || o.done {
		return
	}
	o.done = true
	clearHTTPMetadataBuffer(o.buffer)
	o.buffer = nil
}

func (o *httpResponseMetadataObserver) finishPartial(boundReached bool) (*HTTPResponseObservation, bool) {
	value, valid := parseHTTPResponseMetadata(o.buffer, false, true)
	if !valid {
		if len(o.informational) == 0 {
			return o.finishInvalid()
		}
		value = &HTTPResponseObservation{}
	}
	value.InformationalStatusCodes = append([]int(nil), o.informational...)
	value.InformationalStatusCodesTruncated = o.informationalTruncated
	value.ObservedBytes = o.totalObserved
	value.ObservedAfterMilliseconds = elapsedMilliseconds(o.startedAt)
	value.Truncated = true
	if boundReached {
		value.HeaderNamesTruncated = true
	}
	return o.finishValue(value)
}

func (o *httpResponseMetadataObserver) finishValue(value *HTTPResponseObservation) (*HTTPResponseObservation, bool) {
	o.done = true
	clearHTTPMetadataBuffer(o.buffer)
	o.buffer = nil
	return value, true
}

func (o *httpResponseMetadataObserver) finishInvalid() (*HTTPResponseObservation, bool) {
	o.done = true
	clearHTTPMetadataBuffer(o.buffer)
	o.buffer = nil
	return nil, true
}

func elapsedMilliseconds(startedAt time.Time) int64 {
	if startedAt.IsZero() {
		return 0
	}
	value := time.Since(startedAt).Milliseconds()
	if value < 0 {
		return 0
	}
	return value
}

func parseHTTPRequestMetadata(data []byte, complete, truncated bool) (*HTTPRequestObservation, bool) {
	lines, valid := metadataHeaderLines(data, complete)
	if !valid || len(lines) == 0 {
		return nil, false
	}
	method, target, version, targetTruncated, valid := parseHTTPRequestLine(lines[0])
	if !valid {
		return nil, false
	}
	names, namesTruncated, host, hostTruncated, valid := parseHTTPHeaderNames(lines[1:], true)
	if !valid {
		return nil, false
	}
	return &HTTPRequestObservation{
		Method: method, Target: target, Version: version, Host: host,
		HeaderNames: names, HeadersComplete: complete,
		TargetTruncated:      targetTruncated,
		HostTruncated:        hostTruncated,
		HeaderNamesTruncated: namesTruncated || truncated,
	}, true
}

func parseHTTPResponseMetadata(data []byte, complete, truncated bool) (*HTTPResponseObservation, bool) {
	lines, valid := metadataHeaderLines(data, complete)
	if !valid || len(lines) == 0 {
		return nil, false
	}
	version, statusCode, valid := parseHTTPStatusLine(lines[0])
	if !valid {
		return nil, false
	}
	names, namesTruncated, _, _, valid := parseHTTPHeaderNames(lines[1:], false)
	if !valid {
		return nil, false
	}
	return &HTTPResponseObservation{
		Version: version, StatusCode: statusCode, HeaderNames: names,
		HeadersComplete: complete, Truncated: truncated,
		HeaderNamesTruncated: namesTruncated || truncated,
	}, true
}

func metadataHeaderLines(data []byte, complete bool) ([][]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	limit := len(data)
	if complete {
		if !bytes.HasSuffix(data, httpHeaderTerminator) {
			return nil, false
		}
		limit -= len(httpHeaderTerminator)
	} else {
		last := bytes.LastIndex(data, httpLineTerminator)
		if last < 0 {
			return nil, false
		}
		limit = last
	}
	for index := 0; index < limit; index++ {
		switch data[index] {
		case '\n':
			if index == 0 || data[index-1] != '\r' {
				return nil, false
			}
		case '\r':
			if index+1 >= len(data) || data[index+1] != '\n' {
				return nil, false
			}
		}
	}
	content := data[:limit]
	if len(content) == 0 {
		return nil, false
	}
	return bytes.Split(content, httpLineTerminator), true
}

func parseHTTPRequestLine(line []byte) (method, target, version string, targetTruncated, valid bool) {
	parts := bytes.Split(line, []byte{' '})
	if len(parts) != 3 || !validHTTPToken(parts[0]) || len(parts[0]) > maxHTTPMetadataMethodBytes {
		return "", "", "", false, false
	}
	version = string(parts[2])
	if version != "HTTP/1.0" && version != "HTTP/1.1" {
		return "", "", "", false, false
	}
	method = string(parts[0])
	target, targetTruncated, valid = sanitizeHTTPRequestTarget(method, parts[1])
	return method, target, version, targetTruncated, valid
}

func parseHTTPStatusLine(line []byte) (version string, statusCode int, valid bool) {
	parts := bytes.SplitN(line, []byte{' '}, 3)
	if len(parts) < 2 {
		return "", 0, false
	}
	version = string(parts[0])
	if version != "HTTP/1.0" && version != "HTTP/1.1" || len(parts[1]) != 3 {
		return "", 0, false
	}
	for _, value := range parts[1] {
		if value < '0' || value > '9' {
			return "", 0, false
		}
	}
	statusCode, _ = strconv.Atoi(string(parts[1]))
	if statusCode < 100 || statusCode > 599 {
		return "", 0, false
	}
	if len(parts) == 3 && !validHTTPFieldValue(parts[2]) {
		return "", 0, false
	}
	return version, statusCode, true
}

func parseHTTPHeaderNames(lines [][]byte, retainHost bool) (names []string, namesTruncated bool, host string, hostTruncated bool, valid bool) {
	seen := make(map[string]struct{}, min(len(lines), maxHTTPMetadataHeaderNames))
	hostSeen := false
	for _, line := range lines {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			return nil, false, "", false, false
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validHTTPToken(line[:colon]) || !validHTTPFieldValue(line[colon+1:]) {
			return nil, false, "", false, false
		}
		rawName := line[:colon]
		if len(rawName) > maxHTTPMetadataHeaderNameBytes {
			rawName = rawName[:maxHTTPMetadataHeaderNameBytes]
			namesTruncated = true
		}
		name := strings.ToLower(string(rawName))
		if _, exists := seen[name]; !exists {
			seen[name] = struct{}{}
			if len(names) < maxHTTPMetadataHeaderNames {
				names = append(names, name)
			} else {
				namesTruncated = true
			}
		}
		if retainHost && name == "host" {
			if hostSeen {
				return nil, false, "", false, false
			}
			hostSeen = true
			host, hostTruncated, valid = normalizeHTTPMetadataHost(line[colon+1:])
			if !valid {
				return nil, false, "", false, false
			}
		}
	}
	return names, namesTruncated, host, hostTruncated, true
}

func sanitizeHTTPRequestTarget(method string, raw []byte) (string, bool, bool) {
	if len(raw) == 0 || !utf8.Valid(raw) || !validHTTPFieldValue(raw) {
		return "", false, false
	}
	value := string(raw)
	var sanitized string
	switch {
	case value == "*":
		sanitized = "*"
	case strings.HasPrefix(value, "/"):
		if cut := strings.IndexAny(value, "?#"); cut >= 0 {
			value = value[:cut]
		}
		if value == "" {
			value = "/"
		}
		sanitized = value
	case method == "CONNECT":
		host, _, err := net.SplitHostPort(value)
		if err != nil || strings.Contains(host, "@") {
			return "", false, false
		}
		sanitized = strings.ToLower(strings.TrimSuffix(host, "."))
	default:
		parsed, err := url.ParseRequestURI(value)
		if err != nil || !parsed.IsAbs() || parsed.User != nil {
			return "", false, false
		}
		sanitized = parsed.EscapedPath()
		if sanitized == "" {
			sanitized = "/"
		}
	}
	bounded, wasTruncated := boundedHTTPMetadataText(sanitized, maxHTTPMetadataTargetBytes)
	if bounded == "" {
		return "", false, false
	}
	return bounded, wasTruncated, true
}

func normalizeHTTPMetadataHost(raw []byte) (string, bool, bool) {
	value := strings.TrimSpace(string(raw))
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "@/?#\\") {
		return "", false, false
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if port == "" {
			return "", false, false
		}
		value = host
	} else if strings.Contains(value, ":") {
		return "", false, false
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) > maxHTTPMetadataHostBytes {
		return "", true, true
	}
	if len(value) == 0 || !strings.Contains(value, ".") {
		return "", false, false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", false, false
			}
		}
	}
	return value, false, true
}

func boundedHTTPMetadataText(value string, maximum int) (string, bool) {
	if len(value) <= maximum {
		return value, false
	}
	data := []byte(value[:maximum])
	for len(data) > 0 && !utf8.Valid(data) {
		data = data[:len(data)-1]
	}
	return string(data), true
}

func validHTTPToken(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)):
		default:
			return false
		}
	}
	return true
}

func validHTTPFieldValue(value []byte) bool {
	for _, character := range value {
		if character != '\t' && (character < 0x20 || character == 0x7f) {
			return false
		}
	}
	return true
}

func clearHTTPMetadataBuffer(buffer []byte) {
	if cap(buffer) == 0 {
		return
	}
	clear(buffer[:cap(buffer)])
}

type metadataObservingReader struct {
	reader  io.Reader
	observe func([]byte)
	finish  func()
	abort   func()
	once    sync.Once
}

func (r *metadataObservingReader) Read(buffer []byte) (int, error) {
	count, err := r.reader.Read(buffer)
	if count > 0 {
		r.observeSafely(buffer[:count])
	}
	if err != nil {
		r.Finish()
	}
	return count, err
}

func (r *metadataObservingReader) observeSafely(data []byte) {
	if r == nil || r.observe == nil {
		return
	}
	defer func() {
		if recover() == nil {
			return
		}
		if r.abort != nil {
			func() {
				defer func() { _ = recover() }()
				r.abort()
			}()
		}
		r.observe = nil
		r.finish = nil
		r.abort = nil
	}()
	r.observe(data)
}

func (r *metadataObservingReader) Finish() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		defer func() {
			if recover() != nil && r.abort != nil {
				func() {
					defer func() { _ = recover() }()
					r.abort()
				}()
			}
			r.observe = nil
			r.finish = nil
			r.abort = nil
		}()
		if r.finish != nil {
			r.finish()
		}
	})
}
