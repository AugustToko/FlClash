package inspectionruntime

import (
	"encoding/base64"
	"mime"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MaxCaptureRedactedHeaderNames = 32
	MaxCaptureHeaderValueBytes    = 4096
	MaxCaptureBodyBytes           = 64 * 1024
	DefaultCaptureBodyBytes       = 16 * 1024
	MaxConnectionCaptureBodyBytes = 256 * 1024
	MaxSessionCaptureBodyBytes    = 8 * 1024 * 1024
)

const (
	CaptureBodyNone = "none"
	CaptureBodyText = "text"
	CaptureBodyAll  = "all"
)

// CapturePolicy is an explicitly authorized, per-capture-session data policy.
// Zero values are metadata-only. Sensitive header values remain redacted unless
// SensitiveHeaderValues is separately enabled.
type CapturePolicy struct {
	HeaderValues          bool     `json:"headerValues,omitempty"`
	SensitiveHeaderValues bool     `json:"sensitiveHeaderValues,omitempty"`
	RedactedHeaderNames   []string `json:"redactedHeaderNames,omitempty"`
	BodyMode              string   `json:"bodyMode,omitempty"`
	MaxBodyBytes          int      `json:"maxBodyBytes,omitempty"`
}

func (p CapturePolicy) Normalize() CapturePolicy {
	result := CapturePolicy{
		HeaderValues:          p.HeaderValues,
		SensitiveHeaderValues: p.HeaderValues && p.SensitiveHeaderValues,
	}
	seen := make(map[string]struct{}, len(p.RedactedHeaderNames))
	for _, raw := range p.RedactedHeaderNames {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" || len(name) > maxHTTPMetadataHeaderNameBytes ||
			!validHTTPToken([]byte(name)) {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result.RedactedHeaderNames = append(result.RedactedHeaderNames, name)
		if len(result.RedactedHeaderNames) >= MaxCaptureRedactedHeaderNames {
			break
		}
	}
	sort.Strings(result.RedactedHeaderNames)
	switch p.BodyMode {
	case CaptureBodyText, CaptureBodyAll:
		result.BodyMode = p.BodyMode
		result.MaxBodyBytes = p.MaxBodyBytes
		if result.MaxBodyBytes <= 0 {
			result.MaxBodyBytes = DefaultCaptureBodyBytes
		}
		if result.MaxBodyBytes > MaxCaptureBodyBytes {
			result.MaxBodyBytes = MaxCaptureBodyBytes
		}
	default:
		result.BodyMode = CaptureBodyNone
	}
	return result
}

func (p CapturePolicy) MetadataOnly() bool {
	p = p.Normalize()
	return !p.HeaderValues && p.BodyMode == CaptureBodyNone
}

func (p CapturePolicy) ConnectionBodyLimit() int {
	p = p.Normalize()
	if p.BodyMode == CaptureBodyNone {
		return 0
	}
	limit := p.MaxBodyBytes * 8
	if limit > MaxConnectionCaptureBodyBytes {
		return MaxConnectionCaptureBodyBytes
	}
	return limit
}

func (p CapturePolicy) SessionBodyLimit() int {
	p = p.Normalize()
	if p.BodyMode == CaptureBodyNone {
		return 0
	}
	return MaxSessionCaptureBodyBytes
}

type HTTPHeaderObservation struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	Redacted  bool   `json:"redacted,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type HTTPBodyObservation struct {
	Kind            string `json:"kind"`
	ContentType     string `json:"contentType,omitempty"`
	ContentEncoding string `json:"contentEncoding,omitempty"`
	Encoding        string `json:"encoding,omitempty"`
	Text            string `json:"text,omitempty"`
	Base64          string `json:"base64,omitempty"`
	CapturedBytes   int    `json:"capturedBytes"`
	ObservedBytes   uint64 `json:"observedBytes"`
	Truncated       bool   `json:"truncated,omitempty"`
	OmittedReason   string `json:"omittedReason,omitempty"`
}

func cloneHTTPHeaderObservations(values []HTTPHeaderObservation) []HTTPHeaderObservation {
	if len(values) == 0 {
		return nil
	}
	return append([]HTTPHeaderObservation(nil), values...)
}

func cloneHTTPBodyObservation(value *HTTPBodyObservation) *HTTPBodyObservation {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func sensitiveHTTPHeaderName(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie",
		"x-api-key", "api-key", "x-auth-token", "x-csrf-token",
		"x-xsrf-token", "www-authenticate", "proxy-authenticate":
		return true
	}
	return strings.Contains(name, "token") || strings.Contains(name, "secret") ||
		strings.Contains(name, "credential") || strings.Contains(name, "session")
}

func policyRedactsHTTPHeader(policy CapturePolicy, name string) bool {
	if sensitiveHTTPHeaderName(name) && !policy.SensitiveHeaderValues {
		return true
	}
	name = strings.ToLower(name)
	for _, configured := range policy.RedactedHeaderNames {
		if configured == name {
			return true
		}
	}
	return false
}

func boundedHTTPHeaderValue(value string) (string, bool) {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= MaxCaptureHeaderValueBytes {
		return value, false
	}
	value = value[:MaxCaptureHeaderValueBytes]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return value, true
}

func captureHTTP1HeaderValues(
	data []byte,
	complete bool,
	policy CapturePolicy,
) ([]HTTPHeaderObservation, bool) {
	policy = policy.Normalize()
	if !policy.HeaderValues {
		return nil, false
	}
	lines, valid := metadataHeaderLines(data, complete)
	if !valid || len(lines) == 0 {
		return nil, true
	}
	return captureRawHTTPHeaderValues(lines[1:], policy)
}

func captureRawHTTPHeaderValues(
	lines [][]byte,
	policy CapturePolicy,
) ([]HTTPHeaderObservation, bool) {
	values := make([]HTTPHeaderObservation, 0, min(len(lines), maxHTTPMetadataHeaderNames))
	truncated := false
	for _, line := range lines {
		if len(values) >= maxHTTPMetadataHeaderNames {
			truncated = true
			break
		}
		colon := strings.IndexByte(string(line), ':')
		if colon <= 0 {
			truncated = true
			continue
		}
		name := strings.ToLower(string(line[:colon]))
		if !validHTTPToken([]byte(name)) {
			truncated = true
			continue
		}
		field := HTTPHeaderObservation{Name: name}
		if policyRedactsHTTPHeader(policy, name) {
			field.Redacted = true
		} else {
			field.Value, field.Truncated = boundedHTTPHeaderValue(
				trimHTTPOptionalWhitespace(string(line[colon+1:])),
			)
		}
		values = append(values, field)
	}
	return values, truncated
}

type bodyCaptureAccumulator struct {
	policy          CapturePolicy
	contentType     string
	contentEncoding string
	reserve         func(int) int
	data            []byte
	observed        uint64
	omittedReason   string
	truncated       bool
}

func newBodyCaptureAccumulator(
	policy CapturePolicy,
	contentType string,
	contentEncoding string,
	reserve func(int) int,
) *bodyCaptureAccumulator {
	policy = policy.Normalize()
	if policy.BodyMode == CaptureBodyNone {
		return nil
	}
	kind := classifyHTTPBodyKind(contentType, contentEncoding, nil)
	omitted := ""
	if policy.BodyMode == CaptureBodyText &&
		(kind == "image" || kind == "binary" || kind == "multipart") {
		omitted = "type-not-authorized"
	}
	return &bodyCaptureAccumulator{
		policy:          policy,
		contentType:     boundedHTTPContentMetadata(contentType),
		contentEncoding: boundedHTTPContentMetadata(contentEncoding),
		reserve:         reserve,
		data:            make([]byte, 0, min(policy.MaxBodyBytes, 4096)),
		omittedReason:   omitted,
	}
}

func (a *bodyCaptureAccumulator) Observe(data []byte) {
	if a == nil || len(data) == 0 {
		return
	}
	a.observed += uint64(len(data))
	if a.omittedReason != "" || len(a.data) >= a.policy.MaxBodyBytes {
		a.truncated = true
		return
	}
	allowed := a.policy.MaxBodyBytes - len(a.data)
	if allowed > len(data) {
		allowed = len(data)
	}
	if a.reserve != nil {
		allowed = a.reserve(allowed)
	}
	if allowed > 0 {
		a.data = append(a.data, data[:allowed]...)
	}
	if allowed < len(data) {
		a.truncated = true
		if allowed == 0 && a.omittedReason == "" {
			a.omittedReason = "capture-budget-exhausted"
		}
	}
}

func (a *bodyCaptureAccumulator) Clear() {
	if a == nil {
		return
	}
	clear(a.data)
	a.data = nil
}

func (a *bodyCaptureAccumulator) Finish() *HTTPBodyObservation {
	if a == nil || (a.observed == 0 && len(a.data) == 0) {
		return nil
	}
	kind := classifyHTTPBodyKind(a.contentType, a.contentEncoding, a.data)
	result := &HTTPBodyObservation{
		Kind:            kind,
		ContentType:     a.contentType,
		ContentEncoding: a.contentEncoding,
		CapturedBytes:   len(a.data),
		ObservedBytes:   a.observed,
		Truncated:       a.truncated || uint64(len(a.data)) < a.observed,
		OmittedReason:   a.omittedReason,
	}
	if len(a.data) == 0 {
		return result
	}
	if bodyKindUsesText(kind) && utf8.Valid(a.data) {
		result.Encoding = "utf8"
		result.Text = string(a.data)
	} else {
		result.Encoding = "base64"
		result.Base64 = base64.StdEncoding.EncodeToString(a.data)
	}
	return result
}

func boundedHTTPContentMetadata(value string) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "\uFFFD"))
	if len(value) > 256 {
		value = value[:256]
		for !utf8.ValidString(value) && len(value) > 0 {
			value = value[:len(value)-1]
		}
	}
	return value
}

func classifyHTTPBodyKind(
	contentType string,
	contentEncoding string,
	data []byte,
) string {
	if encoding := strings.ToLower(strings.TrimSpace(contentEncoding)); encoding != "" && encoding != "identity" {
		return "binary"
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	mediaType = strings.ToLower(mediaType)
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return "json"
	case mediaType == "application/x-www-form-urlencoded":
		return "form"
	case mediaType == "multipart/form-data":
		return "multipart"
	case strings.HasPrefix(mediaType, "image/"):
		return "image"
	case strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/xml" || strings.HasSuffix(mediaType, "+xml") ||
		mediaType == "application/javascript" || mediaType == "application/graphql":
		return "text"
	case mediaType != "":
		return "binary"
	}
	if len(data) == 0 {
		return "binary"
	}
	detected := http.DetectContentType(data)
	if strings.HasPrefix(detected, "text/") || strings.Contains(detected, "json") ||
		strings.Contains(detected, "xml") {
		return "text"
	}
	if strings.HasPrefix(detected, "image/") {
		return "image"
	}
	return "binary"
}

func bodyKindUsesText(kind string) bool {
	switch kind {
	case "json", "form", "text":
		return true
	default:
		return false
	}
}
