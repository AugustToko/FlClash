from http2_batch_common import ROOT, replace_once


def patch_http1_metadata() -> None:
    path = ROOT / "core/inspectionruntime/http1_metadata.go"
    replace_once(path,
'''// HTTPRequestObservation retains only bounded request-line metadata and header
// names for one decrypted HTTP/1 transaction. Header values and bodies never
// enter this contract.
type HTTPRequestObservation struct {
\tMethod               string   `json:"method"`
\tTarget               string   `json:"target"`
\tVersion              string   `json:"version"`
\tHost                 string   `json:"host,omitempty"`
\tHeaderNames          []string `json:"headerNames,omitempty"`
\tHeadersComplete      bool     `json:"headersComplete"`
\tTargetTruncated      bool     `json:"targetTruncated,omitempty"`
\tHostTruncated        bool     `json:"hostTruncated,omitempty"`
\tHeaderNamesTruncated bool     `json:"headerNamesTruncated,omitempty"`
}
''',
'''// HTTPRequestObservation retains bounded request metadata. Header values are
// present only when the capture session explicitly authorized them.
type HTTPRequestObservation struct {
\tMethod                string                  `json:"method"`
\tTarget                string                  `json:"target"`
\tVersion               string                  `json:"version"`
\tHost                  string                  `json:"host,omitempty"`
\tHeaderNames           []string                `json:"headerNames,omitempty"`
\tHeaders               []HTTPHeaderObservation `json:"headers,omitempty"`
\tHeadersComplete       bool                    `json:"headersComplete"`
\tTargetTruncated       bool                    `json:"targetTruncated,omitempty"`
\tHostTruncated         bool                    `json:"hostTruncated,omitempty"`
\tHeaderNamesTruncated  bool                    `json:"headerNamesTruncated,omitempty"`
\tHeaderValuesTruncated bool                    `json:"headerValuesTruncated,omitempty"`
}
''')
    replace_once(path,
'''// HTTPResponseObservation retains one final HTTP/1 response status and header
// names. Informational responses are bounded; reason phrases, values and bodies
// are discarded.
type HTTPResponseObservation struct {
\tVersion                           string   `json:"version,omitempty"`
\tStatusCode                        int      `json:"statusCode,omitempty"`
\tInformationalStatusCodes          []int    `json:"informationalStatusCodes,omitempty"`
\tHeaderNames                       []string `json:"headerNames,omitempty"`
\tHeadersComplete                   bool     `json:"headersComplete"`
\tObservedBytes                     int      `json:"observedBytes"`
\tObservedAfterMilliseconds         int64    `json:"observedAfterMilliseconds,omitempty"`
\tTruncated                         bool     `json:"truncated,omitempty"`
\tHeaderNamesTruncated              bool     `json:"headerNamesTruncated,omitempty"`
\tInformationalStatusCodesTruncated bool     `json:"informationalStatusCodesTruncated,omitempty"`
}
''',
'''// HTTPResponseObservation retains one bounded final response. Informational
// responses are bounded; reason phrases remain intentionally excluded.
type HTTPResponseObservation struct {
\tVersion                           string                  `json:"version,omitempty"`
\tStatusCode                        int                     `json:"statusCode,omitempty"`
\tInformationalStatusCodes          []int                   `json:"informationalStatusCodes,omitempty"`
\tHeaderNames                       []string                `json:"headerNames,omitempty"`
\tHeaders                           []HTTPHeaderObservation `json:"headers,omitempty"`
\tHeadersComplete                   bool                    `json:"headersComplete"`
\tObservedBytes                     int                     `json:"observedBytes"`
\tObservedAfterMilliseconds         int64                   `json:"observedAfterMilliseconds,omitempty"`
\tTruncated                         bool                    `json:"truncated,omitempty"`
\tHeaderNamesTruncated              bool                    `json:"headerNamesTruncated,omitempty"`
\tHeaderValuesTruncated             bool                    `json:"headerValuesTruncated,omitempty"`
\tInformationalStatusCodesTruncated bool                    `json:"informationalStatusCodesTruncated,omitempty"`
}
''')


def patch_http1_timeline_contract() -> None:
    path = ROOT / "core/inspectionruntime/http1_timeline.go"
    replacements = [
        ('''type HTTPTransactionObservation struct {
\tSequence                         int                      `json:"sequence"`
\tRequestObservedAfterMilliseconds int64                    `json:"requestObservedAfterMilliseconds"`
\tRequest                          HTTPRequestObservation   `json:"request"`
\tResponse                         *HTTPResponseObservation `json:"response,omitempty"`
}
''', '''type HTTPTransactionObservation struct {
\tSequence                           int                      `json:"sequence"`
\tRequestObservedAfterMilliseconds   int64                    `json:"requestObservedAfterMilliseconds"`
\tRequestCompletedAfterMilliseconds  int64                    `json:"requestCompletedAfterMilliseconds,omitempty"`
\tResponseCompletedAfterMilliseconds int64                    `json:"responseCompletedAfterMilliseconds,omitempty"`
\tRequest                            HTTPRequestObservation   `json:"request"`
\tRequestBody                        *HTTPBodyObservation     `json:"requestBody,omitempty"`
\tResponse                           *HTTPResponseObservation `json:"response,omitempty"`
\tResponseBody                       *HTTPBodyObservation     `json:"responseBody,omitempty"`
}
'''),
        ('''type httpBodyPlan struct {
\tmode              httpBodyMode
\tlength            int64
\tterminalAfterBody bool
}
''', '''type httpBodyPlan struct {
\tmode              httpBodyMode
\tlength            int64
\tterminalAfterBody bool
\tcontentType       string
\tcontentEncoding   string
}
'''),
        ('''type httpFramingHeaders struct {
\tcontentLength     *int64
\ttransferCodings   []string
\tconnectionClose   bool
\tconnectionKeep    bool
\tconnectionUpgrade bool
\tupgradePresent    bool
}
''', '''type httpFramingHeaders struct {
\tcontentLength     *int64
\ttransferCodings   []string
\tcontentType       string
\tcontentEncoding   string
\tconnectionClose   bool
\tconnectionKeep    bool
\tconnectionUpgrade bool
\tupgradePresent    bool
}
'''),
        ('''type httpRequestStreamState struct {
\theader            []byte
\tmode              httpBodyMode
\tremaining         int64
\tchunked           httpChunkedBodySkipper
\tterminalAfterBody bool
\tstopped           bool
}
''', '''type httpRequestStreamState struct {
\theader            []byte
\tmode              httpBodyMode
\tremaining         int64
\tchunked           httpChunkedBodySkipper
\tbody              *bodyCaptureAccumulator
\ttransactionIndex  int
\tterminalAfterBody bool
\tstopped           bool
}
'''),
        ('''type httpResponseStreamState struct {
\theader                 []byte
\tmode                   httpBodyMode
\tremaining              int64
\tchunked                httpChunkedBodySkipper
\tterminalAfterBody      bool
\tinformational          []int
\tinformationalTruncated bool
\tobservedHeaderBytes    int
\tstopped                bool
}
''', '''type httpResponseStreamState struct {
\theader                 []byte
\tmode                   httpBodyMode
\tremaining              int64
\tchunked                httpChunkedBodySkipper
\tbody                   *bodyCaptureAccumulator
\ttransactionIndex       int
\tterminalAfterBody      bool
\tinformational          []int
\tinformationalTruncated bool
\tobservedHeaderBytes    int
\tstopped                bool
}
'''),
        ('''\ttransactions []HTTPTransactionObservation
\ttruncated    bool
\tstopped      bool
\tpublish      func([]HTTPTransactionObservation, bool)
''', '''\ttransactions []HTTPTransactionObservation
\tpolicy       CapturePolicy
\treserveBody  func(int) int
\ttruncated    bool
\tstopped      bool
\tpublish      func([]HTTPTransactionObservation, bool)
'''),
        ('''func newHTTP1MetadataTimeline(
\tstartedAt time.Time,
\texpectedHost string,
\tpublish func([]HTTPTransactionObservation, bool),
) *http1MetadataTimeline {
''', '''func newHTTP1MetadataTimeline(
\tstartedAt time.Time,
\texpectedHost string,
\tpublish func([]HTTPTransactionObservation, bool),
) *http1MetadataTimeline {
\treturn newHTTP1MetadataTimelineWithPolicy(
\t\tstartedAt,
\t\texpectedHost,
\t\tCapturePolicy{},
\t\tnil,
\t\tpublish,
\t)
}

func newHTTP1MetadataTimelineWithPolicy(
\tstartedAt time.Time,
\texpectedHost string,
\tpolicy CapturePolicy,
\treserveBody func(int) int,
\tpublish func([]HTTPTransactionObservation, bool),
) *http1MetadataTimeline {
'''),
        ('''\t\trequest: httpRequestStreamState{
\t\t\theader: make([]byte, 0, 1024),
\t\t},
\t\tresponse: httpResponseStreamState{
\t\t\theader: make([]byte, 0, 1024),
\t\t},
\t\ttransactions: make([]HTTPTransactionObservation, 0, 4),
\t\tpublish:      publish,
''', '''\t\trequest: httpRequestStreamState{
\t\t\theader: make([]byte, 0, 1024), transactionIndex: -1,
\t\t},
\t\tresponse: httpResponseStreamState{
\t\t\theader: make([]byte, 0, 1024), transactionIndex: -1,
\t\t},
\t\ttransactions: make([]HTTPTransactionObservation, 0, 4),
\t\tpolicy:       policy.Normalize(),
\t\treserveBody:  reserveBody,
\t\tpublish:      publish,
'''),
        ('''\t\tresult[index].Request = *cloneHTTPRequestObservation(&value.Request)
\t\tresult[index].Response = cloneHTTPResponseObservation(value.Response)
''', '''\t\tresult[index].Request = *cloneHTTPRequestObservation(&value.Request)
\t\tresult[index].RequestBody = cloneHTTPBodyObservation(value.RequestBody)
\t\tresult[index].Response = cloneHTTPResponseObservation(value.Response)
\t\tresult[index].ResponseBody = cloneHTTPBodyObservation(value.ResponseBody)
'''),
    ]
    text = path.read_text()
    for old, new in replacements:
        if old not in text:
            raise RuntimeError(f"missing HTTP/1 contract replacement: {old[:100]!r}")
        text = text.replace(old, new, 1)
    path.write_text(text)


def patch_http1_framing() -> None:
    path = ROOT / "core/inspectionruntime/http1_timeline.go"
    replace_once(path,
'''\t\tcase "transfer-encoding":
\t\t\tcodings, valid := parseHTTPTransferCodings(value)
\t\t\tif !valid {
\t\t\t\treturn httpFramingHeaders{}, false
\t\t\t}
\t\t\tresult.transferCodings = append(result.transferCodings, codings...)
\t\tcase "connection":
''',
'''\t\tcase "transfer-encoding":
\t\t\tcodings, valid := parseHTTPTransferCodings(value)
\t\t\tif !valid {
\t\t\t\treturn httpFramingHeaders{}, false
\t\t\t}
\t\t\tresult.transferCodings = append(result.transferCodings, codings...)
\t\tcase "content-type":
\t\t\tif result.contentType == "" {
\t\t\t\tresult.contentType = value
\t\t\t}
\t\tcase "content-encoding":
\t\t\tif result.contentEncoding == "" {
\t\t\t\tresult.contentEncoding = value
\t\t\t}
\t\tcase "connection":
''')
    replace_once(path,
'''\tplan, valid := requestBodyPlan(value.Method, value.Version, headers)
\tif !valid {
\t\treturn nil, httpBodyPlan{}, false
\t}
\treturn value, plan, true
''',
'''\tplan, valid := requestBodyPlan(value.Method, value.Version, headers)
\tif !valid {
\t\treturn nil, httpBodyPlan{}, false
\t}
\tplan.contentType = headers.contentType
\tplan.contentEncoding = headers.contentEncoding
\treturn value, plan, true
''')
    replace_once(path,
'''\tif !valid {
\t\treturn nil, httpBodyPlan{}, false, false
\t}
\treturn value, plan, false, true
}

func parseHTTPFramingHeaders''',
'''\tif !valid {
\t\treturn nil, httpBodyPlan{}, false, false
\t}
\tplan.contentType = headers.contentType
\tplan.contentEncoding = headers.contentEncoding
\treturn value, plan, false, true
}

func parseHTTPFramingHeaders''')


def patch_http1_body_helpers() -> None:
    path = ROOT / "core/inspectionruntime/http1_timeline.go"
    replace_once(path,
'''func (t *http1MetadataTimeline) appendRequestLocked(
\trequest *HTTPRequestObservation,
) {
\tif request == nil {
\t\treturn
\t}
\tt.transactions = append(t.transactions, HTTPTransactionObservation{
\t\tSequence:                         len(t.transactions) + 1,
\t\tRequestObservedAfterMilliseconds: elapsedMilliseconds(t.startedAt),
\t\tRequest:                          *cloneHTTPRequestObservation(request),
\t})
}
''',
'''func (t *http1MetadataTimeline) appendRequestLocked(
\trequest *HTTPRequestObservation,
) {
\tif request == nil {
\t\treturn
\t}
\tt.transactions = append(t.transactions, HTTPTransactionObservation{
\t\tSequence:                         len(t.transactions) + 1,
\t\tRequestObservedAfterMilliseconds: elapsedMilliseconds(t.startedAt),
\t\tRequest:                          *cloneHTTPRequestObservation(request),
\t})
\tt.request.transactionIndex = len(t.transactions) - 1
}

func (t *http1MetadataTimeline) beginRequestBodyLocked(plan httpBodyPlan) bool {
\tt.request.mode = plan.mode
\tt.request.remaining = plan.length
\tt.request.terminalAfterBody = plan.terminalAfterBody
\tt.request.body = newBodyCaptureAccumulator(
\t\tt.policy,
\t\tplan.contentType,
\t\tplan.contentEncoding,
\t\tt.reserveBody,
\t)
\tif plan.mode == httpBodyChunked {
\t\tt.request.chunked.reset()
\t}
\tif plan.mode == httpBodyNone {
\t\treturn t.completeRequestBodyLocked(false)
\t}
\treturn false
}

func (t *http1MetadataTimeline) completeRequestBodyLocked(truncated bool) bool {
\tindex := t.request.transactionIndex
\tif index < 0 || index >= len(t.transactions) {
\t\treturn false
\t}
\tbody := t.request.body.Finish()
\tif body != nil {
\t\tbody.Truncated = body.Truncated || truncated
\t\tt.transactions[index].RequestBody = body
\t}
\tt.transactions[index].RequestCompletedAfterMilliseconds =
\t\telapsedMilliseconds(t.startedAt)
\tif t.request.body != nil {
\t\tt.request.body.Clear()
\t}
\tt.request.body = nil
\tt.request.transactionIndex = -1
\treturn true
}

func (t *http1MetadataTimeline) beginResponseBodyLocked(plan httpBodyPlan) bool {
\tt.response.mode = plan.mode
\tt.response.remaining = plan.length
\tt.response.terminalAfterBody = plan.terminalAfterBody
\tt.response.body = newBodyCaptureAccumulator(
\t\tt.policy,
\t\tplan.contentType,
\t\tplan.contentEncoding,
\t\tt.reserveBody,
\t)
\tif plan.mode == httpBodyChunked {
\t\tt.response.chunked.reset()
\t}
\tif plan.mode == httpBodyNone {
\t\treturn t.completeResponseBodyLocked(false)
\t}
\treturn false
}

func (t *http1MetadataTimeline) completeResponseBodyLocked(truncated bool) bool {
\tindex := t.response.transactionIndex
\tif index < 0 || index >= len(t.transactions) {
\t\treturn false
\t}
\tbody := t.response.body.Finish()
\tif body != nil {
\t\tbody.Truncated = body.Truncated || truncated
\t\tt.transactions[index].ResponseBody = body
\t}
\tt.transactions[index].ResponseCompletedAfterMilliseconds =
\t\telapsedMilliseconds(t.startedAt)
\tif t.response.body != nil {
\t\tt.response.body.Clear()
\t}
\tt.response.body = nil
\tt.response.transactionIndex = -1
\treturn true
}
''')
    replace_once(path,
'''\tfor index := range t.transactions {
\t\tif t.transactions[index].Response != nil {
\t\t\tcontinue
\t\t}
\t\tt.transactions[index].Response = cloneHTTPResponseObservation(response)
\t\treturn true
\t}
''',
'''\tfor index := range t.transactions {
\t\tif t.transactions[index].Response != nil {
\t\t\tcontinue
\t\t}
\t\tt.transactions[index].Response = cloneHTTPResponseObservation(response)
\t\tt.response.transactionIndex = index
\t\treturn true
\t}
''')


def patch_http1_observers() -> None:
    path = ROOT / "core/inspectionruntime/http1_timeline.go"
    replacements = [
        ('''\t\t\trequest, plan, valid := parseHTTPRequestEnvelope(block)
\t\t\tif !valid ||
\t\t\t\t!validHTTPTransactionRequest(block, true, request, t.expectedHost) {
\t\t\t\treturn t.failClosedLocked() || changed
\t\t\t}
\t\t\tresetHTTPMetadataHeader(&t.request.header)
\t\t\tt.appendRequestLocked(request)
\t\t\tchanged = true
''', '''\t\t\trequest, plan, valid := parseHTTPRequestEnvelope(block)
\t\t\tif !valid ||
\t\t\t\t!validHTTPTransactionRequest(block, true, request, t.expectedHost) {
\t\t\t\treturn t.failClosedLocked() || changed
\t\t\t}
\t\t\trequest.Headers, request.HeaderValuesTruncated =
\t\t\t\tcaptureHTTP1HeaderValues(block, true, t.policy)
\t\t\tresetHTTPMetadataHeader(&t.request.header)
\t\t\tt.appendRequestLocked(request)
\t\t\tchanged = true
'''),
        ('''\t\t\tt.request.mode = plan.mode
\t\t\tt.request.remaining = plan.length
\t\t\tt.request.terminalAfterBody = plan.terminalAfterBody
\t\t\tif plan.mode == httpBodyChunked {
\t\t\t\tt.request.chunked.reset()
\t\t\t}
\t\t\tif plan.mode == httpBodyNone {
\t\t\t\tif plan.terminalAfterBody {
\t\t\t\t\tt.request.stopped = true
\t\t\t\t\tclearHTTPRequestStreamState(&t.request)
\t\t\t\t\treturn changed
\t\t\t\t}
\t\t\t\tcontinue
\t\t\t}
''', '''\t\t\tif t.beginRequestBodyLocked(plan) {
\t\t\t\tchanged = true
\t\t\t}
\t\t\tif plan.mode == httpBodyNone {
\t\t\t\tresetHTTPRequestBodyState(&t.request)
\t\t\t\tif plan.terminalAfterBody {
\t\t\t\t\tt.request.stopped = true
\t\t\t\t\tclearHTTPRequestStreamState(&t.request)
\t\t\t\t\treturn changed
\t\t\t\t}
\t\t\t\tcontinue
\t\t\t}
'''),
        ('''\t\tcase httpBodyFixed:
\t\t\tconsumed := int64(len(data))
\t\t\tif consumed > t.request.remaining {
\t\t\t\tconsumed = t.request.remaining
\t\t\t}
\t\t\tdata = data[consumed:]
\t\t\tt.request.remaining -= consumed
\t\t\tif t.request.remaining != 0 {
\t\t\t\tcontinue
\t\t\t}
\t\t\tterminal := t.request.terminalAfterBody
\t\t\tresetHTTPRequestBodyState(&t.request)
\t\t\tif terminal {
\t\t\t\tt.request.stopped = true
\t\t\t\treturn changed
\t\t\t}
\t\tcase httpBodyChunked:
\t\t\trest, complete, invalid := t.request.chunked.consume(data)
''', '''\t\tcase httpBodyFixed:
\t\t\tconsumed := int64(len(data))
\t\t\tif consumed > t.request.remaining {
\t\t\t\tconsumed = t.request.remaining
\t\t\t}
\t\t\tt.request.body.Observe(data[:int(consumed)])
\t\t\tdata = data[consumed:]
\t\t\tt.request.remaining -= consumed
\t\t\tif t.request.remaining != 0 {
\t\t\t\tcontinue
\t\t\t}
\t\t\tterminal := t.request.terminalAfterBody
\t\t\tif t.completeRequestBodyLocked(false) {
\t\t\t\tchanged = true
\t\t\t}
\t\t\tresetHTTPRequestBodyState(&t.request)
\t\t\tif terminal {
\t\t\t\tt.request.stopped = true
\t\t\t\treturn changed
\t\t\t}
\t\tcase httpBodyChunked:
\t\t\trest, complete, invalid := t.request.chunked.consumeObserved(
\t\t\t\tdata,
\t\t\t\tt.request.body.Observe,
\t\t\t)
'''),
        ('''\t\t\tterminal := t.request.terminalAfterBody
\t\t\tresetHTTPRequestBodyState(&t.request)
\t\t\tif terminal {
''', '''\t\t\tterminal := t.request.terminalAfterBody
\t\t\tif t.completeRequestBodyLocked(false) {
\t\t\t\tchanged = true
\t\t\t}
\t\t\tresetHTTPRequestBodyState(&t.request)
\t\t\tif terminal {
'''),
        ('''\t\t\tresponse, plan, informational, valid := parseHTTPResponseEnvelope(
\t\t\t\tblock,
\t\t\t\tmethod,
\t\t\t)
\t\t\tresetHTTPMetadataHeader(&t.response.header)
''', '''\t\t\tresponse, plan, informational, valid := parseHTTPResponseEnvelope(
\t\t\t\tblock,
\t\t\t\tmethod,
\t\t\t)
\t\t\theaderValues, headerValuesTruncated :=
\t\t\t\tcaptureHTTP1HeaderValues(block, true, t.policy)
\t\t\tresetHTTPMetadataHeader(&t.response.header)
'''),
        ('''\t\t\tresponse.ObservedBytes = t.response.observedHeaderBytes
\t\t\tresponse.ObservedAfterMilliseconds = elapsedMilliseconds(t.startedAt)
\t\t\tresetHTTPResponseHeaderState(&t.response)
''', '''\t\t\tresponse.ObservedBytes = t.response.observedHeaderBytes
\t\t\tresponse.ObservedAfterMilliseconds = elapsedMilliseconds(t.startedAt)
\t\t\tresponse.Headers = headerValues
\t\t\tresponse.HeaderValuesTruncated = headerValuesTruncated
\t\t\tresetHTTPResponseHeaderState(&t.response)
'''),
        ('''\t\t\tt.response.mode = plan.mode
\t\t\tt.response.remaining = plan.length
\t\t\tt.response.terminalAfterBody = plan.terminalAfterBody
\t\t\tif plan.mode == httpBodyChunked {
\t\t\t\tt.response.chunked.reset()
\t\t\t}
\t\t\tif plan.mode == httpBodyUntilClose {
\t\t\t\treturn t.stopNormallyLocked() || changed
\t\t\t}
\t\t\tif plan.mode == httpBodyNone {
\t\t\t\tif plan.terminalAfterBody {
\t\t\t\t\treturn t.stopNormallyLocked() || changed
\t\t\t\t}
\t\t\t\tcontinue
\t\t\t}
''', '''\t\t\tif t.beginResponseBodyLocked(plan) {
\t\t\t\tchanged = true
\t\t\t}
\t\t\tif plan.mode == httpBodyNone {
\t\t\t\tresetHTTPResponseBodyState(&t.response)
\t\t\t\tif plan.terminalAfterBody {
\t\t\t\t\treturn t.stopNormallyLocked() || changed
\t\t\t\t}
\t\t\t\tcontinue
\t\t\t}
'''),
        ('''\t\tcase httpBodyFixed:
\t\t\tconsumed := int64(len(data))
\t\t\tif consumed > t.response.remaining {
\t\t\t\tconsumed = t.response.remaining
\t\t\t}
\t\t\tdata = data[consumed:]
\t\t\tt.response.remaining -= consumed
\t\t\tif t.response.remaining != 0 {
\t\t\t\tcontinue
\t\t\t}
\t\t\tterminal := t.response.terminalAfterBody
\t\t\tresetHTTPResponseBodyState(&t.response)
\t\t\tif terminal {
\t\t\t\treturn t.stopNormallyLocked() || changed
\t\t\t}
\t\tcase httpBodyChunked:
\t\t\trest, complete, invalid := t.response.chunked.consume(data)
''', '''\t\tcase httpBodyFixed:
\t\t\tconsumed := int64(len(data))
\t\t\tif consumed > t.response.remaining {
\t\t\t\tconsumed = t.response.remaining
\t\t\t}
\t\t\tt.response.body.Observe(data[:int(consumed)])
\t\t\tdata = data[consumed:]
\t\t\tt.response.remaining -= consumed
\t\t\tif t.response.remaining != 0 {
\t\t\t\tcontinue
\t\t\t}
\t\t\tterminal := t.response.terminalAfterBody
\t\t\tif t.completeResponseBodyLocked(false) {
\t\t\t\tchanged = true
\t\t\t}
\t\t\tresetHTTPResponseBodyState(&t.response)
\t\t\tif terminal {
\t\t\t\treturn t.stopNormallyLocked() || changed
\t\t\t}
\t\tcase httpBodyChunked:
\t\t\trest, complete, invalid := t.response.chunked.consumeObserved(
\t\t\t\tdata,
\t\t\t\tt.response.body.Observe,
\t\t\t)
'''),
        ('''\t\t\tterminal := t.response.terminalAfterBody
\t\t\tresetHTTPResponseBodyState(&t.response)
\t\t\tif terminal {
''', '''\t\t\tterminal := t.response.terminalAfterBody
\t\t\tif t.completeResponseBodyLocked(false) {
\t\t\t\tchanged = true
\t\t\t}
\t\t\tresetHTTPResponseBodyState(&t.response)
\t\t\tif terminal {
'''),
        ('''\t\tcase httpBodyUntilClose:
\t\t\treturn changed
''', '''\t\tcase httpBodyUntilClose:
\t\t\tt.response.body.Observe(data)
\t\t\tdata = nil
'''),
    ]
    text = path.read_text()
    for old, new in replacements:
        if old not in text:
            raise RuntimeError(f"missing HTTP/1 observer replacement: {old[:110]!r}")
        text = text.replace(old, new, 1)
    path.write_text(text)


def patch_http1_completion() -> None:
    path = ROOT / "core/inspectionruntime/http1_timeline.go"
    replacements = [
        ('''\tif t.response.mode == httpBodyUntilClose {
\t\tchanged := t.stopNormallyLocked()
''', '''\tif t.response.mode == httpBodyUntilClose {
\t\tchanged := t.completeResponseBodyLocked(false)
\t\tchanged = t.stopNormallyLocked() || changed
'''),
        ('''func (t *http1MetadataTimeline) failClosedLocked() bool {
\tchanged := !t.truncated
\tt.truncated = true
\tt.clearLocked()
''', '''func (t *http1MetadataTimeline) failClosedLocked() bool {
\tchanged := !t.truncated
\tif t.request.transactionIndex >= 0 {
\t\tchanged = t.completeRequestBodyLocked(true) || changed
\t}
\tif t.response.transactionIndex >= 0 {
\t\tchanged = t.completeResponseBodyLocked(true) || changed
\t}
\tt.truncated = true
\tt.clearLocked()
'''),
        ('''func (t *http1MetadataTimeline) stopNormallyLocked() bool {
\tchanged := false
\tif t.hasPendingResponseLocked() && !t.truncated {
''', '''func (t *http1MetadataTimeline) stopNormallyLocked() bool {
\tchanged := false
\tif t.response.transactionIndex >= 0 {
\t\tchanged = t.completeResponseBodyLocked(false)
\t}
\tif t.request.transactionIndex >= 0 {
\t\tchanged = t.completeRequestBodyLocked(true) || changed
\t}
\tif t.hasPendingResponseLocked() && !t.truncated {
'''),
        ('''func resetHTTPRequestBodyState(state *httpRequestStreamState) {
\tstate.mode = httpBodyNone
\tstate.remaining = 0
\tstate.chunked.clear()
\tstate.terminalAfterBody = false
}
''', '''func resetHTTPRequestBodyState(state *httpRequestStreamState) {
\tstate.mode = httpBodyNone
\tstate.remaining = 0
\tstate.chunked.clear()
\tif state.body != nil {
\t\tstate.body.Clear()
\t}
\tstate.body = nil
\tstate.transactionIndex = -1
\tstate.terminalAfterBody = false
}
'''),
        ('''func resetHTTPResponseBodyState(state *httpResponseStreamState) {
\tstate.mode = httpBodyNone
\tstate.remaining = 0
\tstate.chunked.clear()
\tstate.terminalAfterBody = false
}
''', '''func resetHTTPResponseBodyState(state *httpResponseStreamState) {
\tstate.mode = httpBodyNone
\tstate.remaining = 0
\tstate.chunked.clear()
\tif state.body != nil {
\t\tstate.body.Clear()
\t}
\tstate.body = nil
\tstate.transactionIndex = -1
\tstate.terminalAfterBody = false
}
'''),
        ('''func clearHTTPRequestStreamState(state *httpRequestStreamState) {
\tclearHTTPMetadataBuffer(state.header)
\tstate.header = nil
\tstate.chunked.clear()
\tstate.remaining = 0
\tstate.terminalAfterBody = false
}
''', '''func clearHTTPRequestStreamState(state *httpRequestStreamState) {
\tclearHTTPMetadataBuffer(state.header)
\tstate.header = nil
\tstate.chunked.clear()
\tif state.body != nil {
\t\tstate.body.Clear()
\t}
\tstate.body = nil
\tstate.remaining = 0
\tstate.transactionIndex = -1
\tstate.terminalAfterBody = false
}
'''),
        ('''func clearHTTPResponseStreamState(state *httpResponseStreamState) {
\tclearHTTPMetadataBuffer(state.header)
\tstate.header = nil
\tstate.chunked.clear()
\tstate.remaining = 0
\tstate.terminalAfterBody = false
''', '''func clearHTTPResponseStreamState(state *httpResponseStreamState) {
\tclearHTTPMetadataBuffer(state.header)
\tstate.header = nil
\tstate.chunked.clear()
\tif state.body != nil {
\t\tstate.body.Clear()
\t}
\tstate.body = nil
\tstate.remaining = 0
\tstate.transactionIndex = -1
\tstate.terminalAfterBody = false
'''),
        ('''func (s *httpChunkedBodySkipper) consume(
\tdata []byte,
) (rest []byte, complete bool, invalid bool) {
\tfor len(data) > 0 {
''', '''func (s *httpChunkedBodySkipper) consume(
\tdata []byte,
) (rest []byte, complete bool, invalid bool) {
\treturn s.consumeObserved(data, nil)
}

func (s *httpChunkedBodySkipper) consumeObserved(
\tdata []byte,
\tobserve func([]byte),
) (rest []byte, complete bool, invalid bool) {
\tfor len(data) > 0 {
'''),
        ('''\t\tcase httpChunkData:
\t\t\tconsumed := int64(len(data))
\t\t\tif consumed > s.remaining {
\t\t\t\tconsumed = s.remaining
\t\t\t}
\t\t\tdata = data[consumed:]
''', '''\t\tcase httpChunkData:
\t\t\tconsumed := int64(len(data))
\t\t\tif consumed > s.remaining {
\t\t\t\tconsumed = s.remaining
\t\t\t}
\t\t\tif observe != nil && consumed > 0 {
\t\t\t\tobserve(data[:int(consumed)])
\t\t\t}
\t\t\tdata = data[consumed:]
'''),
    ]
    text = path.read_text()
    for old, new in replacements:
        if old not in text:
            raise RuntimeError(f"missing HTTP/1 completion replacement: {old[:110]!r}")
        text = text.replace(old, new, 1)
    path.write_text(text)


def patch_all() -> None:
    patch_http1_metadata()
    patch_http1_timeline_contract()
    patch_http1_framing()
    patch_http1_body_helpers()
    patch_http1_observers()
    patch_http1_completion()
