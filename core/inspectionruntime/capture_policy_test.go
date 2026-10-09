package inspectionruntime

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
