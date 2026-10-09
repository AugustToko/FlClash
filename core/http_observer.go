package main

import (
	"sync"

	"core/inspectionruntime"
	"github.com/metacubex/mihomo/component/observer"
)

var httpObservationChangeMu sync.Mutex
var httpObservationChange = make(chan struct{})
var httpObservationPolicyMu sync.RWMutex
var httpObservationPolicy inspectionruntime.CapturePolicy

func httpObservationChangeSignal() <-chan struct{} {
	httpObservationChangeMu.Lock()
	defer httpObservationChangeMu.Unlock()
	return httpObservationChange
}

func publishHTTPObservationChange() {
	httpObservationChangeMu.Lock()
	close(httpObservationChange)
	httpObservationChange = make(chan struct{})
	httpObservationChangeMu.Unlock()
}

func currentHTTPObservationPolicy() inspectionruntime.CapturePolicy {
	httpObservationPolicyMu.RLock()
	defer httpObservationPolicyMu.RUnlock()
	return httpObservationPolicy.Normalize()
}

func setHTTPObservationPolicy(policy inspectionruntime.CapturePolicy) bool {
	policy = policy.Normalize()
	httpObservationPolicyMu.Lock()
	changed := !sameHTTPObservationPolicy(httpObservationPolicy, policy)
	httpObservationPolicy = policy
	httpObservationPolicyMu.Unlock()
	return changed
}

func sameHTTPObservationPolicy(
	left inspectionruntime.CapturePolicy,
	right inspectionruntime.CapturePolicy,
) bool {
	left = left.Normalize()
	right = right.Normalize()
	if left.HeaderValues != right.HeaderValues ||
		left.SensitiveHeaderValues != right.SensitiveHeaderValues ||
		left.BodyMode != right.BodyMode ||
		left.MaxBodyBytes != right.MaxBodyBytes ||
		len(left.RedactedHeaderNames) != len(right.RedactedHeaderNames) {
		return false
	}
	for index := range left.RedactedHeaderNames {
		if left.RedactedHeaderNames[index] != right.RedactedHeaderNames[index] {
			return false
		}
	}
	return true
}

type HTTPObservationParams struct {
	Enabled   bool                            `json:"enabled"`
	SessionID string                          `json:"sessionId"`
	Policy    inspectionruntime.CapturePolicy `json:"policy"`
}

func handleSetHTTPObservationEnabled(params HTTPObservationParams) bool {
	previousEnabled := observer.Enabled()
	previousSession := observer.SessionID()
	policy := params.Policy
	if !params.Enabled {
		policy = inspectionruntime.CapturePolicy{}
	}
	policyChanged := setHTTPObservationPolicy(policy)
	observer.Configure(params.Enabled, params.SessionID)
	enabled := observer.Enabled()
	session := observer.SessionID()
	if enabled != previousEnabled || session != previousSession || policyChanged {
		publishHTTPObservationChange()
	}
	return enabled
}

func disableHTTPObservation() {
	handleSetHTTPObservationEnabled(HTTPObservationParams{})
}

func init() {
	registerMethod(setHTTPObservationEnabledMethod, withArguments(func(params *HTTPObservationParams, response MethodResponse) {
		response.success(handleSetHTTPObservationEnabled(*params))
	}))
}
