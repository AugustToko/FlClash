package main

import (
	"sync"

	"github.com/metacubex/mihomo/component/observer"
)

var httpObservationChangeMu sync.Mutex
var httpObservationChange = make(chan struct{})

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

type HTTPObservationParams struct {
	Enabled   bool   `json:"enabled"`
	SessionID string `json:"sessionId"`
}

func handleSetHTTPObservationEnabled(params HTTPObservationParams) bool {
	previousEnabled := observer.Enabled()
	previousSession := observer.SessionID()
	observer.Configure(params.Enabled, params.SessionID)
	enabled := observer.Enabled()
	session := observer.SessionID()
	if enabled != previousEnabled || session != previousSession {
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
