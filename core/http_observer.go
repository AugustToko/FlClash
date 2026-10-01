package main

import "github.com/metacubex/mihomo/component/observer"

type HTTPObservationParams struct {
	Enabled   bool   `json:"enabled"`
	SessionID string `json:"sessionId"`
}

func handleSetHTTPObservationEnabled(params HTTPObservationParams) bool {
	observer.Configure(params.Enabled, params.SessionID)
	return observer.Enabled()
}

func disableHTTPObservation() {
	observer.Configure(false, "")
}

func init() {
	registerMethod(setHTTPObservationEnabledMethod, withArguments(func(params *HTTPObservationParams, response MethodResponse) {
		response.success(handleSetHTTPObservationEnabled(*params))
	}))
}
