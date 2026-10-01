package main

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/observer"
)

func TestHTTPObservationToggle(t *testing.T) {
	observer.SetEnabled(false)
	t.Cleanup(func() { observer.SetEnabled(false) })

	if !handleSetHTTPObservationEnabled(HTTPObservationParams{
		Enabled:   true,
		SessionID: "session-a",
	}) || !observer.Enabled() {
		t.Fatal("enabling HTTP observation did not reach the Mihomo observer")
	}
	if observer.SessionID() != "session-a" {
		t.Fatalf("session ID = %q", observer.SessionID())
	}
	if handleSetHTTPObservationEnabled(HTTPObservationParams{}) || observer.Enabled() {
		t.Fatal("disabling HTTP observation did not reach the Mihomo observer")
	}
	if observer.SessionID() != "" {
		t.Fatalf("disabled observer retained session %q", observer.SessionID())
	}
}

func TestHTTPObservationBoundsSessionIdentifier(t *testing.T) {
	observer.SetEnabled(false)
	t.Cleanup(func() { observer.SetEnabled(false) })

	handleSetHTTPObservationEnabled(HTTPObservationParams{
		Enabled:   true,
		SessionID: strings.Repeat("s", 256),
	})
	if got := observer.SessionID(); len(got) != 128 {
		t.Fatalf("session ID length = %d", len(got))
	}
}

func TestHTTPObservationMethodIsRegistered(t *testing.T) {
	if _, exists := methodHandlers[setHTTPObservationEnabledMethod]; !exists {
		t.Fatal("setHttpObservationEnabled core method is not registered")
	}
}

func TestDisableHTTPObservationIsIdempotent(t *testing.T) {
	observer.Configure(true, "session-a")
	t.Cleanup(func() { observer.SetEnabled(false) })

	disableHTTPObservation()
	disableHTTPObservation()
	if observer.Enabled() || observer.SessionID() != "" {
		t.Fatal("HTTP observation remained configured after shutdown cleanup")
	}
}
