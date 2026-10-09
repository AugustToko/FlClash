package main

import (
	"strings"
	"testing"
	"time"

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

func TestHTTPObservationChangeSignalTracksActualSessionChanges(t *testing.T) {
	disableHTTPObservation()
	defer disableHTTPObservation()

	enabledSignal := httpObservationChangeSignal()
	if !handleSetHTTPObservationEnabled(HTTPObservationParams{
		Enabled: true, SessionID: "http-capture:test-session",
	}) {
		t.Fatal("observer did not enable")
	}
	select {
	case <-enabledSignal:
	case <-time.After(time.Second):
		t.Fatal("enabling observation did not close the change signal")
	}

	unchangedSignal := httpObservationChangeSignal()
	if !handleSetHTTPObservationEnabled(HTTPObservationParams{
		Enabled: true, SessionID: "http-capture:test-session",
	}) {
		t.Fatal("observer did not remain enabled")
	}
	select {
	case <-unchangedSignal:
		t.Fatal("an unchanged observer configuration emitted a change")
	default:
	}

	disableHTTPObservation()
	select {
	case <-unchangedSignal:
	case <-time.After(time.Second):
		t.Fatal("disabling observation did not close the change signal")
	}
}
