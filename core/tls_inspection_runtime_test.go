package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func runtimePolicyFixture(t *testing.T) (*TLSInspectionAuthorityStatus, *TLSInspectionLeafCacheStatus) {
	t.Helper()
	oldHome := C.Path.HomeDir()
	wasRunning := isRunning.Load()
	isRunning.Store(true)
	tlsInspectionAuthorityMu.Lock()
	resetTLSInspectionLeafPolicySession()
	tlsInspectionRuntimeCancelled = make(map[string]time.Time)
	C.SetHomeDir(t.TempDir())
	tlsInspectionAuthorityMu.Unlock()
	t.Cleanup(func() {
		tlsInspectionAuthorityMu.Lock()
		resetTLSInspectionLeafPolicySession()
		C.SetHomeDir(oldHome)
		isRunning.Store(wasRunning)
		tlsInspectionRuntimeCancelled = make(map[string]time.Time)
		tlsInspectionAuthorityMu.Unlock()
	})
	authority, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatal(failure)
	}
	policy, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{
		Enabled: true, AuthorityGeneration: authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		RiskVersion:                tlsInspectionLeafRiskVersion, TrustSatisfied: true,
		Allowlist:  []TLSInspectionLeafRule{{Host: "example.com", Scope: "subdomains"}},
		Exclusions: []TLSInspectionLeafRule{{Host: "accounts.example.com", Scope: "exact"}},
	})
	if failure != nil {
		t.Fatal(failure)
	}
	return authority, policy
}

func runtimeStartParams(authority *TLSInspectionAuthorityStatus, policy *TLSInspectionLeafCacheStatus) *TLSInspectionRuntimeStartParams {
	return &TLSInspectionRuntimeStartParams{
		ID: "0123456789abcdef0123456789abcdef", Confirm: true,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		PolicyDigest:               policy.PolicyDigest,
	}
}

func TestTLSInspectionRuntimeNeverStartsFromPreparation(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	if getTLSInspectionRuntimeStatus().Runtime.State != "stopped" {
		t.Fatal("preparation automatically started runtime")
	}
	params := runtimeStartParams(authority, policy)
	params.Confirm = false
	if _, failure := startTLSInspectionRuntime(params); failure == nil {
		t.Fatal("unconfirmed runtime started")
	}
	params.Confirm = true
	params.PolicyDigest = strings.Repeat("0", 64)
	if _, failure := startTLSInspectionRuntime(params); failure == nil {
		t.Fatal("stale policy started runtime")
	}
}

func TestTLSInspectionRuntimeStartIsIdentityBoundAndCredentialsNotInStatus(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	params := runtimeStartParams(authority, policy)
	started, failure := startTLSInspectionRuntime(params)
	if failure != nil {
		t.Fatal(failure)
	}
	if started.Status.Runtime.ID != params.ID || started.Username != "flclash" || len(started.Password) != 64 {
		t.Fatal("invalid runtime start contract")
	}
	if started.Status.Mode != "loopback-connect-http1" || started.Status.CapturesPayload || started.Status.ChangesSystemProxy {
		t.Fatal("misleading runtime boundary")
	}
	encoded, err := json.Marshal(getTLSInspectionRuntimeStatus())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), started.Password) || strings.Contains(string(encoded), "password") {
		t.Fatal("runtime credential leaked into status")
	}
	if _, failure := startTLSInspectionRuntime(params); failure == nil || failure.Code != "runtime_already_running" {
		t.Fatal("duplicate start created another listener")
	}
	if _, failure := stopTLSInspectionRuntime(&TLSInspectionRuntimeStopParams{ID: strings.Repeat("a", 32)}); failure != nil {
		t.Fatal(failure)
	}
	if getTLSInspectionRuntimeStatus().Runtime.State != "running" {
		t.Fatal("stale stop killed newer runtime")
	}
	if _, failure := stopTLSInspectionRuntime(&TLSInspectionRuntimeStopParams{ID: params.ID}); failure != nil {
		t.Fatal(failure)
	}
	if getTLSInspectionRuntimeStatus().Runtime.State != "stopped" {
		t.Fatal("explicit stop did not revoke runtime")
	}
}

func TestTLSInspectionRuntimeStopBeforeStartPreventsLateResurrection(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	params := runtimeStartParams(authority, policy)
	if _, failure := stopTLSInspectionRuntime(&TLSInspectionRuntimeStopParams{ID: params.ID}); failure != nil {
		t.Fatal(failure)
	}
	if _, failure := startTLSInspectionRuntime(params); failure == nil || failure.Code != "runtime_start_cancelled" {
		t.Fatal("cancelled start resurrected runtime")
	}
}

func TestTLSInspectionRuntimeLeafAccessIsAuthorizedAndPrivate(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	params := runtimeStartParams(authority, policy)
	if _, failure := startTLSInspectionRuntime(params); failure != nil {
		t.Fatal(failure)
	}
	active := tlsInspectionRuntime
	leaf, err := loadTLSInspectionRuntimeLeaf(context.Background(), active, "api.example.com")
	if err != nil || leaf == nil || leaf.PrivateKey == nil {
		t.Fatalf("authorized runtime leaf unavailable: %v", err)
	}
	if err := leaf.Leaf.VerifyHostname("api.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"accounts.example.com", "outside.example.net", "co.uk", "127.0.0.1"} {
		if _, err := loadTLSInspectionRuntimeLeaf(context.Background(), active, host); err == nil {
			t.Fatalf("unauthorized runtime leaf for %s", host)
		}
	}
	if _, failure := rotateTLSInspectionAuthority(true); failure != nil {
		t.Fatal(failure)
	}
	if getTLSInspectionRuntimeStatus().Runtime.State != "stopped" {
		t.Fatal("CA rotation did not stop runtime")
	}
	if _, err := loadTLSInspectionRuntimeLeaf(context.Background(), active, "api.example.com"); err == nil {
		t.Fatal("old runtime acquired rotated private material")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := active.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTLSInspectionRuntimeTrustPolicyLossRevokesListener(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	if _, failure := startTLSInspectionRuntime(runtimeStartParams(authority, policy)); failure != nil {
		t.Fatal(failure)
	}
	active := tlsInspectionRuntime
	if _, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{Enabled: false}); failure != nil {
		t.Fatal(failure)
	}
	if getTLSInspectionRuntimeStatus().Runtime.State != "stopped" {
		t.Fatal("policy loss kept runtime alive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := active.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}
