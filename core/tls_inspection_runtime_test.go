package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	O "github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/tunnel"
)

type tlsInspectionRouteAdapter struct {
	*O.Base
	marker   byte
	metadata chan C.Metadata
}

func newTLSInspectionRouteProxy(name string, marker byte) (*tlsInspectionRouteAdapter, C.Proxy) {
	adapter := &tlsInspectionRouteAdapter{
		Base:     O.NewBase(O.BaseOption{Name: name, Type: C.Compatible}),
		marker:   marker,
		metadata: make(chan C.Metadata, 1),
	}
	return adapter, A.NewProxy(adapter)
}

func (a *tlsInspectionRouteAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	client, server := net.Pipe()
	copyMetadata := *metadata
	select {
	case a.metadata <- copyMetadata:
	default:
	}
	go func() {
		defer server.Close()
		stop := context.AfterFunc(ctx, func() { _ = server.Close() })
		defer stop()
		request := make([]byte, 1)
		if _, err := io.ReadFull(server, request); err != nil {
			return
		}
		_, _ = server.Write([]byte{a.marker})
	}()
	return O.NewConn(client, a), nil
}

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
		RuntimeProofID:             policy.RuntimeProofID,
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

func TestTLSInspectionRuntimeRejectsStaleRuntimeProof(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	params := runtimeStartParams(authority, policy)
	params.RuntimeProofID = strings.Repeat("f", 32)
	if result, failure := startTLSInspectionRuntime(params); failure == nil || result != nil || failure.Code != "runtime_not_authorized" {
		t.Fatalf("stale runtime proof started listener: result=%+v failure=%+v", result, failure)
	}
}

func TestTLSInspectionRuntimeRejectsProofFromPreviousAuthorizationEpoch(t *testing.T) {
	authority, first := runtimePolicyFixture(t)
	stale := runtimeStartParams(authority, first)
	if _, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{Enabled: false}); failure != nil {
		t.Fatal(failure)
	}
	second, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{
		Enabled:                    true,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		RiskVersion:                tlsInspectionLeafRiskVersion,
		TrustSatisfied:             true,
		Allowlist:                  []TLSInspectionLeafRule{{Host: "example.com", Scope: "subdomains"}},
		Exclusions:                 []TLSInspectionLeafRule{{Host: "accounts.example.com", Scope: "exact"}},
	})
	if failure != nil {
		t.Fatal(failure)
	}
	if second.RuntimeProofID == first.RuntimeProofID {
		t.Fatal("authorization re-enable reused the previous runtime proof")
	}
	if result, failure := startTLSInspectionRuntime(stale); failure == nil || result != nil || failure.Code != "runtime_not_authorized" {
		t.Fatalf("previous authorization proof started listener: result=%+v failure=%+v", result, failure)
	}
	fresh := runtimeStartParams(authority, second)
	started, failure := startTLSInspectionRuntime(fresh)
	if failure != nil || started == nil {
		t.Fatalf("fresh authorization proof did not start listener: result=%+v failure=%+v", started, failure)
	}
	if _, failure := stopTLSInspectionRuntime(&TLSInspectionRuntimeStopParams{ID: fresh.ID}); failure != nil {
		t.Fatal(failure)
	}
}

func TestTLSInspectionRuntimeSurvivesIdempotentAuthorizationRefresh(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	params := runtimeStartParams(authority, policy)
	started, failure := startTLSInspectionRuntime(params)
	if failure != nil {
		t.Fatal(failure)
	}
	refreshed, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{
		Enabled:                    true,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		RiskVersion:                tlsInspectionLeafRiskVersion,
		TrustSatisfied:             true,
		Allowlist:                  []TLSInspectionLeafRule{{Host: "example.com", Scope: "subdomains"}},
		Exclusions:                 []TLSInspectionLeafRule{{Host: "accounts.example.com", Scope: "exact"}},
	})
	if failure != nil {
		t.Fatal(failure)
	}
	if refreshed.RuntimeProofID != policy.RuntimeProofID {
		t.Fatalf("idempotent refresh changed runtime proof: before=%q after=%q", policy.RuntimeProofID, refreshed.RuntimeProofID)
	}
	status := getTLSInspectionRuntimeStatus()
	if status.Runtime.State != "running" || status.Runtime.ID != started.Status.Runtime.ID {
		t.Fatalf("idempotent refresh stopped or replaced runtime: %+v", status)
	}
	if _, failure := stopTLSInspectionRuntime(&TLSInspectionRuntimeStopParams{ID: params.ID}); failure != nil {
		t.Fatal(failure)
	}
}

func TestTLSInspectionRuntimeStartIsIdentityBoundAndCredentialsNotInStatus(t *testing.T) {
	authority, policy := runtimePolicyFixture(t)
	params := runtimeStartParams(authority, policy)
	started, failure := startTLSInspectionRuntime(params)
	if failure != nil {
		t.Fatal(failure)
	}
	if started.Status.Runtime.ID != params.ID || started.Status.RuntimeProofID != policy.RuntimeProofID || started.Username != "flclash" || len(started.Password) != 64 {
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

func TestTLSInspectionRuntimeDialUsesActiveMihomoTunnelMetadata(t *testing.T) {
	original := tlsInspectionRuntimeHandleTCPConn
	defer func() { tlsInspectionRuntimeHandleTCPConn = original }()
	received := make(chan *C.Metadata, 1)
	tlsInspectionRuntimeHandleTCPConn = func(conn net.Conn, metadata *C.Metadata) {
		copyMetadata := *metadata
		received <- &copyMetadata
		_ = conn.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := dialTLSInspectionRuntime(ctx, "tcp", "api.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case metadata := <-received:
		if metadata.NetWork != C.TCP || metadata.Type != C.INNER ||
			metadata.Host != "api.example.com" || metadata.DstPort != 443 ||
			metadata.DstIP.IsValid() || metadata.SourceValid() ||
			metadata.Process != "" || metadata.ProcessPath != "" || metadata.Uid != 0 {
			t.Fatalf("unexpected routed metadata: %+v", metadata)
		}
	case <-ctx.Done():
		t.Fatal("tunnel handler did not receive routed metadata")
	}
}

func TestTLSInspectionRuntimeDialFollowsCurrentTunnelHandler(t *testing.T) {
	original := tlsInspectionRuntimeHandleTCPConn
	defer func() { tlsInspectionRuntimeHandleTCPConn = original }()

	roundTrip := func(marker byte) {
		t.Helper()
		done := make(chan struct{})
		tlsInspectionRuntimeHandleTCPConn = func(conn net.Conn, metadata *C.Metadata) {
			defer close(done)
			defer conn.Close()
			if metadata.Type != C.INNER || metadata.Host != "api.example.com" || metadata.DstPort != 443 {
				return
			}
			request := make([]byte, 1)
			if _, err := io.ReadFull(conn, request); err != nil {
				return
			}
			_, _ = conn.Write([]byte{marker})
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := dialTLSInspectionRuntime(ctx, "tcp", "api.example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{1}); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		response := make([]byte, 1)
		if _, err := io.ReadFull(conn, response); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		_ = conn.Close()
		if response[0] != marker {
			t.Fatalf("routed marker = %q, want %q", response[0], marker)
		}
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("active tunnel handler did not finish")
		}
	}

	roundTrip('A')
	roundTrip('B')

	rejected := make(chan struct{})
	tlsInspectionRuntimeHandleTCPConn = func(conn net.Conn, _ *C.Metadata) {
		defer close(rejected)
		_ = conn.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialTLSInspectionRuntime(ctx, "tcp", "api.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); err == nil {
		_ = conn.Close()
		t.Fatal("current tunnel rejection was ignored")
	}
	_ = conn.Close()
	select {
	case <-rejected:
	case <-ctx.Done():
		t.Fatal("rejection handler did not finish")
	}
}

func TestTLSInspectionRuntimeDialFollowsLiveMihomoRules(t *testing.T) {
	originalHandler := tlsInspectionRuntimeHandleTCPConn
	originalMode := tunnel.Mode()
	originalStatus := tunnel.Status()
	originalRules := append([]C.Rule(nil), tunnel.Rules()...)
	originalProxies := make(map[string]C.Proxy, len(tunnel.Proxies()))
	for name, proxy := range tunnel.Proxies() {
		originalProxies[name] = proxy
	}
	t.Cleanup(func() {
		tlsInspectionRuntimeHandleTCPConn = originalHandler
		tunnel.UpdateRules(originalRules, nil, nil)
		tunnel.UpdateProxies(originalProxies, nil)
		tunnel.SetMode(originalMode)
		switch originalStatus {
		case tunnel.Running:
			tunnel.OnRunning()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		default:
			tunnel.OnSuspend()
		}
	})

	routeA, proxyA := newTLSInspectionRouteProxy("RUNTIME-A", 'A')
	routeB, proxyB := newTLSInspectionRouteProxy("RUNTIME-B", 'B')
	reject := A.NewProxy(O.NewReject())
	tunnel.UpdateProxies(map[string]C.Proxy{
		"RUNTIME-A": proxyA,
		"RUNTIME-B": proxyB,
		"REJECT":    reject,
	}, nil)
	tunnel.SetMode(tunnel.Rule)
	tunnel.OnInnerLoading()
	tlsInspectionRuntimeHandleTCPConn = tunnel.Tunnel.HandleTCPConn

	setRoute := func(target string) {
		t.Helper()
		rule, err := R.ParseRule("DOMAIN", "api.example.com", target, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		fallback, err := R.ParseRule("MATCH", "", "REJECT", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		tunnel.UpdateRules([]C.Rule{rule, fallback}, nil, nil)
	}

	roundTrip := func(route *tlsInspectionRouteAdapter, expected byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := dialTLSInspectionRuntime(ctx, "tcp", "api.example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 1)
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatal(err)
		}
		if response[0] != expected {
			t.Fatalf("routed marker = %q, want %q", response[0], expected)
		}
		select {
		case metadata := <-route.metadata:
			if metadata.Type != C.INNER || metadata.Host != "api.example.com" ||
				metadata.DstPort != 443 || metadata.SourceValid() || metadata.Uid != 0 ||
				metadata.Process != "" || metadata.ProcessPath != "" {
				t.Fatalf("runtime route invented external process identity: %+v", metadata)
			}
		case <-ctx.Done():
			t.Fatal("selected Mihomo proxy did not receive runtime metadata")
		}
	}

	setRoute("RUNTIME-A")
	roundTrip(routeA, 'A')
	setRoute("RUNTIME-B")
	roundTrip(routeB, 'B')

	setRoute("REJECT")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialTLSInspectionRuntime(ctx, "tcp", "api.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte{1})
	response := make([]byte, 1)
	if _, err := conn.Read(response); err == nil {
		t.Fatal("Mihomo REJECT rule was ignored by the runtime route")
	}
}

func TestTLSInspectionRuntimeDialRejectsNonTCPAndMalformedTargets(t *testing.T) {
	for _, test := range []struct {
		network string
		address string
	}{
		{network: "udp", address: "api.example.com:443"},
		{network: "tcp", address: "api.example.com"},
		{network: "tcp", address: "api.example.com:70000"},
	} {
		conn, err := dialTLSInspectionRuntime(context.Background(), test.network, test.address)
		if conn != nil || err == nil {
			t.Fatalf("dial(%q, %q) = (%v, %v), want rejection", test.network, test.address, conn, err)
		}
	}
}

func TestTLSInspectionRuntimeCancellationTombstonesStayBoundedAndTargeted(t *testing.T) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	original := tlsInspectionRuntimeCancelled
	defer func() { tlsInspectionRuntimeCancelled = original }()
	resetTLSInspectionRuntimeCancellationsLocked()
	now := time.Now()
	for index := 0; index < tlsInspectionRuntimeCancellationLimit; index++ {
		id := strings.Repeat("0", 30) + fmt.Sprintf("%02x", index)
		rememberTLSInspectionRuntimeCancellationLocked(id, now.Add(time.Duration(index)*time.Millisecond))
	}
	target := strings.Repeat("f", 32)
	rememberTLSInspectionRuntimeCancellationLocked(target, now.Add(time.Second))
	if len(tlsInspectionRuntimeCancelled) != tlsInspectionRuntimeCancellationLimit {
		t.Fatalf("tombstone count = %d, want %d", len(tlsInspectionRuntimeCancelled), tlsInspectionRuntimeCancellationLimit)
	}
	if _, ok := tlsInspectionRuntimeCancelled[target]; !ok {
		t.Fatal("latest requested identity was not retained")
	}
	if _, ok := tlsInspectionRuntimeCancelled[strings.Repeat("0", 32)]; ok {
		t.Fatal("oldest tombstone was not evicted")
	}
	unrelated := strings.Repeat("e", 32)
	if _, cancelled := tlsInspectionRuntimeCancelled[unrelated]; cancelled {
		t.Fatal("unrelated identity was cancelled")
	}
}

func TestTLSInspectionRuntimeCancellationPrunesExpiredEntries(t *testing.T) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	original := tlsInspectionRuntimeCancelled
	defer func() { tlsInspectionRuntimeCancelled = original }()
	now := time.Now()
	tlsInspectionRuntimeCancelled = map[string]time.Time{
		strings.Repeat("a", 32): now.Add(-time.Second),
		strings.Repeat("b", 32): now.Add(time.Second),
	}
	pruneTLSInspectionRuntimeCancellationsLocked(now)
	if len(tlsInspectionRuntimeCancelled) != 1 {
		t.Fatalf("tombstone count = %d, want 1", len(tlsInspectionRuntimeCancelled))
	}
	if _, ok := tlsInspectionRuntimeCancelled[strings.Repeat("b", 32)]; !ok {
		t.Fatal("live tombstone was pruned")
	}
}
