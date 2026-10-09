package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"time"

	"core/inspectionruntime"
	"github.com/metacubex/mihomo/component/observer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

type TLSInspectionRuntimeStartParams struct {
	ID                         string `json:"id"`
	Confirm                    bool   `json:"confirm"`
	AuthorityGeneration        string `json:"authorityGeneration"`
	AuthorityFingerprintSHA256 string `json:"authorityFingerprintSha256"`
	PolicyDigest               string `json:"policyDigest"`
	RuntimeProofID             string `json:"runtimeProofId"`
}

type TLSInspectionRuntimeStopParams struct {
	ID string `json:"id"`
}

type TLSInspectionRuntimeStatus struct {
	Runtime                    inspectionruntime.Status        `json:"runtime"`
	Generation                 string                          `json:"generation"`
	AuthorityFingerprintSHA256 string                          `json:"authorityFingerprintSha256"`
	PolicyDigest               string                          `json:"policyDigest"`
	RuntimeProofID             string                          `json:"runtimeProofId,omitempty"`
	Mode                       string                          `json:"mode"`
	Capacity                   int                             `json:"capacity"`
	ConnectionLifetimeSeconds  int64                           `json:"connectionLifetimeSeconds"`
	CapturesPayload            bool                            `json:"capturesPayload"`
	CapturePolicy              inspectionruntime.CapturePolicy `json:"capturePolicy"`
	ChangesSystemProxy         bool                            `json:"changesSystemProxy"`
}

type TLSInspectionRuntimeStartResult struct {
	Status   TLSInspectionRuntimeStatus `json:"status"`
	Username string                     `json:"username"`
	Password string                     `json:"password"`
}

var tlsInspectionRuntime *inspectionruntime.Runtime
var tlsInspectionRuntimeBinding TLSInspectionRuntimeStartParams

const tlsInspectionRuntimeCancellationLimit = 128

var tlsInspectionRuntimeCancelled = make(map[string]time.Time)
var tlsInspectionRuntimeDialSlots = make(chan struct{}, inspectionruntime.MaxClients)
var tlsInspectionRuntimeHandleTCPConn = tunnel.Tunnel.HandleTCPConn

func pruneTLSInspectionRuntimeCancellationsLocked(now time.Time) {
	for id, expiry := range tlsInspectionRuntimeCancelled {
		if !expiry.After(now) {
			delete(tlsInspectionRuntimeCancelled, id)
		}
	}
}

func rememberTLSInspectionRuntimeCancellationLocked(id string, now time.Time) {
	pruneTLSInspectionRuntimeCancellationsLocked(now)
	if len(tlsInspectionRuntimeCancelled) >= tlsInspectionRuntimeCancellationLimit {
		var oldestID string
		var oldestExpiry time.Time
		for candidate, expiry := range tlsInspectionRuntimeCancelled {
			if oldestID == "" || expiry.Before(oldestExpiry) {
				oldestID = candidate
				oldestExpiry = expiry
			}
		}
		delete(tlsInspectionRuntimeCancelled, oldestID)
	}
	tlsInspectionRuntimeCancelled[id] = now.Add(inspectionruntime.SessionLifetime)
}

func resetTLSInspectionRuntimeCancellationsLocked() {
	tlsInspectionRuntimeCancelled = make(map[string]time.Time)
}

func stopTLSInspectionRuntimeLocked() {
	if tlsInspectionRuntime != nil {
		tlsInspectionRuntime.Stop()
		tlsInspectionRuntime = nil
	}
	tlsInspectionRuntimeBinding = TLSInspectionRuntimeStartParams{}
}

func tlsInspectionRuntimeStatusLocked() TLSInspectionRuntimeStatus {
	policy := currentHTTPObservationPolicy()
	result := TLSInspectionRuntimeStatus{
		Runtime: inspectionruntime.Status{State: "stopped"},
		Mode:    "loopback-connect-http1-h2", Capacity: inspectionruntime.MaxClients,
		ConnectionLifetimeSeconds: int64(inspectionruntime.ConnectionLifetime / time.Second),
		CapturesPayload:           policy.BodyMode != inspectionruntime.CaptureBodyNone,
		CapturePolicy:             policy,
	}
	if tlsInspectionRuntime != nil {
		result.Runtime = tlsInspectionRuntime.Status()
		result.Generation = tlsInspectionRuntimeBinding.AuthorityGeneration
		result.AuthorityFingerprintSHA256 = tlsInspectionRuntimeBinding.AuthorityFingerprintSHA256
		result.PolicyDigest = tlsInspectionRuntimeBinding.PolicyDigest
		result.RuntimeProofID = tlsInspectionRuntimeBinding.RuntimeProofID
	}
	return result
}

func getTLSInspectionRuntimeStatus() TLSInspectionRuntimeStatus {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	if tlsInspectionRuntime != nil && !getTLSInspectionLeafCacheStatusLocked().Ready {
		stopTLSInspectionRuntimeLocked()
	}
	return tlsInspectionRuntimeStatusLocked()
}

func startTLSInspectionRuntime(params *TLSInspectionRuntimeStartParams) (*TLSInspectionRuntimeStartResult, *MethodError) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	if params == nil || !params.Confirm || !validTLSInspectionGeneration(params.ID) || strings.ToLower(params.ID) != params.ID {
		return nil, &MethodError{Code: "runtime_confirmation_required", Message: "runtime requires an explicit confirmed identity"}
	}
	pruneTLSInspectionRuntimeCancellationsLocked(time.Now())
	if _, cancelled := tlsInspectionRuntimeCancelled[params.ID]; cancelled {
		return nil, &MethodError{Code: "runtime_start_cancelled", Message: "runtime start was cancelled"}
	}
	if !isRunning.Load() {
		return nil, &MethodError{Code: "runtime_core_not_running", Message: "start the configured Core before inspection"}
	}
	status := getTLSInspectionLeafCacheStatusLocked()
	if !status.Ready || params.AuthorityGeneration != status.Generation || params.AuthorityFingerprintSHA256 != status.AuthorityFingerprintSHA256 || params.PolicyDigest != status.PolicyDigest || params.RuntimeProofID != status.RuntimeProofID {
		return nil, &MethodError{Code: "runtime_not_authorized", Message: "current authority, trust and allowlist preparation are required"}
	}
	if tlsInspectionRuntime != nil && tlsInspectionRuntime.Status().State == "running" {
		return nil, &MethodError{Code: "runtime_already_running", Message: "stop the current runtime before starting another"}
	}
	stopTLSInspectionRuntimeLocked()
	var active *inspectionruntime.Runtime
	var password string
	var err error
	active, password, err = inspectionruntime.Start(inspectionruntime.Config{
		ID: params.ID,
		Authorize: func(ctx context.Context, host string) error {
			tlsInspectionAuthorityMu.Lock()
			defer tlsInspectionAuthorityMu.Unlock()
			return authorizeTLSInspectionRuntimeLocked(ctx, active, host)
		},
		Leaf: func(ctx context.Context, host string) (*tls.Certificate, error) {
			return loadTLSInspectionRuntimeLeaf(ctx, active, host)
		},
		Dial: dialTLSInspectionRuntime,
		CaptureSession: func() string {
			if !observer.Enabled() {
				return ""
			}
			return observer.SessionID()
		},
		CaptureSessionChanged: httpObservationChangeSignal,
		CapturePolicy:         currentHTTPObservationPolicy,
		Observe: func(value inspectionruntime.Observation) {
			sendMessage(Message{Type: InspectionRuntimeMessage, Data: value})
		},
	})
	if err != nil {
		return nil, &MethodError{Code: "runtime_start_failed", Message: "local inspection listener could not start"}
	}
	tlsInspectionRuntime = active
	tlsInspectionRuntimeBinding = *params
	return &TLSInspectionRuntimeStartResult{Status: tlsInspectionRuntimeStatusLocked(), Username: "flclash", Password: password}, nil
}

func stopTLSInspectionRuntime(params *TLSInspectionRuntimeStopParams) (bool, *MethodError) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	if params == nil || !validTLSInspectionGeneration(params.ID) || strings.ToLower(params.ID) != params.ID {
		return false, &MethodError{Code: "runtime_identity_required", Message: "runtime stop requires the requested identity"}
	}
	rememberTLSInspectionRuntimeCancellationLocked(params.ID, time.Now())
	if tlsInspectionRuntime != nil && tlsInspectionRuntime.Status().ID == params.ID {
		stopTLSInspectionRuntimeLocked()
	}
	return true, nil
}

func authorizeTLSInspectionRuntimeLocked(ctx context.Context, active *inspectionruntime.Runtime, host string) error {
	if ctx.Err() != nil || active == nil || tlsInspectionRuntime != active || tlsInspectionLeafSession == nil {
		return errors.New("inspection runtime authorization revoked")
	}
	binding := tlsInspectionRuntimeBinding
	policy := tlsInspectionLeafSession
	if policy.Generation != binding.AuthorityGeneration || policy.Digest != binding.PolicyDigest || policy.AuthorityFingerprintSHA256 != binding.AuthorityFingerprintSHA256 {
		return errors.New("inspection runtime policy changed")
	}
	analysis, err := analyzeTLSInspectionLeafDomain(host)
	if err != nil || analysis.IsIP || analysis.RegistrableDomain == "" || analysis.NormalizedHost == analysis.PublicSuffix || analysis.NormalizedHost != host || !tlsInspectionLeafPolicyAllows(policy, host) {
		return errors.New("inspection runtime target not allowed")
	}
	status := getTLSInspectionLeafCacheStatusLocked()
	if !status.Ready || status.Generation != binding.AuthorityGeneration || status.PolicyDigest != binding.PolicyDigest || status.AuthorityFingerprintSHA256 != binding.AuthorityFingerprintSHA256 || status.RuntimeProofID != binding.RuntimeProofID {
		return errors.New("inspection runtime authority unavailable")
	}
	return nil
}

func loadTLSInspectionRuntimeLeaf(ctx context.Context, active *inspectionruntime.Runtime, host string) (*tls.Certificate, error) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	if err := authorizeTLSInspectionRuntimeLocked(ctx, active, host); err != nil {
		return nil, err
	}
	binding := tlsInspectionRuntimeBinding
	_, failure := prepareTLSInspectionLeafCertificateLocked(&TLSInspectionLeafPrepareParams{
		Host: host, AuthorityGeneration: binding.AuthorityGeneration,
		AuthorityFingerprintSHA256: binding.AuthorityFingerprintSHA256, PolicyDigest: binding.PolicyDigest,
	})
	if failure != nil {
		return nil, errors.New("inspection leaf unavailable")
	}
	_, authority, _, err := readTLSInspectionAuthoritySigningMaterialLocked()
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, errors.New("inspection authority unavailable")
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		return nil, errors.New("inspection cache unavailable")
	}
	entry, err := loadTLSInspectionLeafEntry(filepath.Join(tlsInspectionLeafEntriesRoot(root, binding.AuthorityGeneration), tlsInspectionLeafCacheKey(host)), tlsInspectionLeafSession, authority)
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, errors.New("inspection leaf invalid")
	}
	return &tls.Certificate{Certificate: [][]byte{entry.Certificate.Raw}, PrivateKey: entry.PrivateKey, Leaf: entry.Certificate}, nil
}

func dialTLSInspectionRuntime(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("inspection runtime requires TCP")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || host != strings.ToLower(host) ||
		net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return nil, errors.New("inspection runtime requires a normalized DNS host on port 443")
	}
	select {
	case tlsInspectionRuntimeDialSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, errors.New("inspection routed connection limit reached")
	}
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER}
	if err := metadata.SetRemoteAddress(address); err != nil {
		<-tlsInspectionRuntimeDialSlots
		return nil, errors.New("invalid inspection route")
	}
	client, inbound := net.Pipe()
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = inbound.Close() })
	safeGoDetached("inspection-runtime-route", func() {
		defer func() { stop(); _ = client.Close(); _ = inbound.Close(); <-tlsInspectionRuntimeDialSlots }()
		tlsInspectionRuntimeHandleTCPConn(inbound, metadata)
	})
	return client, nil
}

func init() {
	registerMethod(getTLSInspectionRuntimeStatusMethod, withoutArguments(func(response MethodResponse) { response.success(getTLSInspectionRuntimeStatus()) }))
	registerMethod(startTLSInspectionRuntimeMethod, withArguments(func(params *TLSInspectionRuntimeStartParams, response MethodResponse) {
		value, failure := startTLSInspectionRuntime(params)
		if failure != nil {
			response.failure(failure.Code, failure.Message, nil)
			return
		}
		response.success(value)
	}))
	registerMethod(stopTLSInspectionRuntimeMethod, withArguments(func(params *TLSInspectionRuntimeStopParams, response MethodResponse) {
		value, failure := stopTLSInspectionRuntime(params)
		if failure != nil {
			response.failure(failure.Code, failure.Message, nil)
			return
		}
		response.success(value)
	}))
}
