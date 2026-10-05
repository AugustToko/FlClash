package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func handshakeTestPolicy(t *testing.T) *TLSInspectionLeafPrepareParams {
	t.Helper()
	tlsInspectionAuthorityMu.Lock()
	previous := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	resetTLSInspectionLeafPolicySession()
	tlsInspectionAuthorityMu.Unlock()
	t.Cleanup(func() {
		tlsInspectionAuthorityMu.Lock()
		defer tlsInspectionAuthorityMu.Unlock()
		resetTLSInspectionLeafPolicySession()
		C.SetHomeDir(previous)
	})
	authority, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatal(failure.Code)
	}
	policy, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{
		Enabled:                    true,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		RiskVersion:                tlsInspectionLeafRiskVersion,
		TrustSatisfied:             true,
		Allowlist:                  []TLSInspectionLeafRule{{Host: "example.com", Scope: "subdomains"}},
		Exclusions:                 []TLSInspectionLeafRule{{Host: "accounts.example.com", Scope: "exact"}},
	})
	if failure != nil {
		t.Fatal(failure.Code)
	}
	return &TLSInspectionLeafPrepareParams{
		Host:                       "api.example.com",
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		PolicyDigest:               policy.PolicyDigest,
		VerifyHandshake:            true,
	}
}

func TestTLSInspectionHandshakePreparation(t *testing.T) {
	params := handshakeTestPolicy(t)
	first, failure := prepareTLSInspectionLeafCertificate(params)
	if failure != nil {
		t.Fatal(failure.Code)
	}
	if !first.HandshakeVerified || first.CacheHit || first.HandshakeScope != "in-memory-only" || first.HandshakeALPN != "http/1.1" || !reflect.DeepEqual(first.HandshakeVersions, []string{"TLS 1.2", "TLS 1.3"}) {
		t.Fatalf("unexpected local handshake result: %+v", first)
	}
	if first.HandshakeDurationMs < 0 || first.HandshakeDurationMs > 5000 {
		t.Fatalf("unbounded handshake duration: %d", first.HandshakeDurationMs)
	}
	second, failure := prepareTLSInspectionLeafCertificate(params)
	if failure != nil || !second.CacheHit || !second.HandshakeVerified || second.FingerprintSHA256 != first.FingerprintSHA256 {
		t.Fatalf("cached leaf handshake was not revalidated: result=%+v failure=%+v", second, failure)
	}
	encoded, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"BEGIN", "PRIVATE KEY", "CERTIFICATE", "challenge", "leaf-key.pem", "authority-key.pem"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("handshake response contains forbidden material %q", secret)
		}
	}
}

func TestTLSInspectionHandshakeIsExplicit(t *testing.T) {
	params := handshakeTestPolicy(t)
	params.VerifyHandshake = false
	result, failure := prepareTLSInspectionLeafCertificate(params)
	if failure != nil {
		t.Fatal(failure.Code)
	}
	if result.HandshakeVerified || result.HandshakeVersions != nil || result.HandshakeScope != "" || result.HandshakeALPN != "" {
		t.Fatal("ordinary leaf issuance must not claim handshake verification")
	}
}

func TestTLSInspectionHandshakeCannotBroadenPolicy(t *testing.T) {
	params := handshakeTestPolicy(t)
	for _, host := range []string{"accounts.example.com", "unrelated.net", "127.0.0.1", "*.example.com", "co.uk"} {
		t.Run(host, func(t *testing.T) {
			request := *params
			request.Host = host
			if result, failure := prepareTLSInspectionLeafCertificate(&request); failure == nil || result != nil {
				t.Fatalf("unauthorized handshake host was accepted: %s", host)
			}
		})
	}
}

func TestTLSInspectionHandshakeRejectsStaleAuthorization(t *testing.T) {
	params := handshakeTestPolicy(t)
	if _, failure := rotateTLSInspectionAuthority(true); failure != nil {
		t.Fatal(failure.Code)
	}
	if result, failure := prepareTLSInspectionLeafCertificate(params); failure == nil || result != nil {
		t.Fatal("rotated authority accepted stale handshake authorization")
	}
}

func handshakeTestMaterial(t *testing.T) (*tlsInspectionLeafEntry, *x509.Certificate) {
	t.Helper()
	params := handshakeTestPolicy(t)
	params.VerifyHandshake = false
	result, failure := prepareTLSInspectionLeafCertificate(params)
	if failure != nil {
		t.Fatal(failure.Code)
	}
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	_, authority, _, err := readTLSInspectionAuthoritySigningMaterialLocked()
	if err != nil {
		t.Fatal(err)
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entryRoot := filepath.Join(tlsInspectionLeafEntriesRoot(root, result.Generation), tlsInspectionLeafCacheKey(result.Host))
	entry, err := loadTLSInspectionLeafEntry(entryRoot, tlsInspectionLeafSession, authority)
	if err != nil {
		t.Fatal(err)
	}
	return entry, authority
}

func TestTLSInspectionHandshakeNegotiatesBothVersions(t *testing.T) {
	entry, authority := handshakeTestMaterial(t)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := verifyTLSInspectionHandshakeVersion(ctx, entry, authority, version); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSInspectionHandshakeRejectsWrongHost(t *testing.T) {
	entry, authority := handshakeTestMaterial(t)
	entry.Metadata.Host = "other.example.com"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := verifyTLSInspectionLeafHandshake(ctx, entry, authority); err == nil {
		t.Fatal("local handshake accepted a certificate for another host")
	}
}

func TestTLSInspectionHandshakeRejectsWrongKey(t *testing.T) {
	entry, authority := handshakeTestMaterial(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry.PrivateKey = key
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := verifyTLSInspectionLeafHandshake(ctx, entry, authority); err == nil {
		t.Fatal("local handshake accepted a different private key")
	}
}

func TestTLSInspectionHandshakeRejectsUnrelatedAuthority(t *testing.T) {
	entry, _ := handshakeTestMaterial(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Unrelated test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := verifyTLSInspectionLeafHandshake(ctx, entry, authority); err == nil {
		t.Fatal("local handshake accepted an unrelated root")
	}
}

func TestTLSInspectionHandshakeCancellation(t *testing.T) {
	entry, authority := handshakeTestMaterial(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyTLSInspectionLeafHandshake(ctx, entry, authority); err != context.Canceled {
		t.Fatalf("cancelled handshake returned %v", err)
	}
}

func TestTLSInspectionHandshakeMissingMaterial(t *testing.T) {
	if err := verifyTLSInspectionLeafHandshake(context.Background(), nil, nil); err == nil {
		t.Fatal("missing signing material was accepted")
	}
}

func TestTLSInspectionHandshakeFailureRevokesAuthorization(t *testing.T) {
	entry, authority := handshakeTestMaterial(t)
	entry.Metadata.Host = "wrong.example.com"
	tlsInspectionAuthorityMu.Lock()
	result, failure := completeTLSInspectionLeafPreparation(entry, true, authority, true)
	revoked := tlsInspectionLeafSession == nil
	tlsInspectionAuthorityMu.Unlock()
	if result != nil || failure == nil || failure.Code != "leaf_handshake_failed" || !revoked {
		t.Fatalf("failed local handshake did not revoke authorization: %v", failure)
	}
	if strings.Contains(failure.Message, entry.Metadata.Host) {
		t.Fatal("handshake error exposed raw certificate details")
	}
}
