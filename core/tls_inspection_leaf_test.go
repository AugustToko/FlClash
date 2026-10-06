package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func requireTLSInspectionLeafAuthority(t *testing.T) *TLSInspectionAuthorityStatus {
	t.Helper()
	withTLSInspectionHome(t)
	status, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatalf("create authority: %#v", failure)
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows authority remains fail-closed until DACL verification is implemented")
	}
	if !status.Ready {
		t.Fatalf("authority is not ready: %#v", status)
	}
	return status
}

func configureTLSInspectionLeafTestPolicy(
	t *testing.T,
	authority *TLSInspectionAuthorityStatus,
	allowlist []TLSInspectionLeafRule,
	exclusions []TLSInspectionLeafRule,
) *TLSInspectionLeafCacheStatus {
	t.Helper()
	status, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{
		Enabled:                    true,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		RiskVersion:                tlsInspectionLeafRiskVersion,
		TrustSatisfied:             true,
		Allowlist:                  allowlist,
		Exclusions:                 exclusions,
	})
	if failure != nil {
		t.Fatalf("configure leaf policy: %#v", failure)
	}
	if !status.Ready || status.State != "ready" || status.PolicyDigest == "" || !validTLSInspectionGeneration(status.RuntimeProofID) {
		t.Fatalf("leaf cache status = %#v", status)
	}
	return status
}

func prepareTLSInspectionLeafTestCertificate(
	t *testing.T,
	authority *TLSInspectionAuthorityStatus,
	policy *TLSInspectionLeafCacheStatus,
	host string,
) *TLSInspectionLeafCertificateStatus {
	t.Helper()
	status, failure := prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{
		Host:                       host,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		PolicyDigest:               policy.PolicyDigest,
	})
	if failure != nil {
		t.Fatalf("prepare leaf certificate for %q: %#v", host, failure)
	}
	return status
}

func TestTLSInspectionLeafPolicyAndCertificateLifecycle(t *testing.T) {
	authorityStatus := requireTLSInspectionLeafAuthority(t)
	policyStatus := configureTLSInspectionLeafTestPolicy(
		t,
		authorityStatus,
		[]TLSInspectionLeafRule{
			{Host: "API.Example.COM.", Scope: "exact"},
			{Host: "example.org", Scope: "subdomains"},
		},
		[]TLSInspectionLeafRule{{Host: "blocked.example.org", Scope: "subdomains"}},
	)
	if policyStatus.EntryCount != 0 ||
		policyStatus.Capacity != tlsInspectionLeafMaxEntries ||
		policyStatus.LeafValiditySeconds != int64(tlsInspectionLeafValidity/time.Second) ||
		policyStatus.PrivateKeysExported ||
		!policyStatus.RuntimeAuthorizationPresent ||
		!policyStatus.KeyPermissionsRestricted {
		t.Fatalf("unexpected initial status: %#v", policyStatus)
	}

	created := prepareTLSInspectionLeafTestCertificate(t, authorityStatus, policyStatus, "Api.Example.COM.")
	if created.CacheHit ||
		created.Host != "api.example.com" ||
		created.PrivateKeyExported ||
		created.Generation != authorityStatus.Generation ||
		created.AuthorityFingerprintSHA256 != authorityStatus.FingerprintSHA256 ||
		created.PolicyDigest != policyStatus.PolicyDigest ||
		created.Algorithm != "ECDSA P-256 / SHA-256" ||
		created.KeyStorage != "app-data-file" {
		t.Fatalf("created leaf = %#v", created)
	}
	reused := prepareTLSInspectionLeafTestCertificate(t, authorityStatus, policyStatus, "api.example.com")
	if !reused.CacheHit || reused.SerialNumber != created.SerialNumber || reused.FingerprintSHA256 != created.FingerprintSHA256 {
		t.Fatalf("cached leaf changed: %#v -> %#v", created, reused)
	}

	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entryRoot := filepath.Join(
		tlsInspectionLeafEntriesRoot(root, authorityStatus.Generation),
		tlsInspectionLeafCacheKey(created.Host),
	)
	certificatePEM, err := os.ReadFile(filepath.Join(entryRoot, tlsInspectionLeafCertFile))
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, rest := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatal("invalid cached leaf certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	authorityPEM, err := os.ReadFile(filepath.Join(
		tlsInspectionGenerationPath(root, authorityStatus.Generation),
		tlsInspectionCertFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	authorityBlock, _ := pem.Decode(authorityPEM)
	authorityCertificate, err := x509.ParseCertificate(authorityBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.CheckSignatureFrom(authorityCertificate); err != nil {
		t.Fatalf("leaf signature: %v", err)
	}
	if certificate.IsCA ||
		certificate.Subject.CommonName != created.Host ||
		len(certificate.DNSNames) != 1 ||
		certificate.DNSNames[0] != created.Host ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		certificate.NotAfter.Sub(certificate.NotBefore) > tlsInspectionLeafValidity {
		t.Fatalf("unsafe leaf certificate: %#v", certificate)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authorityCertificate)
	if _, err := certificate.Verify(x509.VerifyOptions{
		DNSName:     created.Host,
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("leaf does not form a valid server-auth chain: %v", err)
	}
	privatePEM, err := os.ReadFile(filepath.Join(entryRoot, tlsInspectionLeafKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := parseTLSInspectionLeafPrivateKey(privatePEM)
	if err != nil || privateKey.Curve != elliptic.P256() {
		t.Fatalf("leaf key = %#v, %v", privateKey, err)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.X.Cmp(privateKey.X) != 0 || publicKey.Y.Cmp(privateKey.Y) != 0 {
		t.Fatal("cached leaf key pair does not match")
	}
	if info, err := os.Stat(filepath.Join(entryRoot, tlsInspectionLeafKeyFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("leaf key mode = %#v, %v", info, err)
	}

	for _, testCase := range []struct {
		host string
		code string
	}{
		{host: "blocked.example.org", code: "domain_not_allowed"},
		{host: "deep.blocked.example.org", code: "domain_not_allowed"},
		{host: "unlisted.example.net", code: "domain_not_allowed"},
		{host: "co.uk", code: "invalid_domain"},
		{host: "127.0.0.1", code: "invalid_domain"},
		{host: "https://api.example.com/private", code: "invalid_domain"},
		{host: "api.example.com:443", code: "invalid_domain"},
	} {
		_, failure := prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{
			Host:                       testCase.host,
			AuthorityGeneration:        authorityStatus.Generation,
			AuthorityFingerprintSHA256: authorityStatus.FingerprintSHA256,
			PolicyDigest:               policyStatus.PolicyDigest,
		})
		if failure == nil || failure.Code != testCase.code {
			t.Fatalf("prepare %q failure = %#v", testCase.host, failure)
		}
	}

	current := getTLSInspectionLeafCacheStatus()
	if !current.Ready || current.EntryCount != 1 {
		t.Fatalf("leaf cache after issuance = %#v", current)
	}
	disabled, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{Enabled: false})
	if failure != nil || disabled.State != "disabled" || disabled.Ready {
		t.Fatalf("disable result = %#v, %#v", disabled, failure)
	}
	if _, err := os.Stat(tlsInspectionLeafCacheRoot(root, authorityStatus.Generation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leaf cache survived disable: %v", err)
	}
	_, failure = prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{Host: created.Host})
	if failure == nil || failure.Code != "leaf_policy_not_configured" {
		t.Fatalf("prepare after disable = %#v", failure)
	}
}

func rewriteTLSInspectionLeafAsNearExpiry(
	t *testing.T,
	authorityStatus *TLSInspectionAuthorityStatus,
	leafStatus *TLSInspectionLeafCertificateStatus,
) {
	t.Helper()
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entryRoot := filepath.Join(
		tlsInspectionLeafEntriesRoot(root, authorityStatus.Generation),
		tlsInspectionLeafCacheKey(leafStatus.Host),
	)
	privatePEM, err := os.ReadFile(filepath.Join(entryRoot, tlsInspectionLeafKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := parseTLSInspectionLeafPrivateKey(privatePEM)
	if err != nil {
		t.Fatal(err)
	}

	tlsInspectionAuthorityMu.Lock()
	_, authority, authorityKey, err := readTLSInspectionAuthoritySigningMaterialLocked()
	tlsInspectionAuthorityMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	serial, err := tlsInspectionLeafSerial()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   leafStatus.Host,
			Organization: []string{"FlClash"},
		},
		NotBefore:             now.Add(-tlsInspectionLeafClockSkew),
		NotAfter:              now.Add(tlsInspectionLeafRenewBefore / 2),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{leafStatus.Host},
		SubjectKeyId:          make([]byte, 20),
		AuthorityKeyId:        append([]byte(nil), authority.SubjectKeyId...),
	}
	if _, err := rand.Read(template.SubjectKeyId); err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		authority,
		&privateKey.PublicKey,
		authorityKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(entryRoot, tlsInspectionLeafMetadataFile)
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata tlsInspectionLeafMetadata
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata.FingerprintSHA256 = tlsInspectionFingerprint(certificate.Raw)
	metadata.SerialNumber = strings.ToUpper(certificate.SerialNumber.Text(16))
	metadata.NotBefore = certificate.NotBefore.UTC()
	metadata.NotAfter = certificate.NotAfter.UTC()
	metadata.CreatedAt = now
	metadata.LastUsedAt = now
	metadataData, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTLSInspectionFile(
		filepath.Join(entryRoot, tlsInspectionLeafCertFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := writeTLSInspectionFile(metadataPath, metadataData, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTLSInspectionLeafNearExpiryEntryIsReissued(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	created := prepareTLSInspectionLeafTestCertificate(t, authority, policy, "api.example.com")
	rewriteTLSInspectionLeafAsNearExpiry(t, authority, created)

	reissued := prepareTLSInspectionLeafTestCertificate(t, authority, policy, "api.example.com")
	if reissued.CacheHit || reissued.FingerprintSHA256 == created.FingerprintSHA256 {
		t.Fatalf("near-expiry leaf was reused: %#v", reissued)
	}
	if !reissued.NotAfter.After(time.Now().UTC().Add(tlsInspectionLeafRenewBefore)) {
		t.Fatalf("reissued leaf expires too soon: %#v", reissued)
	}
}

func TestTLSInspectionLeafStatusIntegrityFailureRevokesRuntimeAuthorization(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		tlsInspectionLeafPolicyPath(root, authority.Generation),
		[]byte("{invalid"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	status := getTLSInspectionLeafCacheStatus()
	if status.Ready || status.RuntimeAuthorizationPresent || tlsInspectionLeafSession != nil {
		t.Fatalf("integrity failure retained runtime authorization: %#v", status)
	}
	_, failure := prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{
		Host:                       "api.example.com",
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		PolicyDigest:               policy.PolicyDigest,
	})
	if failure == nil || failure.Code != "leaf_policy_not_configured" {
		t.Fatalf("issuance remained available after integrity failure: %#v", failure)
	}
}

func TestTLSInspectionLeafReconfigurationFailureRevokesRuntimeAuthorization(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics are required for this failure injection")
	}
	authority := requireTLSInspectionLeafAuthority(t)
	configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "first.example.com", Scope: "exact"}},
		nil,
	)
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	generationRoot := tlsInspectionGenerationPath(root, authority.Generation)
	if err := os.Chmod(generationRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(generationRoot, 0o700); err != nil {
			t.Errorf("restore generation permissions: %v", err)
		}
	}()

	_, failure := configureTLSInspectionLeafPolicy(&TLSInspectionLeafPolicyParams{
		Enabled:                    true,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		RiskVersion:                tlsInspectionLeafRiskVersion,
		TrustSatisfied:             true,
		Allowlist:                  []TLSInspectionLeafRule{{Host: "second.example.com", Scope: "exact"}},
	})
	if failure == nil {
		t.Fatal("reconfiguration unexpectedly succeeded with a non-writable generation")
	}
	if tlsInspectionLeafSession != nil {
		t.Fatal("failed reconfiguration retained the previous runtime authorization")
	}
}

func TestTLSInspectionLeafSymlinkedCacheRootRevokesRuntimeAuthorization(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic-link permissions differ on Windows")
	}
	authority := requireTLSInspectionLeafAuthority(t)
	configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	cacheRoot := tlsInspectionLeafCacheRoot(root, authority.Generation)
	if err := os.RemoveAll(cacheRoot); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	marker := filepath.Join(external, "must-not-be-touched")
	if err := os.WriteFile(marker, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, cacheRoot); err != nil {
		t.Fatal(err)
	}

	status := getTLSInspectionLeafCacheStatus()
	if status.Ready || status.RuntimeAuthorizationPresent || tlsInspectionLeafSession != nil {
		t.Fatalf("symlinked cache root retained runtime authorization: %#v", status)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "safe" {
		t.Fatalf("external symlink target was modified: %q, %v", data, err)
	}
}

func TestTLSInspectionLeafSymlinkedEntriesRootRevokesRuntimeAuthorization(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic-link permissions differ on Windows")
	}
	authority := requireTLSInspectionLeafAuthority(t)
	configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entriesRoot := tlsInspectionLeafEntriesRoot(root, authority.Generation)
	if err := os.RemoveAll(entriesRoot); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	marker := filepath.Join(external, "must-not-be-touched")
	if err := os.WriteFile(marker, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, entriesRoot); err != nil {
		t.Fatal(err)
	}

	status := getTLSInspectionLeafCacheStatus()
	if status.Ready || status.RuntimeAuthorizationPresent || tlsInspectionLeafSession != nil {
		t.Fatalf("symlinked entries root retained runtime authorization: %#v", status)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "safe" {
		t.Fatalf("external symlink target was modified: %q, %v", data, err)
	}
}

func TestTLSInspectionLeafPolicyRejectsUnsafeAuthorization(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	base := TLSInspectionLeafPolicyParams{
		Enabled:                    true,
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		RiskVersion:                tlsInspectionLeafRiskVersion,
		TrustSatisfied:             true,
		Allowlist:                  []TLSInspectionLeafRule{{Host: "example.com", Scope: "exact"}},
	}
	tests := []struct {
		name   string
		mutate func(*TLSInspectionLeafPolicyParams)
	}{
		{name: "trust", mutate: func(value *TLSInspectionLeafPolicyParams) { value.TrustSatisfied = false }},
		{name: "generation", mutate: func(value *TLSInspectionLeafPolicyParams) { value.AuthorityGeneration = strings.Repeat("b", 32) }},
		{name: "fingerprint", mutate: func(value *TLSInspectionLeafPolicyParams) {
			value.AuthorityFingerprintSHA256 = strings.Repeat("BB:", 31) + "BB"
		}},
		{name: "risk", mutate: func(value *TLSInspectionLeafPolicyParams) { value.RiskVersion++ }},
		{name: "empty", mutate: func(value *TLSInspectionLeafPolicyParams) { value.Allowlist = nil }},
		{name: "public suffix", mutate: func(value *TLSInspectionLeafPolicyParams) {
			value.Allowlist = []TLSInspectionLeafRule{{Host: "co.uk", Scope: "exact"}}
		}},
		{name: "IP", mutate: func(value *TLSInspectionLeafPolicyParams) {
			value.Allowlist = []TLSInspectionLeafRule{{Host: "192.0.2.1", Scope: "exact"}}
		}},
		{name: "wildcard", mutate: func(value *TLSInspectionLeafPolicyParams) {
			value.Allowlist = []TLSInspectionLeafRule{{Host: "*.example.com", Scope: "exact"}}
		}},
		{name: "URL", mutate: func(value *TLSInspectionLeafPolicyParams) {
			value.Allowlist = []TLSInspectionLeafRule{{Host: "https://example.com/path", Scope: "exact"}}
		}},
		{name: "port", mutate: func(value *TLSInspectionLeafPolicyParams) {
			value.Allowlist = []TLSInspectionLeafRule{{Host: "example.com:443", Scope: "exact"}}
		}},
		{name: "scope", mutate: func(value *TLSInspectionLeafPolicyParams) {
			value.Allowlist = []TLSInspectionLeafRule{{Host: "example.com", Scope: "wildcard"}}
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			value := base
			value.Allowlist = append([]TLSInspectionLeafRule(nil), base.Allowlist...)
			testCase.mutate(&value)
			_, failure := configureTLSInspectionLeafPolicy(&value)
			if failure == nil || failure.Code != "leaf_policy_invalid" {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}
}

func TestTLSInspectionLeafNormalizesIDNAWithoutIssuingWildcards(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "BÜCHER.Example", Scope: "exact"}},
		nil,
	)
	leaf := prepareTLSInspectionLeafTestCertificate(t, authority, policy, "bücher.example.")
	if leaf.Host != "xn--bcher-kva.example" {
		t.Fatalf("IDNA leaf host = %q", leaf.Host)
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entryRoot := filepath.Join(
		tlsInspectionLeafEntriesRoot(root, authority.Generation),
		tlsInspectionLeafCacheKey(leaf.Host),
	)
	certificatePEM, err := os.ReadFile(filepath.Join(entryRoot, tlsInspectionLeafCertFile))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := parseTLSInspectionLeafCertificate(certificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != leaf.Host || strings.Contains(certificate.DNSNames[0], "*") {
		t.Fatalf("IDNA leaf SANs = %#v", certificate.DNSNames)
	}
}

func TestTLSInspectionLeafConcurrentIssuanceDeduplicates(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	const workers = 16
	results := make(chan *TLSInspectionLeafCertificateStatus, workers)
	failures := make(chan *MethodError, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, failure := prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{
				Host:                       "api.example.com",
				AuthorityGeneration:        authority.Generation,
				AuthorityFingerprintSHA256: authority.FingerprintSHA256,
				PolicyDigest:               policy.PolicyDigest,
			})
			results <- result
			failures <- failure
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	for failure := range failures {
		if failure != nil {
			t.Fatalf("concurrent issuance: %#v", failure)
		}
	}
	var serial, fingerprint string
	misses := 0
	for result := range results {
		if result == nil {
			t.Fatal("nil concurrent result")
		}
		if !result.CacheHit {
			misses++
		}
		if serial == "" {
			serial = result.SerialNumber
			fingerprint = result.FingerprintSHA256
			continue
		}
		if result.SerialNumber != serial || result.FingerprintSHA256 != fingerprint {
			t.Fatalf("concurrent issuance produced multiple leaves: %#v", result)
		}
	}
	if misses != 1 {
		t.Fatalf("cache misses = %d, want 1", misses)
	}
	if status := getTLSInspectionLeafCacheStatus(); status.EntryCount != 1 || !status.Ready {
		t.Fatalf("cache status = %#v", status)
	}
}

func TestTLSInspectionLeafPolicyChangePurgesCache(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	firstPolicy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "first.example.com", Scope: "exact"}},
		nil,
	)
	prepareTLSInspectionLeafTestCertificate(t, authority, firstPolicy, "first.example.com")
	secondPolicy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "second.example.com", Scope: "exact"}},
		nil,
	)
	if secondPolicy.PolicyDigest == firstPolicy.PolicyDigest || secondPolicy.EntryCount != 0 {
		t.Fatalf("policy change did not purge cache: %#v -> %#v", firstPolicy, secondPolicy)
	}
	_, failure := prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{
		Host:                       "first.example.com",
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		PolicyDigest:               secondPolicy.PolicyDigest,
	})
	if failure == nil || failure.Code != "domain_not_allowed" {
		t.Fatalf("old host failure = %#v", failure)
	}
	created := prepareTLSInspectionLeafTestCertificate(t, authority, secondPolicy, "second.example.com")
	if created.CacheHit {
		t.Fatalf("new policy unexpectedly reused a leaf: %#v", created)
	}
}

func TestTLSInspectionLeafRuntimeAuthorizationMustBeRenewed(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	created := prepareTLSInspectionLeafTestCertificate(t, authority, policy, "api.example.com")
	resetTLSInspectionLeafPolicySession()
	status := getTLSInspectionLeafCacheStatus()
	if status.Ready || status.State != "disabled" || status.RuntimeAuthorizationPresent {
		t.Fatalf("runtime reset status = %#v", status)
	}
	_, failure := prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{
		Host:                       "api.example.com",
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		PolicyDigest:               policy.PolicyDigest,
	})
	if failure == nil || failure.Code != "leaf_policy_not_configured" {
		t.Fatalf("prepare without runtime authorization = %#v", failure)
	}
	reauthorized := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	if reauthorized.EntryCount != 1 || reauthorized.PolicyDigest != policy.PolicyDigest {
		t.Fatalf("reauthorized status = %#v", reauthorized)
	}
	reused := prepareTLSInspectionLeafTestCertificate(t, authority, reauthorized, "api.example.com")
	if !reused.CacheHit || reused.SerialNumber != created.SerialNumber {
		t.Fatalf("reauthorized cache result = %#v", reused)
	}
}

func TestTLSInspectionLeafRotationInvalidatesCache(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	prepareTLSInspectionLeafTestCertificate(t, authority, policy, "api.example.com")
	rotated, failure := rotateTLSInspectionAuthority(true)
	if failure != nil {
		t.Fatal(failure)
	}
	if rotated.Generation == authority.Generation {
		t.Fatal("authority did not rotate")
	}
	status := getTLSInspectionLeafCacheStatus()
	if status.Ready || status.State != "disabled" {
		t.Fatalf("leaf cache survived rotation: %#v", status)
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tlsInspectionGenerationPath(root, authority.Generation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old authority generation survived rotation: %v", err)
	}
}

func TestTLSInspectionLeafIssuanceRejectsRelaxedCachePermissions(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entriesRoot := tlsInspectionLeafEntriesRoot(root, authority.Generation)
	if err := os.Chmod(entriesRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	_, failure := prepareTLSInspectionLeafCertificate(&TLSInspectionLeafPrepareParams{
		Host:                       "api.example.com",
		AuthorityGeneration:        authority.Generation,
		AuthorityFingerprintSHA256: authority.FingerprintSHA256,
		PolicyDigest:               policy.PolicyDigest,
	})
	if failure == nil || failure.Code != "leaf_key_permissions" {
		t.Fatalf("relaxed permission failure = %#v", failure)
	}
	if tlsInspectionLeafSession != nil {
		t.Fatal("unsafe cache permissions did not revoke runtime authorization")
	}
}

func TestTLSInspectionLeafCacheCleansTamperedEntry(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "api.example.com", Scope: "exact"}},
		nil,
	)
	created := prepareTLSInspectionLeafTestCertificate(t, authority, policy, "api.example.com")
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entryRoot := filepath.Join(
		tlsInspectionLeafEntriesRoot(root, authority.Generation),
		tlsInspectionLeafCacheKey(created.Host),
	)
	metadataPath := filepath.Join(entryRoot, tlsInspectionLeafMetadataFile)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata["host"] = "other.example.com"
	tampered, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	status := getTLSInspectionLeafCacheStatus()
	if !status.Ready || status.EntryCount != 0 {
		t.Fatalf("tampered entry was not cleaned: %#v", status)
	}
	if _, err := os.Stat(entryRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered entry still exists: %v", err)
	}
}

func TestTLSInspectionLeafCacheEvictsLeastRecentlyUsed(t *testing.T) {
	authority := requireTLSInspectionLeafAuthority(t)
	policy := configureTLSInspectionLeafTestPolicy(
		t,
		authority,
		[]TLSInspectionLeafRule{{Host: "example.com", Scope: "subdomains"}},
		nil,
	)
	for index := 0; index < tlsInspectionLeafMaxEntries; index++ {
		prepareTLSInspectionLeafTestCertificate(t, authority, policy, fmt.Sprintf("host-%02d.example.com", index))
	}
	time.Sleep(2 * time.Millisecond)
	prepareTLSInspectionLeafTestCertificate(t, authority, policy, "host-00.example.com")
	prepareTLSInspectionLeafTestCertificate(t, authority, policy, "host-64.example.com")
	status := getTLSInspectionLeafCacheStatus()
	if !status.Ready || status.EntryCount != tlsInspectionLeafMaxEntries {
		t.Fatalf("bounded cache status = %#v", status)
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		t.Fatal(err)
	}
	entriesRoot := tlsInspectionLeafEntriesRoot(root, authority.Generation)
	for _, testCase := range []struct {
		host   string
		exists bool
	}{
		{host: "host-00.example.com", exists: true},
		{host: "host-01.example.com", exists: false},
		{host: "host-64.example.com", exists: true},
	} {
		_, err := os.Stat(filepath.Join(entriesRoot, tlsInspectionLeafCacheKey(testCase.host)))
		if testCase.exists && err != nil {
			t.Fatalf("expected cached host %s: %v", testCase.host, err)
		}
		if !testCase.exists && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected evicted host %s, stat = %v", testCase.host, err)
		}
	}
}

func TestTLSInspectionLeafMethodsAreRegistered(t *testing.T) {
	for _, method := range []CoreMethod{
		getTLSInspectionLeafCacheStatusMethod,
		configureTLSInspectionLeafPolicyMethod,
		prepareTLSInspectionLeafCertificateMethod,
	} {
		if _, exists := methodHandlers[method]; !exists {
			t.Fatalf("Core method %q is not registered", method)
		}
	}
}
