package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	tlsInspectionLeafPolicyFormatVersion = 1
	tlsInspectionLeafRiskVersion         = 1
	tlsInspectionLeafCacheDirectory      = "leaf-cache"
	tlsInspectionLeafEntriesDirectory    = "entries"
	tlsInspectionLeafPolicyFile          = "policy.json"
	tlsInspectionLeafMetadataFile        = "metadata.json"
	tlsInspectionLeafCertFile            = "leaf-cert.pem"
	tlsInspectionLeafKeyFile             = "leaf-key.pem"
	tlsInspectionLeafMaxPolicySize       = 256 * 1024
	tlsInspectionLeafMaxMetadataSize     = 8 * 1024
	tlsInspectionLeafMaxRulesPerList     = 200
	tlsInspectionLeafMaxEntries          = 64
	tlsInspectionLeafValidity            = 24 * time.Hour
	tlsInspectionLeafClockSkew           = 5 * time.Minute
	tlsInspectionLeafRenewBefore         = 10 * time.Minute
)

type TLSInspectionLeafRule struct {
	Host  string `json:"host"`
	Scope string `json:"scope"`
}

type TLSInspectionLeafPolicyParams struct {
	Enabled                    bool                    `json:"enabled"`
	AuthorityGeneration        string                  `json:"authorityGeneration"`
	AuthorityFingerprintSHA256 string                  `json:"authorityFingerprintSha256"`
	RiskVersion                int                     `json:"riskVersion"`
	TrustSatisfied             bool                    `json:"trustSatisfied"`
	Allowlist                  []TLSInspectionLeafRule `json:"allowlist"`
	Exclusions                 []TLSInspectionLeafRule `json:"exclusions"`
}

type TLSInspectionLeafPrepareParams struct {
	VerifyHandshake            bool   `json:"verifyHandshake"`
	Host                       string `json:"host"`
	AuthorityGeneration        string `json:"authorityGeneration"`
	AuthorityFingerprintSHA256 string `json:"authorityFingerprintSha256"`
	PolicyDigest               string `json:"policyDigest"`
}

type TLSInspectionLeafCacheStatus struct {
	State                       string    `json:"state"`
	Ready                       bool      `json:"ready"`
	Generation                  string    `json:"generation,omitempty"`
	AuthorityFingerprintSHA256  string    `json:"authorityFingerprintSha256,omitempty"`
	PolicyDigest                string    `json:"policyDigest,omitempty"`
	EntryCount                  int       `json:"entryCount"`
	Capacity                    int       `json:"capacity"`
	LeafValiditySeconds         int64     `json:"leafValiditySeconds"`
	Algorithm                   string    `json:"algorithm"`
	KeyStorage                  string    `json:"keyStorage"`
	KeyPermissionsRestricted    bool      `json:"keyPermissionsRestricted"`
	PrivateKeysExported         bool      `json:"privateKeysExported"`
	RuntimeAuthorizationPresent bool      `json:"runtimeAuthorizationPresent"`
	UpdatedAt                   time.Time `json:"updatedAt,omitempty"`
	Issue                       string    `json:"issue,omitempty"`
}

type TLSInspectionLeafCertificateStatus struct {
	HandshakeVerified          bool      `json:"handshakeVerified,omitempty"`
	HandshakeVersions          []string  `json:"handshakeVersions,omitempty"`
	HandshakeALPN              string    `json:"handshakeAlpn,omitempty"`
	HandshakeScope             string    `json:"handshakeScope,omitempty"`
	HandshakeDurationMs        int64     `json:"handshakeDurationMs,omitempty"`
	Host                       string    `json:"host"`
	CacheHit                   bool      `json:"cacheHit"`
	Generation                 string    `json:"generation"`
	AuthorityFingerprintSHA256 string    `json:"authorityFingerprintSha256"`
	PolicyDigest               string    `json:"policyDigest"`
	FingerprintSHA256          string    `json:"fingerprintSha256"`
	SerialNumber               string    `json:"serialNumber"`
	NotBefore                  time.Time `json:"notBefore"`
	NotAfter                   time.Time `json:"notAfter"`
	Algorithm                  string    `json:"algorithm"`
	KeyStorage                 string    `json:"keyStorage"`
	PrivateKeyExported         bool      `json:"privateKeyExported"`
}

type tlsInspectionLeafPolicy struct {
	FormatVersion              int                     `json:"formatVersion"`
	Generation                 string                  `json:"generation"`
	AuthorityFingerprintSHA256 string                  `json:"authorityFingerprintSha256"`
	RiskVersion                int                     `json:"riskVersion"`
	Allowlist                  []TLSInspectionLeafRule `json:"allowlist"`
	Exclusions                 []TLSInspectionLeafRule `json:"exclusions"`
	Digest                     string                  `json:"digest"`
	UpdatedAt                  time.Time               `json:"updatedAt"`
}

type tlsInspectionLeafMetadata struct {
	FormatVersion              int       `json:"formatVersion"`
	Host                       string    `json:"host"`
	Generation                 string    `json:"generation"`
	AuthorityFingerprintSHA256 string    `json:"authorityFingerprintSha256"`
	PolicyDigest               string    `json:"policyDigest"`
	FingerprintSHA256          string    `json:"fingerprintSha256"`
	SerialNumber               string    `json:"serialNumber"`
	NotBefore                  time.Time `json:"notBefore"`
	NotAfter                   time.Time `json:"notAfter"`
	CreatedAt                  time.Time `json:"createdAt"`
	LastUsedAt                 time.Time `json:"lastUsedAt"`
}

type tlsInspectionLeafEntry struct {
	Root        string
	Metadata    tlsInspectionLeafMetadata
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
}

var tlsInspectionLeafSession *tlsInspectionLeafPolicy

func resetTLSInspectionLeafPolicySession() {
	tlsInspectionLeafSession = nil
}

func tlsInspectionLeafCacheRoot(root, generation string) string {
	return filepath.Join(tlsInspectionGenerationPath(root, generation), tlsInspectionLeafCacheDirectory)
}

func tlsInspectionLeafEntriesRoot(root, generation string) string {
	return filepath.Join(tlsInspectionLeafCacheRoot(root, generation), tlsInspectionLeafEntriesDirectory)
}

func tlsInspectionLeafPolicyPath(root, generation string) string {
	return filepath.Join(tlsInspectionLeafCacheRoot(root, generation), tlsInspectionLeafPolicyFile)
}

func tlsInspectionLeafCacheKey(host string) string {
	sum := sha256.Sum256([]byte(host))
	return hex.EncodeToString(sum[:])
}

func validTLSInspectionLeafCacheKey(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func normalizeTLSInspectionFingerprint(value string) (string, error) {
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(value)), ":")
	if len(parts) != sha256.Size {
		return "", errors.New("fingerprint must contain 32 hexadecimal octets")
	}
	for _, part := range parts {
		if len(part) != 2 {
			return "", errors.New("fingerprint must use canonical hexadecimal octets")
		}
		if _, err := hex.DecodeString(part); err != nil {
			return "", errors.New("fingerprint contains non-hexadecimal data")
		}
	}
	return strings.Join(parts, ":"), nil
}

func analyzeTLSInspectionLeafDomain(raw string) (*DomainAnalysisResult, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, "/\\?#@:") {
		return nil, errors.New("leaf certificate hosts must be bare domain names")
	}
	return analyzeDomain(value)
}

func normalizeTLSInspectionLeafRules(raw []TLSInspectionLeafRule, listName string) ([]TLSInspectionLeafRule, error) {
	if len(raw) > tlsInspectionLeafMaxRulesPerList {
		return nil, fmt.Errorf("%s exceeds the rule limit", listName)
	}
	byIdentity := make(map[string]TLSInspectionLeafRule, len(raw))
	for _, input := range raw {
		analysis, err := analyzeTLSInspectionLeafDomain(input.Host)
		if err != nil {
			return nil, fmt.Errorf("%s contains an invalid domain: %w", listName, err)
		}
		if analysis.IsIP || analysis.RegistrableDomain == "" || analysis.NormalizedHost == analysis.PublicSuffix {
			return nil, fmt.Errorf("%s contains a domain without a safe registrable boundary", listName)
		}
		scope := strings.TrimSpace(input.Scope)
		if scope != "exact" && scope != "subdomains" {
			return nil, fmt.Errorf("%s contains an unsupported rule scope", listName)
		}
		rule := TLSInspectionLeafRule{Host: analysis.NormalizedHost, Scope: scope}
		byIdentity[scope+":"+rule.Host] = rule
	}
	values := make([]TLSInspectionLeafRule, 0, len(byIdentity))
	for _, rule := range byIdentity {
		values = append(values, rule)
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].Host == values[right].Host {
			return values[left].Scope < values[right].Scope
		}
		return values[left].Host < values[right].Host
	})
	return values, nil
}

func tlsInspectionLeafPolicyDigest(policy *tlsInspectionLeafPolicy) (string, error) {
	payload := struct {
		FormatVersion              int                     `json:"formatVersion"`
		Generation                 string                  `json:"generation"`
		AuthorityFingerprintSHA256 string                  `json:"authorityFingerprintSha256"`
		RiskVersion                int                     `json:"riskVersion"`
		Allowlist                  []TLSInspectionLeafRule `json:"allowlist"`
		Exclusions                 []TLSInspectionLeafRule `json:"exclusions"`
	}{
		FormatVersion:              policy.FormatVersion,
		Generation:                 policy.Generation,
		AuthorityFingerprintSHA256: policy.AuthorityFingerprintSHA256,
		RiskVersion:                policy.RiskVersion,
		Allowlist:                  policy.Allowlist,
		Exclusions:                 policy.Exclusions,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func newTLSInspectionLeafPolicy(params *TLSInspectionLeafPolicyParams, authority *TLSInspectionAuthorityStatus) (*tlsInspectionLeafPolicy, error) {
	generation := strings.ToLower(strings.TrimSpace(params.AuthorityGeneration))
	if !validTLSInspectionGeneration(generation) || generation != authority.Generation {
		return nil, errors.New("authority generation does not match the active authority")
	}
	fingerprint, err := normalizeTLSInspectionFingerprint(params.AuthorityFingerprintSHA256)
	if err != nil || fingerprint != authority.FingerprintSHA256 {
		return nil, errors.New("authority fingerprint does not match the active authority")
	}
	if params.RiskVersion != tlsInspectionLeafRiskVersion {
		return nil, errors.New("risk acknowledgement version is not current")
	}
	if !params.TrustSatisfied {
		return nil, errors.New("platform or explicit trust is not currently satisfied")
	}
	allowlist, err := normalizeTLSInspectionLeafRules(params.Allowlist, "allowlist")
	if err != nil {
		return nil, err
	}
	if len(allowlist) == 0 {
		return nil, errors.New("allowlist must contain at least one domain rule")
	}
	exclusions, err := normalizeTLSInspectionLeafRules(params.Exclusions, "exclusions")
	if err != nil {
		return nil, err
	}
	policy := &tlsInspectionLeafPolicy{
		FormatVersion:              tlsInspectionLeafPolicyFormatVersion,
		Generation:                 generation,
		AuthorityFingerprintSHA256: fingerprint,
		RiskVersion:                params.RiskVersion,
		Allowlist:                  allowlist,
		Exclusions:                 exclusions,
		UpdatedAt:                  time.Now().UTC(),
	}
	policy.Digest, err = tlsInspectionLeafPolicyDigest(policy)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func validateTLSInspectionLeafPolicy(policy *tlsInspectionLeafPolicy) error {
	if policy.FormatVersion != tlsInspectionLeafPolicyFormatVersion ||
		!validTLSInspectionGeneration(policy.Generation) ||
		policy.RiskVersion != tlsInspectionLeafRiskVersion ||
		policy.UpdatedAt.IsZero() ||
		!validTLSInspectionLeafCacheKey(policy.Digest) {
		return errors.New("leaf policy metadata is invalid")
	}
	fingerprint, err := normalizeTLSInspectionFingerprint(policy.AuthorityFingerprintSHA256)
	if err != nil || fingerprint != policy.AuthorityFingerprintSHA256 {
		return errors.New("leaf policy fingerprint is invalid")
	}
	allowlist, err := normalizeTLSInspectionLeafRules(policy.Allowlist, "allowlist")
	if err != nil || len(allowlist) == 0 {
		return errors.New("leaf policy allowlist is invalid")
	}
	exclusions, err := normalizeTLSInspectionLeafRules(policy.Exclusions, "exclusions")
	if err != nil {
		return errors.New("leaf policy exclusions are invalid")
	}
	policy.Allowlist = allowlist
	policy.Exclusions = exclusions
	digest, err := tlsInspectionLeafPolicyDigest(policy)
	if err != nil || digest != policy.Digest {
		return errors.New("leaf policy digest is invalid")
	}
	return nil
}

func tlsInspectionLeafRuleMatches(rule TLSInspectionLeafRule, host string) bool {
	if rule.Scope == "exact" {
		return host == rule.Host
	}
	return host == rule.Host || strings.HasSuffix(host, "."+rule.Host)
}

func tlsInspectionLeafPolicyAllows(policy *tlsInspectionLeafPolicy, host string) bool {
	for _, rule := range policy.Exclusions {
		if tlsInspectionLeafRuleMatches(rule, host) {
			return false
		}
	}
	for _, rule := range policy.Allowlist {
		if tlsInspectionLeafRuleMatches(rule, host) {
			return true
		}
	}
	return false
}

func readTLSInspectionLeafPolicy(root, generation string) (*tlsInspectionLeafPolicy, error) {
	data, err := readTLSInspectionFile(tlsInspectionLeafPolicyPath(root, generation), tlsInspectionLeafMaxPolicySize)
	if err != nil {
		return nil, err
	}
	var policy tlsInspectionLeafPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("decode leaf policy: %w", err)
	}
	if err := validateTLSInspectionLeafPolicy(&policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func writeTLSInspectionLeafPolicy(root string, policy *tlsInspectionLeafPolicy) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	if len(data) > tlsInspectionLeafMaxPolicySize {
		return errors.New("leaf policy exceeds its size limit")
	}
	return writeTLSInspectionFile(tlsInspectionLeafPolicyPath(root, policy.Generation), data, 0o600)
}

func removeTLSInspectionLeafPath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return os.Remove(path)
	}
	return os.RemoveAll(path)
}

func clearTLSInspectionLeafCachesLocked() error {
	resetTLSInspectionLeafPolicySession()
	root, err := tlsInspectionRoot()
	if err != nil {
		return err
	}
	if err := tlsInspectionDirectoryStatus(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	authoritiesRoot := filepath.Join(root, "authorities")
	if err := tlsInspectionDirectoryStatus(authoritiesRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	entries, err := os.ReadDir(authoritiesRoot)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		generationRoot := filepath.Join(authoritiesRoot, entry.Name())
		if err := tlsInspectionDirectoryStatus(generationRoot); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := removeTLSInspectionLeafPath(filepath.Join(generationRoot, tlsInspectionLeafCacheDirectory)); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func ensureTLSInspectionLeafCacheDirectories(root, generation string) error {
	for _, directory := range []string{
		tlsInspectionLeafCacheRoot(root, generation),
		tlsInspectionLeafEntriesRoot(root, generation),
	} {
		if err := ensureTLSInspectionDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func readTLSInspectionAuthoritySigningMaterialLocked() (*TLSInspectionAuthorityStatus, *x509.Certificate, *ecdsa.PrivateKey, error) {
	status, certificatePEM, err := readTLSInspectionAuthority()
	if err != nil {
		return nil, nil, nil, err
	}
	if !status.Ready || len(certificatePEM) == 0 {
		return status, nil, nil, errors.New("local authority is not ready")
	}
	certificateBlock, rest := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return status, nil, nil, errors.New("local authority certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || tlsInspectionFingerprint(certificate.Raw) != status.FingerprintSHA256 {
		return status, nil, nil, errors.New("local authority certificate changed")
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		return status, nil, nil, err
	}
	privatePEM, err := readTLSInspectionFile(
		filepath.Join(tlsInspectionGenerationPath(root, status.Generation), tlsInspectionKeyFile),
		tlsInspectionMaxPEMSize,
	)
	if err != nil {
		return status, nil, nil, err
	}
	privateBlock, rest := pem.Decode(privatePEM)
	if privateBlock == nil || privateBlock.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return status, nil, nil, errors.New("local authority private key is invalid")
	}
	privateValue, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		return status, nil, nil, errors.New("local authority private key is invalid")
	}
	privateKey, ok := privateValue.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return status, nil, nil, errors.New("local authority private key is unsupported")
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return status, nil, nil, err
	}
	privatePublic, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil || !bytes.Equal(certificatePublic, privatePublic) {
		return status, nil, nil, errors.New("local authority key pair changed")
	}
	return status, certificate, privateKey, nil
}

func tlsInspectionRestrictedDirectory(path string, mask os.FileMode) bool {
	info, err := os.Lstat(path)
	return err == nil &&
		info.Mode()&os.ModeSymlink == 0 &&
		info.IsDir() &&
		info.Mode().Perm()&mask == 0
}

func tlsInspectionRestrictedFile(path string, mask os.FileMode) bool {
	info, err := os.Lstat(path)
	return err == nil &&
		info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().IsRegular() &&
		info.Mode().Perm()&mask == 0
}

func tlsInspectionLeafCachePermissionsRestricted(root, generation string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return tlsInspectionRestrictedDirectory(tlsInspectionLeafCacheRoot(root, generation), 0o077) &&
		tlsInspectionRestrictedDirectory(tlsInspectionLeafEntriesRoot(root, generation), 0o077) &&
		tlsInspectionRestrictedFile(tlsInspectionLeafPolicyPath(root, generation), 0o077)
}

func tlsInspectionLeafEntryPermissionsRestricted(entryRoot string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return tlsInspectionRestrictedDirectory(entryRoot, 0o077) &&
		tlsInspectionRestrictedFile(filepath.Join(entryRoot, tlsInspectionLeafMetadataFile), 0o077) &&
		tlsInspectionRestrictedFile(filepath.Join(entryRoot, tlsInspectionLeafKeyFile), 0o077) &&
		tlsInspectionRestrictedFile(filepath.Join(entryRoot, tlsInspectionLeafCertFile), 0o022)
}

func parseTLSInspectionLeafPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("leaf private key is invalid")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("leaf private key is invalid")
	}
	privateKey, ok := value.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return nil, errors.New("leaf private key is unsupported")
	}
	return privateKey, nil
}

func parseTLSInspectionLeafCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("leaf certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("leaf certificate is invalid")
	}
	return certificate, nil
}

func loadTLSInspectionLeafEntry(entryRoot string, policy *tlsInspectionLeafPolicy, authority *x509.Certificate) (*tlsInspectionLeafEntry, error) {
	if err := tlsInspectionDirectoryStatus(entryRoot); err != nil {
		return nil, err
	}
	metadataData, err := readTLSInspectionFile(filepath.Join(entryRoot, tlsInspectionLeafMetadataFile), tlsInspectionLeafMaxMetadataSize)
	if err != nil {
		return nil, err
	}
	certificatePEM, err := readTLSInspectionFile(filepath.Join(entryRoot, tlsInspectionLeafCertFile), tlsInspectionMaxPEMSize)
	if err != nil {
		return nil, err
	}
	privatePEM, err := readTLSInspectionFile(filepath.Join(entryRoot, tlsInspectionLeafKeyFile), tlsInspectionMaxPEMSize)
	if err != nil {
		return nil, err
	}
	var metadata tlsInspectionLeafMetadata
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return nil, errors.New("leaf metadata is invalid")
	}
	now := time.Now().UTC()
	if metadata.FormatVersion != tlsInspectionLeafPolicyFormatVersion ||
		metadata.Generation != policy.Generation ||
		metadata.AuthorityFingerprintSHA256 != policy.AuthorityFingerprintSHA256 ||
		metadata.PolicyDigest != policy.Digest ||
		metadata.Host == "" ||
		metadata.FingerprintSHA256 == "" ||
		metadata.SerialNumber == "" ||
		metadata.CreatedAt.IsZero() ||
		metadata.LastUsedAt.IsZero() ||
		metadata.NotBefore.IsZero() ||
		metadata.NotAfter.IsZero() ||
		metadata.CreatedAt.Before(metadata.NotBefore) ||
		!metadata.CreatedAt.Before(metadata.NotAfter) ||
		metadata.LastUsedAt.Before(metadata.CreatedAt) ||
		metadata.CreatedAt.After(now.Add(tlsInspectionLeafClockSkew)) ||
		metadata.LastUsedAt.After(now.Add(tlsInspectionLeafClockSkew)) {
		return nil, errors.New("leaf metadata does not match the active policy")
	}
	analysis, err := analyzeDomain(metadata.Host)
	if err != nil || analysis.IsIP || analysis.NormalizedHost != metadata.Host || analysis.RegistrableDomain == "" || analysis.NormalizedHost == analysis.PublicSuffix {
		return nil, errors.New("leaf metadata host is invalid")
	}
	if !tlsInspectionLeafPolicyAllows(policy, metadata.Host) || filepath.Base(entryRoot) != tlsInspectionLeafCacheKey(metadata.Host) {
		return nil, errors.New("leaf metadata host is outside the active policy")
	}
	certificate, err := parseTLSInspectionLeafCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	privateKey, err := parseTLSInspectionLeafPrivateKey(privatePEM)
	if err != nil {
		return nil, err
	}
	certificatePublic, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || certificatePublic.Curve != elliptic.P256() {
		return nil, errors.New("leaf certificate key is unsupported")
	}
	certificatePublicDER, certificateErr := x509.MarshalPKIXPublicKey(certificatePublic)
	privatePublicDER, privateErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if certificateErr != nil || privateErr != nil || !bytes.Equal(certificatePublicDER, privatePublicDER) {
		return nil, errors.New("leaf key pair does not match")
	}
	if err := certificate.CheckSignatureFrom(authority); err != nil {
		return nil, errors.New("leaf certificate signature is invalid")
	}
	if certificate.IsCA ||
		!certificate.BasicConstraintsValid ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		len(certificate.UnknownExtKeyUsage) != 0 ||
		certificate.PublicKeyAlgorithm != x509.ECDSA ||
		certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		certificate.Subject.CommonName != metadata.Host ||
		len(certificate.Subject.Organization) != 1 ||
		certificate.Subject.Organization[0] != "FlClash" ||
		len(certificate.DNSNames) != 1 ||
		certificate.DNSNames[0] != metadata.Host ||
		len(certificate.IPAddresses) != 0 ||
		len(certificate.EmailAddresses) != 0 ||
		len(certificate.URIs) != 0 ||
		len(certificate.SubjectKeyId) != 20 ||
		!bytes.Equal(certificate.AuthorityKeyId, authority.SubjectKeyId) ||
		!bytes.Equal(certificate.RawIssuer, authority.RawSubject) ||
		certificate.SerialNumber == nil ||
		certificate.SerialNumber.Sign() <= 0 ||
		certificate.SerialNumber.BitLen() > 128 ||
		certificate.NotAfter.Sub(certificate.NotBefore) > tlsInspectionLeafValidity ||
		certificate.NotBefore.Before(authority.NotBefore) ||
		certificate.NotAfter.After(authority.NotAfter) ||
		!certificate.NotBefore.Equal(metadata.NotBefore) ||
		!certificate.NotAfter.Equal(metadata.NotAfter) ||
		strings.ToUpper(certificate.SerialNumber.Text(16)) != metadata.SerialNumber ||
		tlsInspectionFingerprint(certificate.Raw) != metadata.FingerprintSHA256 {
		return nil, errors.New("leaf certificate violates the cache contract")
	}
	if now.Before(certificate.NotBefore) || !certificate.NotAfter.After(now.Add(tlsInspectionLeafRenewBefore)) {
		return nil, errors.New("leaf certificate is outside its reusable validity window")
	}
	if !tlsInspectionLeafEntryPermissionsRestricted(entryRoot) {
		return nil, errors.New("leaf key permissions are not restricted")
	}
	return &tlsInspectionLeafEntry{
		Root:        entryRoot,
		Metadata:    metadata,
		Certificate: certificate,
		PrivateKey:  privateKey,
	}, nil
}

func scanTLSInspectionLeafEntries(root string, policy *tlsInspectionLeafPolicy, authority *x509.Certificate) ([]*tlsInspectionLeafEntry, error) {
	cacheRoot := tlsInspectionLeafCacheRoot(root, policy.Generation)
	if err := tlsInspectionDirectoryStatus(cacheRoot); err != nil {
		return nil, err
	}
	entriesRoot := tlsInspectionLeafEntriesRoot(root, policy.Generation)
	if err := tlsInspectionDirectoryStatus(entriesRoot); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(entriesRoot)
	if err != nil {
		return nil, err
	}
	values := make([]*tlsInspectionLeafEntry, 0, len(entries))
	var cleanupFailures []error
	for _, entry := range entries {
		entryRoot := filepath.Join(entriesRoot, entry.Name())
		if !validTLSInspectionLeafCacheKey(entry.Name()) {
			if err := removeTLSInspectionLeafPath(entryRoot); err != nil {
				cleanupFailures = append(cleanupFailures, err)
			}
			continue
		}
		value, err := loadTLSInspectionLeafEntry(entryRoot, policy, authority)
		if err != nil {
			if removeErr := removeTLSInspectionLeafPath(entryRoot); removeErr != nil {
				cleanupFailures = append(cleanupFailures, removeErr)
			}
			continue
		}
		values = append(values, value)
	}
	if err := errors.Join(cleanupFailures...); err != nil {
		return nil, err
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].Metadata.LastUsedAt.Equal(values[right].Metadata.LastUsedAt) {
			return values[left].Metadata.Host < values[right].Metadata.Host
		}
		return values[left].Metadata.LastUsedAt.Before(values[right].Metadata.LastUsedAt)
	})
	return values, nil
}

func pruneTLSInspectionLeafEntries(entries []*tlsInspectionLeafEntry, keep int) ([]*tlsInspectionLeafEntry, error) {
	if keep < 0 {
		keep = 0
	}
	if len(entries) <= keep {
		return entries, nil
	}
	removeCount := len(entries) - keep
	for index := 0; index < removeCount; index++ {
		if err := removeTLSInspectionLeafPath(entries[index].Root); err != nil {
			return nil, err
		}
	}
	return entries[removeCount:], nil
}

func tlsInspectionLeafSerial() (*big.Int, error) {
	return tlsInspectionSerial()
}

func maxTLSInspectionTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}

func minTLSInspectionTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func createTLSInspectionLeafEntry(root, host string, policy *tlsInspectionLeafPolicy, authority *x509.Certificate, authorityKey *ecdsa.PrivateKey) (*tlsInspectionLeafEntry, error) {
	serial, err := tlsInspectionLeafSerial()
	if err != nil {
		return nil, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	notBefore := maxTLSInspectionTime(now.Add(-tlsInspectionLeafClockSkew), authority.NotBefore)
	notAfter := minTLSInspectionTime(notBefore.Add(tlsInspectionLeafValidity), authority.NotAfter)
	if !notAfter.After(now.Add(tlsInspectionLeafRenewBefore)) {
		return nil, errors.New("local authority expires too soon to issue a leaf certificate")
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"FlClash"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{host},
		SubjectKeyId:          make([]byte, 20),
		AuthorityKeyId:        append([]byte(nil), authority.SubjectKeyId...),
	}
	if _, err := rand.Read(template.SubjectKeyId); err != nil {
		return nil, err
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority, &privateKey.PublicKey, authorityKey)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	metadata := tlsInspectionLeafMetadata{
		FormatVersion:              tlsInspectionLeafPolicyFormatVersion,
		Host:                       host,
		Generation:                 policy.Generation,
		AuthorityFingerprintSHA256: policy.AuthorityFingerprintSHA256,
		PolicyDigest:               policy.Digest,
		FingerprintSHA256:          tlsInspectionFingerprint(certificate.Raw),
		SerialNumber:               strings.ToUpper(certificate.SerialNumber.Text(16)),
		NotBefore:                  certificate.NotBefore.UTC(),
		NotAfter:                   certificate.NotAfter.UTC(),
		CreatedAt:                  now,
		LastUsedAt:                 now,
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	entriesRoot := tlsInspectionLeafEntriesRoot(root, policy.Generation)
	temporary, err := os.MkdirTemp(entriesRoot, ".leaf-*")
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil && runtime.GOOS != "windows" {
		return nil, err
	}
	if err := writeTLSInspectionFile(filepath.Join(temporary, tlsInspectionLeafKeyFile), privatePEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeTLSInspectionFile(filepath.Join(temporary, tlsInspectionLeafCertFile), certificatePEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeTLSInspectionFile(filepath.Join(temporary, tlsInspectionLeafMetadataFile), metadataData, 0o600); err != nil {
		return nil, err
	}
	finalRoot := filepath.Join(entriesRoot, tlsInspectionLeafCacheKey(host))
	if err := removeTLSInspectionLeafPath(finalRoot); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary, finalRoot); err != nil {
		return nil, err
	}
	cleanup = false
	entry, err := loadTLSInspectionLeafEntry(finalRoot, policy, authority)
	if err != nil {
		_ = removeTLSInspectionLeafPath(finalRoot)
		return nil, err
	}
	return entry, nil
}

func touchTLSInspectionLeafEntry(entry *tlsInspectionLeafEntry) error {
	entry.Metadata.LastUsedAt = time.Now().UTC()
	data, err := json.Marshal(entry.Metadata)
	if err != nil {
		return err
	}
	return writeTLSInspectionFile(filepath.Join(entry.Root, tlsInspectionLeafMetadataFile), data, 0o600)
}

func tlsInspectionLeafCertificateStatus(entry *tlsInspectionLeafEntry, cacheHit bool) *TLSInspectionLeafCertificateStatus {
	return &TLSInspectionLeafCertificateStatus{
		Host:                       entry.Metadata.Host,
		CacheHit:                   cacheHit,
		Generation:                 entry.Metadata.Generation,
		AuthorityFingerprintSHA256: entry.Metadata.AuthorityFingerprintSHA256,
		PolicyDigest:               entry.Metadata.PolicyDigest,
		FingerprintSHA256:          entry.Metadata.FingerprintSHA256,
		SerialNumber:               entry.Metadata.SerialNumber,
		NotBefore:                  entry.Metadata.NotBefore,
		NotAfter:                   entry.Metadata.NotAfter,
		Algorithm:                  "ECDSA P-256 / SHA-256",
		KeyStorage:                 "app-data-file",
		PrivateKeyExported:         false,
	}
}

func disabledTLSInspectionLeafCacheStatus(issue string) *TLSInspectionLeafCacheStatus {
	return &TLSInspectionLeafCacheStatus{
		State:                       "disabled",
		Capacity:                    tlsInspectionLeafMaxEntries,
		LeafValiditySeconds:         int64(tlsInspectionLeafValidity / time.Second),
		Algorithm:                   "ECDSA P-256 / SHA-256",
		KeyStorage:                  "app-data-file",
		PrivateKeysExported:         false,
		RuntimeAuthorizationPresent: false,
		Issue:                       issue,
	}
}

func unavailableTLSInspectionLeafCacheStatus(policy *tlsInspectionLeafPolicy, issue string, runtimeAuthorizationPresent bool) *TLSInspectionLeafCacheStatus {
	status := disabledTLSInspectionLeafCacheStatus(issue)
	status.State = "unavailable"
	status.RuntimeAuthorizationPresent = runtimeAuthorizationPresent && policy != nil
	if policy != nil {
		status.Generation = policy.Generation
		status.AuthorityFingerprintSHA256 = policy.AuthorityFingerprintSHA256
		status.PolicyDigest = policy.Digest
		status.UpdatedAt = policy.UpdatedAt
	}
	return status
}

func readyTLSInspectionLeafCacheStatus(root string, policy *tlsInspectionLeafPolicy, entries []*tlsInspectionLeafEntry) *TLSInspectionLeafCacheStatus {
	updatedAt := policy.UpdatedAt
	for _, entry := range entries {
		if entry.Metadata.LastUsedAt.After(updatedAt) {
			updatedAt = entry.Metadata.LastUsedAt
		}
	}
	return &TLSInspectionLeafCacheStatus{
		State:                       "ready",
		Ready:                       true,
		Generation:                  policy.Generation,
		AuthorityFingerprintSHA256:  policy.AuthorityFingerprintSHA256,
		PolicyDigest:                policy.Digest,
		EntryCount:                  len(entries),
		Capacity:                    tlsInspectionLeafMaxEntries,
		LeafValiditySeconds:         int64(tlsInspectionLeafValidity / time.Second),
		Algorithm:                   "ECDSA P-256 / SHA-256",
		KeyStorage:                  "app-data-file",
		KeyPermissionsRestricted:    tlsInspectionLeafCachePermissionsRestricted(root, policy.Generation),
		PrivateKeysExported:         false,
		RuntimeAuthorizationPresent: true,
		UpdatedAt:                   updatedAt,
	}
}

func getTLSInspectionLeafCacheStatusLocked() *TLSInspectionLeafCacheStatus {
	policy := tlsInspectionLeafSession
	if policy == nil {
		return disabledTLSInspectionLeafCacheStatus("runtime-authorization-missing")
	}
	status, authority, _, err := readTLSInspectionAuthoritySigningMaterialLocked()
	if err != nil || status.Generation != policy.Generation || status.FingerprintSHA256 != policy.AuthorityFingerprintSHA256 {
		resetTLSInspectionLeafPolicySession()
		return disabledTLSInspectionLeafCacheStatus("authority-changed")
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return unavailableTLSInspectionLeafCacheStatus(policy, "leaf-cache-root-unavailable", false)
	}
	if runtime.GOOS == "windows" ||
		!tlsInspectionRestrictedDirectory(tlsInspectionLeafCacheRoot(root, policy.Generation), 0o077) ||
		!tlsInspectionRestrictedDirectory(tlsInspectionLeafEntriesRoot(root, policy.Generation), 0o077) {
		resetTLSInspectionLeafPolicySession()
		return unavailableTLSInspectionLeafCacheStatus(policy, "leaf-key-permissions", false)
	}
	stored, err := readTLSInspectionLeafPolicy(root, policy.Generation)
	if err != nil || stored.Digest != policy.Digest {
		resetTLSInspectionLeafPolicySession()
		return unavailableTLSInspectionLeafCacheStatus(policy, "leaf-policy-unavailable", false)
	}
	entries, err := scanTLSInspectionLeafEntries(root, policy, authority)
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return unavailableTLSInspectionLeafCacheStatus(policy, "leaf-cache-cleanup-failed", false)
	}
	entries, err = pruneTLSInspectionLeafEntries(entries, tlsInspectionLeafMaxEntries)
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return unavailableTLSInspectionLeafCacheStatus(policy, "leaf-cache-prune-failed", false)
	}
	result := readyTLSInspectionLeafCacheStatus(root, policy, entries)
	if !result.KeyPermissionsRestricted {
		resetTLSInspectionLeafPolicySession()
		result.State = "unavailable"
		result.Ready = false
		result.RuntimeAuthorizationPresent = false
		result.Issue = "leaf-key-permissions"
	}
	return result
}

func getTLSInspectionLeafCacheStatus() *TLSInspectionLeafCacheStatus {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	return getTLSInspectionLeafCacheStatusLocked()
}

func configureTLSInspectionLeafPolicy(params *TLSInspectionLeafPolicyParams) (*TLSInspectionLeafCacheStatus, *MethodError) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	if !params.Enabled {
		if err := clearTLSInspectionLeafCachesLocked(); err != nil {
			return nil, &MethodError{Code: "leaf_cache_clear_failed", Message: err.Error()}
		}
		return disabledTLSInspectionLeafCacheStatus("policy-disabled"), nil
	}
	resetTLSInspectionLeafPolicySession()
	status, authority, _, err := readTLSInspectionAuthoritySigningMaterialLocked()
	if err != nil {
		return nil, &MethodError{Code: "authority_not_ready", Message: err.Error()}
	}
	policy, err := newTLSInspectionLeafPolicy(params, status)
	if err != nil {
		return nil, &MethodError{Code: "leaf_policy_invalid", Message: err.Error()}
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		return nil, &MethodError{Code: "leaf_cache_unavailable", Message: err.Error()}
	}
	cacheRoot := tlsInspectionLeafCacheRoot(root, policy.Generation)
	storedMatches := false
	if cacheStatusErr := tlsInspectionDirectoryStatus(cacheRoot); cacheStatusErr == nil {
		stored, storedErr := readTLSInspectionLeafPolicy(root, policy.Generation)
		storedMatches = storedErr == nil && stored.Digest == policy.Digest
	} else if !errors.Is(cacheStatusErr, os.ErrNotExist) {
		if err := removeTLSInspectionLeafPath(cacheRoot); err != nil {
			return nil, &MethodError{Code: "leaf_cache_unavailable", Message: err.Error()}
		}
	}
	if !storedMatches {
		if err := removeTLSInspectionLeafPath(cacheRoot); err != nil {
			return nil, &MethodError{Code: "leaf_cache_unavailable", Message: err.Error()}
		}
	}
	if err := ensureTLSInspectionLeafCacheDirectories(root, policy.Generation); err != nil {
		return nil, &MethodError{Code: "leaf_cache_unavailable", Message: err.Error()}
	}
	if err := writeTLSInspectionLeafPolicy(root, policy); err != nil {
		return nil, &MethodError{Code: "leaf_cache_unavailable", Message: err.Error()}
	}
	tlsInspectionLeafSession = policy
	entries, err := scanTLSInspectionLeafEntries(root, policy, authority)
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_cache_unavailable", Message: err.Error()}
	}
	entries, err = pruneTLSInspectionLeafEntries(entries, tlsInspectionLeafMaxEntries)
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_cache_unavailable", Message: err.Error()}
	}
	result := readyTLSInspectionLeafCacheStatus(root, policy, entries)
	if !result.KeyPermissionsRestricted {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_key_permissions", Message: "leaf cache permissions are not restricted"}
	}
	return result, nil
}

func prepareTLSInspectionLeafCertificate(params *TLSInspectionLeafPrepareParams) (*TLSInspectionLeafCertificateStatus, *MethodError) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	policy := tlsInspectionLeafSession
	if policy == nil {
		return nil, &MethodError{Code: "leaf_policy_not_configured", Message: "leaf issuance requires current runtime authorization"}
	}
	generation := strings.ToLower(strings.TrimSpace(params.AuthorityGeneration))
	fingerprint, fingerprintErr := normalizeTLSInspectionFingerprint(params.AuthorityFingerprintSHA256)
	if generation != policy.Generation || fingerprintErr != nil || fingerprint != policy.AuthorityFingerprintSHA256 || strings.TrimSpace(params.PolicyDigest) != policy.Digest {
		return nil, &MethodError{Code: "leaf_policy_mismatch", Message: "leaf issuance request does not match the active policy"}
	}
	analysis, err := analyzeTLSInspectionLeafDomain(params.Host)
	if err != nil || analysis.IsIP || analysis.RegistrableDomain == "" || analysis.NormalizedHost == analysis.PublicSuffix {
		return nil, &MethodError{Code: "invalid_domain", Message: "leaf certificates require a registrable domain name"}
	}
	host := analysis.NormalizedHost
	if !tlsInspectionLeafPolicyAllows(policy, host) {
		return nil, &MethodError{Code: "domain_not_allowed", Message: "domain is outside the active inspection allowlist"}
	}
	status, authority, authorityKey, err := readTLSInspectionAuthoritySigningMaterialLocked()
	if err != nil || status.Generation != policy.Generation || status.FingerprintSHA256 != policy.AuthorityFingerprintSHA256 {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "authority_not_ready", Message: "active authority no longer matches the leaf policy"}
	}
	root, err := tlsInspectionRoot()
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_issue_failed", Message: err.Error()}
	}
	if runtime.GOOS == "windows" ||
		!tlsInspectionRestrictedDirectory(tlsInspectionLeafCacheRoot(root, policy.Generation), 0o077) ||
		!tlsInspectionRestrictedDirectory(tlsInspectionLeafEntriesRoot(root, policy.Generation), 0o077) {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_key_permissions", Message: "leaf cache directories are not restricted"}
	}
	stored, err := readTLSInspectionLeafPolicy(root, policy.Generation)
	if err != nil || stored.Digest != policy.Digest {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_policy_mismatch", Message: "persisted leaf policy no longer matches runtime authorization"}
	}
	if !tlsInspectionLeafCachePermissionsRestricted(root, policy.Generation) {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_key_permissions", Message: "leaf cache permissions are not restricted"}
	}
	entries, err := scanTLSInspectionLeafEntries(root, policy, authority)
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_issue_failed", Message: err.Error()}
	}
	for _, entry := range entries {
		if entry.Metadata.Host != host {
			continue
		}
		if err := touchTLSInspectionLeafEntry(entry); err != nil {
			resetTLSInspectionLeafPolicySession()
			return nil, &MethodError{Code: "leaf_issue_failed", Message: err.Error()}
		}
		return completeTLSInspectionLeafPreparation(entry, true, authority, params.VerifyHandshake)
	}
	if _, err := pruneTLSInspectionLeafEntries(entries, tlsInspectionLeafMaxEntries-1); err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_issue_failed", Message: err.Error()}
	}
	entry, err := createTLSInspectionLeafEntry(root, host, policy, authority, authorityKey)
	if err != nil {
		resetTLSInspectionLeafPolicySession()
		return nil, &MethodError{Code: "leaf_issue_failed", Message: err.Error()}
	}
	return completeTLSInspectionLeafPreparation(entry, false, authority, params.VerifyHandshake)
}

func init() {
	registerMethod(getTLSInspectionLeafCacheStatusMethod, withoutArguments(func(response MethodResponse) {
		response.success(getTLSInspectionLeafCacheStatus())
	}))
	registerMethod(configureTLSInspectionLeafPolicyMethod, withArguments(func(params *TLSInspectionLeafPolicyParams, response MethodResponse) {
		value, failure := configureTLSInspectionLeafPolicy(params)
		if failure != nil {
			response.failure(failure.Code, failure.Message, failure.Details)
			return
		}
		response.success(value)
	}))
	registerMethod(prepareTLSInspectionLeafCertificateMethod, withArguments(func(params *TLSInspectionLeafPrepareParams, response MethodResponse) {
		value, failure := prepareTLSInspectionLeafCertificate(params)
		if failure != nil {
			response.failure(failure.Code, failure.Message, failure.Details)
			return
		}
		response.success(value)
	}))
}
