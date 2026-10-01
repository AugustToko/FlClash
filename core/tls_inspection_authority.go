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
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	tlsInspectionDirectoryName = "tls-inspection"
	tlsInspectionActiveFile    = "active.json"
	tlsInspectionCertFile      = "authority-cert.pem"
	tlsInspectionKeyFile       = "authority-key.pem"
	tlsInspectionExportName    = "flclash-local-inspection-ca.crt"
	tlsInspectionValidity      = 3 * 365 * 24 * time.Hour
	tlsInspectionMaxActiveSize = 4 * 1024
	tlsInspectionMaxPEMSize    = 64 * 1024
)

var tlsInspectionAuthorityMu sync.Mutex

type tlsInspectionActiveAuthority struct {
	Generation string    `json:"generation"`
	CreatedAt  time.Time `json:"createdAt"`
}

type TLSInspectionAuthorityStatus struct {
	State                    string    `json:"state"`
	Ready                    bool      `json:"ready"`
	Generation               string    `json:"generation,omitempty"`
	FingerprintSHA256        string    `json:"fingerprintSha256,omitempty"`
	Subject                  string    `json:"subject,omitempty"`
	SerialNumber             string    `json:"serialNumber,omitempty"`
	NotBefore                time.Time `json:"notBefore,omitempty"`
	NotAfter                 time.Time `json:"notAfter,omitempty"`
	CreatedAt                time.Time `json:"createdAt,omitempty"`
	Algorithm                string    `json:"algorithm,omitempty"`
	KeyStorage               string    `json:"keyStorage"`
	KeyPermissionsRestricted bool      `json:"keyPermissionsRestricted"`
	TrustState               string    `json:"trustState"`
	TrustCapability          string    `json:"trustCapability"`
	CertificateFileName      string    `json:"certificateFileName"`
	Issue                    string    `json:"issue,omitempty"`
}

type TLSInspectionAuthorityExport struct {
	FileName          string `json:"fileName"`
	PEM               string `json:"pem"`
	FingerprintSHA256 string `json:"fingerprintSha256"`
}

type TLSInspectionConfirmedMutation struct {
	Confirm bool `json:"confirm"`
}

func tlsInspectionRoot() (string, error) {
	home := strings.TrimSpace(C.Path.HomeDir())
	if home == "" {
		return "", errors.New("Core home directory is unavailable")
	}
	return filepath.Join(home, tlsInspectionDirectoryName), nil
}

func tlsInspectionGenerationPath(root, generation string) string {
	return filepath.Join(root, "authorities", generation)
}

func validTLSInspectionGeneration(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func tlsInspectionRandomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func tlsInspectionSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if value.Sign() == 0 {
		value.SetInt64(1)
	}
	return value, nil
}

func tlsInspectionFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(encoded)/2)
	for index := 0; index < len(encoded); index += 2 {
		parts = append(parts, encoded[index:index+2])
	}
	return strings.Join(parts, ":")
}

func tlsInspectionDirectoryStatus(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("unsafe authority directory: %s", path)
	}
	return nil
}

func ensureTLSInspectionDirectory(path string) error {
	if err := tlsInspectionDirectoryStatus(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := tlsInspectionDirectoryStatus(path); err != nil {
			return err
		}
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(path, 0o700)
	}
	return nil
}

func readTLSInspectionFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("unsafe authority file: %s", path)
	}
	if before.Size() < 0 || before.Size() > maximum {
		return nil, fmt.Errorf("authority file exceeds its size limit: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, fmt.Errorf("authority file changed while opening: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("authority file exceeds its size limit: %s", path)
	}
	return data, nil
}

func writeTLSInspectionFile(path string, data []byte, mode os.FileMode) error {
	if err := ensureTLSInspectionDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".flclash-write-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Rename(temporaryPath, path)
	}

	backup := path + ".previous"
	_ = os.Remove(backup)
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Rename(backup, path)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func createTLSInspectionAuthority() (*TLSInspectionAuthorityStatus, error) {
	root, err := tlsInspectionRoot()
	if err != nil {
		return nil, err
	}
	generation, err := tlsInspectionRandomID()
	if err != nil {
		return nil, fmt.Errorf("generate authority identity: %w", err)
	}
	serial, err := tlsInspectionSerial()
	if err != nil {
		return nil, fmt.Errorf("generate authority serial: %w", err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate authority key: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "FlClash Local Inspection CA",
			Organization: []string{"FlClash"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(tlsInspectionValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          make([]byte, 20),
	}
	if _, err := rand.Read(template.SubjectKeyId); err != nil {
		return nil, fmt.Errorf("generate subject key identifier: %w", err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create authority certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode authority key: %w", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})

	authoritiesRoot := filepath.Join(root, "authorities")
	generationRoot := tlsInspectionGenerationPath(root, generation)
	for _, directory := range []string{root, authoritiesRoot} {
		if err := ensureTLSInspectionDirectory(directory); err != nil {
			return nil, fmt.Errorf("prepare authority directory: %w", err)
		}
	}
	if err := os.Mkdir(generationRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create authority generation: %w", err)
	}
	if err := ensureTLSInspectionDirectory(generationRoot); err != nil {
		return nil, fmt.Errorf("restrict authority generation: %w", err)
	}
	cleanupGeneration := true
	defer func() {
		if cleanupGeneration {
			_ = os.RemoveAll(generationRoot)
		}
	}()
	if err := writeTLSInspectionFile(filepath.Join(generationRoot, tlsInspectionKeyFile), privatePEM, 0o600); err != nil {
		return nil, fmt.Errorf("write authority key: %w", err)
	}
	if err := writeTLSInspectionFile(filepath.Join(generationRoot, tlsInspectionCertFile), certificatePEM, 0o644); err != nil {
		return nil, fmt.Errorf("write authority certificate: %w", err)
	}
	active := tlsInspectionActiveAuthority{Generation: generation, CreatedAt: now}
	activeData, err := json.Marshal(active)
	if err != nil {
		return nil, err
	}
	if err := writeTLSInspectionFile(filepath.Join(root, tlsInspectionActiveFile), activeData, 0o600); err != nil {
		return nil, fmt.Errorf("activate authority: %w", err)
	}
	resetTLSInspectionLeafPolicySession()
	cleanupGeneration = false
	status, _, err := readTLSInspectionAuthority()
	return status, err
}

func cleanupTLSInspectionGenerations(root, active string) error {
	authoritiesRoot := filepath.Join(root, "authorities")
	entries, err := os.ReadDir(authoritiesRoot)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if entry.Name() == active {
			continue
		}
		path := filepath.Join(authoritiesRoot, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			failures = append(failures, fmt.Errorf("remove stale authority %s: %w", entry.Name(), err))
		}
	}
	return errors.Join(failures...)
}

func readTLSInspectionAuthority() (*TLSInspectionAuthorityStatus, []byte, error) {
	root, err := tlsInspectionRoot()
	if err != nil {
		return nil, nil, err
	}
	base := TLSInspectionAuthorityStatus{
		State:               "missing",
		KeyStorage:          "app-data-file",
		TrustState:          "unknown",
		TrustCapability:     "manual-only",
		CertificateFileName: tlsInspectionExportName,
	}
	if err := tlsInspectionDirectoryStatus(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &base, nil, nil
		}
		base.State = "corrupt"
		base.Issue = "authority-path-unsafe"
		return &base, nil, nil
	}
	activeData, err := readTLSInspectionFile(
		filepath.Join(root, tlsInspectionActiveFile),
		tlsInspectionMaxActiveSize,
	)
	if errors.Is(err, os.ErrNotExist) {
		return &base, nil, nil
	}
	if err != nil {
		base.State = "unavailable"
		base.Issue = "active-record-unreadable"
		return &base, nil, nil
	}
	var active tlsInspectionActiveAuthority
	if err := json.Unmarshal(activeData, &active); err != nil || !validTLSInspectionGeneration(active.Generation) {
		base.State = "corrupt"
		base.Issue = "active-record-invalid"
		return &base, nil, nil
	}
	base.Generation = active.Generation
	base.CreatedAt = active.CreatedAt
	authoritiesRoot := filepath.Join(root, "authorities")
	generationRoot := tlsInspectionGenerationPath(root, active.Generation)
	for _, directory := range []string{authoritiesRoot, generationRoot} {
		if err := tlsInspectionDirectoryStatus(directory); err != nil {
			base.State = "corrupt"
			base.Issue = "authority-path-unsafe"
			return &base, nil, nil
		}
	}
	certificatePEM, certificateErr := readTLSInspectionFile(
		filepath.Join(generationRoot, tlsInspectionCertFile),
		tlsInspectionMaxPEMSize,
	)
	privatePEM, privateErr := readTLSInspectionFile(
		filepath.Join(generationRoot, tlsInspectionKeyFile),
		tlsInspectionMaxPEMSize,
	)
	if certificateErr != nil || privateErr != nil {
		base.State = "corrupt"
		base.Issue = "authority-material-missing"
		return &base, nil, nil
	}
	certificateBlock, rest := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		base.State = "corrupt"
		base.Issue = "certificate-invalid"
		return &base, nil, nil
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		base.State = "corrupt"
		base.Issue = "certificate-invalid"
		return &base, nil, nil
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		base.State = "corrupt"
		base.Issue = "certificate-signature-invalid"
		return &base, nil, nil
	}
	privateBlock, rest := pem.Decode(privatePEM)
	if privateBlock == nil || privateBlock.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		base.State = "corrupt"
		base.Issue = "private-key-invalid"
		return &base, nil, nil
	}
	privateValue, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		base.State = "corrupt"
		base.Issue = "private-key-invalid"
		return &base, nil, nil
	}
	privateKey, ok := privateValue.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		base.State = "corrupt"
		base.Issue = "private-key-unsupported"
		return &base, nil, nil
	}
	certificatePublicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || certificatePublicKey.Curve != elliptic.P256() {
		base.State = "corrupt"
		base.Issue = "certificate-key-unsupported"
		return &base, nil, nil
	}
	certificatePublic, certificateErr := x509.MarshalPKIXPublicKey(certificatePublicKey)
	privatePublic, privateErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if certificateErr != nil || privateErr != nil || !bytes.Equal(certificatePublic, privatePublic) {
		base.State = "corrupt"
		base.Issue = "key-pair-mismatch"
		return &base, nil, nil
	}
	if !certificate.IsCA ||
		!certificate.BasicConstraintsValid ||
		!certificate.MaxPathLenZero ||
		certificate.MaxPathLen != 0 ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		certificate.PublicKeyAlgorithm != x509.ECDSA ||
		certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		certificate.Subject.CommonName != "FlClash Local Inspection CA" ||
		certificate.SerialNumber == nil ||
		certificate.SerialNumber.Sign() <= 0 ||
		certificate.SerialNumber.BitLen() > 128 ||
		len(certificate.SubjectKeyId) != 20 ||
		(len(certificate.AuthorityKeyId) != 0 &&
			!bytes.Equal(certificate.AuthorityKeyId, certificate.SubjectKeyId)) ||
		len(certificate.DNSNames) != 0 ||
		len(certificate.IPAddresses) != 0 ||
		len(certificate.EmailAddresses) != 0 ||
		len(certificate.URIs) != 0 ||
		certificate.NotAfter.Sub(certificate.NotBefore) > tlsInspectionValidity+10*time.Minute ||
		active.CreatedAt.IsZero() ||
		active.CreatedAt.Before(certificate.NotBefore) ||
		active.CreatedAt.After(certificate.NotAfter) {
		base.State = "corrupt"
		base.Issue = "certificate-not-authority"
		return &base, nil, nil
	}
	base.FingerprintSHA256 = tlsInspectionFingerprint(certificate.Raw)
	base.Subject = certificate.Subject.String()
	base.SerialNumber = strings.ToUpper(certificate.SerialNumber.Text(16))
	base.NotBefore = certificate.NotBefore.UTC()
	base.NotAfter = certificate.NotAfter.UTC()
	base.Algorithm = "ECDSA P-256 / SHA-256"
	base.KeyPermissionsRestricted = tlsInspectionPermissionsRestricted(root, generationRoot)
	if err := cleanupTLSInspectionGenerations(root, active.Generation); err != nil {
		base.State = "stale-material-warning"
		base.Issue = "stale-authority-material"
		return &base, certificatePEM, nil
	}
	now := time.Now().UTC()
	switch {
	case now.Before(certificate.NotBefore):
		base.State = "not-yet-valid"
		base.Issue = "certificate-not-yet-valid"
	case !now.Before(certificate.NotAfter):
		base.State = "expired"
		base.Issue = "certificate-expired"
	case !base.KeyPermissionsRestricted:
		base.State = "permissions-warning"
		base.Issue = "private-key-permissions"
	default:
		base.State = "ready"
		base.Ready = true
	}
	return &base, certificatePEM, nil
}

func tlsInspectionPermissionsRestricted(root, generationRoot string) bool {
	if runtime.GOOS == "windows" {
		// ACL verification is not implemented yet. Treating an unverified DACL
		// as restricted would make the safety checklist lie, so Windows stays
		// fail-closed until a native ACL check is available.
		return false
	}
	for _, item := range []struct {
		path string
		mask os.FileMode
	}{
		{root, 0o077},
		{filepath.Join(root, "authorities"), 0o077},
		{generationRoot, 0o077},
		{filepath.Join(root, tlsInspectionActiveFile), 0o077},
		{filepath.Join(generationRoot, tlsInspectionKeyFile), 0o077},
		{filepath.Join(generationRoot, tlsInspectionCertFile), 0o022},
	} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm()&item.mask != 0 {
			return false
		}
	}
	return true
}

func getTLSInspectionAuthorityStatus() (*TLSInspectionAuthorityStatus, error) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	status, _, err := readTLSInspectionAuthority()
	return status, err
}

func ensureTLSInspectionAuthority() (*TLSInspectionAuthorityStatus, *MethodError) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	status, _, err := readTLSInspectionAuthority()
	if err != nil {
		return nil, &MethodError{Code: "authority_unavailable", Message: err.Error()}
	}
	if status.Ready {
		return status, nil
	}
	if status.State != "missing" {
		return nil, &MethodError{
			Code:    "authority_requires_rotation",
			Message: "existing authority is not usable and requires explicit rotation",
			Details: map[string]any{"state": status.State, "issue": status.Issue},
		}
	}
	created, err := createTLSInspectionAuthority()
	if err != nil {
		return nil, &MethodError{Code: "authority_create_failed", Message: err.Error()}
	}
	return created, nil
}

func rotateTLSInspectionAuthority(confirm bool) (*TLSInspectionAuthorityStatus, *MethodError) {
	if !confirm {
		return nil, &MethodError{Code: "confirmation_required", Message: "authority rotation requires explicit confirmation"}
	}
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	created, err := createTLSInspectionAuthority()
	if err != nil {
		return nil, &MethodError{Code: "authority_rotate_failed", Message: err.Error()}
	}
	return created, nil
}

func deleteTLSInspectionAuthority(confirm bool) *MethodError {
	if !confirm {
		return &MethodError{Code: "confirmation_required", Message: "authority deletion requires explicit confirmation"}
	}
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	root, err := tlsInspectionRoot()
	if err != nil {
		return &MethodError{Code: "authority_unavailable", Message: err.Error()}
	}
	resetTLSInspectionLeafPolicySession()
	if err := os.RemoveAll(root); err != nil {
		return &MethodError{Code: "authority_delete_failed", Message: err.Error()}
	}
	return nil
}

func exportTLSInspectionAuthority() (*TLSInspectionAuthorityExport, *MethodError) {
	tlsInspectionAuthorityMu.Lock()
	defer tlsInspectionAuthorityMu.Unlock()
	status, certificatePEM, err := readTLSInspectionAuthority()
	if err != nil {
		return nil, &MethodError{Code: "authority_unavailable", Message: err.Error()}
	}
	if !status.Ready || len(certificatePEM) == 0 {
		return nil, &MethodError{
			Code:    "authority_not_ready",
			Message: "local authority is not ready",
			Details: map[string]any{"state": status.State, "issue": status.Issue},
		}
	}
	return &TLSInspectionAuthorityExport{
		FileName:          tlsInspectionExportName,
		PEM:               string(certificatePEM),
		FingerprintSHA256: status.FingerprintSHA256,
	}, nil
}

func init() {
	registerMethod(getTLSInspectionAuthorityStatusMethod, withoutArguments(func(response MethodResponse) {
		status, err := getTLSInspectionAuthorityStatus()
		if err != nil {
			response.failure("authority_unavailable", err.Error(), nil)
			return
		}
		response.success(status)
	}))
	registerMethod(ensureTLSInspectionAuthorityMethod, withoutArguments(func(response MethodResponse) {
		status, failure := ensureTLSInspectionAuthority()
		if failure != nil {
			response.failure(failure.Code, failure.Message, failure.Details)
			return
		}
		response.success(status)
	}))
	registerMethod(rotateTLSInspectionAuthorityMethod, withArguments(func(params *TLSInspectionConfirmedMutation, response MethodResponse) {
		status, failure := rotateTLSInspectionAuthority(params.Confirm)
		if failure != nil {
			response.failure(failure.Code, failure.Message, failure.Details)
			return
		}
		response.success(status)
	}))
	registerMethod(deleteTLSInspectionAuthorityMethod, withArguments(func(params *TLSInspectionConfirmedMutation, response MethodResponse) {
		if failure := deleteTLSInspectionAuthority(params.Confirm); failure != nil {
			response.failure(failure.Code, failure.Message, failure.Details)
			return
		}
		response.success(true)
	}))
	registerMethod(exportTLSInspectionCertificateMethod, withoutArguments(func(response MethodResponse) {
		value, failure := exportTLSInspectionAuthority()
		if failure != nil {
			response.failure(failure.Code, failure.Message, failure.Details)
			return
		}
		response.success(value)
	}))
}
