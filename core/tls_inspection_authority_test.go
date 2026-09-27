package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func withTLSInspectionHome(t *testing.T) string {
	t.Helper()
	previous := C.Path.HomeDir()
	home := t.TempDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	return home
}

func TestTLSInspectionAuthorityLifecycle(t *testing.T) {
	home := withTLSInspectionHome(t)

	missing, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if missing.State != "missing" || missing.Ready {
		t.Fatalf("missing status = %#v", missing)
	}

	created, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatalf("create authority: %#v", failure)
	}
	if runtime.GOOS == "windows" {
		if created.Ready || created.State != "permissions-warning" || created.KeyPermissionsRestricted {
			t.Fatalf("Windows authority did not fail closed: %#v", created)
		}
		return
	}
	if !created.Ready || created.State != "ready" || created.FingerprintSHA256 == "" {
		t.Fatalf("created status = %#v", created)
	}
	if created.TrustState != "unknown" || created.TrustCapability != "manual-only" {
		t.Fatalf("trust status = %#v", created)
	}
	if created.CertificateFileName != tlsInspectionExportName {
		t.Fatalf("certificate filename = %q", created.CertificateFileName)
	}

	reused, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatalf("reuse authority: %#v", failure)
	}
	if reused.Generation != created.Generation || reused.FingerprintSHA256 != created.FingerprintSHA256 {
		t.Fatalf("ensure unexpectedly rotated authority: %#v -> %#v", created, reused)
	}

	exported, failure := exportTLSInspectionAuthority()
	if failure != nil {
		t.Fatalf("export authority: %#v", failure)
	}
	if strings.Contains(exported.PEM, "PRIVATE KEY") || exported.FingerprintSHA256 != created.FingerprintSHA256 {
		t.Fatalf("unsafe export = %#v", exported)
	}
	block, rest := pem.Decode([]byte(exported.PEM))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("invalid export PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA {
		t.Fatalf("exported certificate = %#v, %v", certificate, err)
	}

	root := filepath.Join(home, tlsInspectionDirectoryName)
	generationRoot := tlsInspectionGenerationPath(root, created.Generation)
	if runtime.GOOS != "windows" {
		for _, directory := range []string{
			root,
			filepath.Join(root, "authorities"),
			generationRoot,
		} {
			info, err := os.Stat(directory)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o700 {
				t.Fatalf("directory %s mode = %o", directory, info.Mode().Perm())
			}
		}
		keyInfo, err := os.Stat(filepath.Join(generationRoot, tlsInspectionKeyFile))
		if err != nil {
			t.Fatal(err)
		}
		if keyInfo.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode = %o", keyInfo.Mode().Perm())
		}
	}

	rotated, failure := rotateTLSInspectionAuthority(true)
	if failure != nil {
		t.Fatalf("rotate authority: %#v", failure)
	}
	if rotated.Generation == created.Generation || rotated.FingerprintSHA256 == created.FingerprintSHA256 {
		t.Fatalf("rotation did not replace authority: %#v", rotated)
	}
	entries, err := os.ReadDir(filepath.Join(root, "authorities"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != rotated.Generation {
		t.Fatalf("generation cleanup = %#v", entries)
	}

	if failure := deleteTLSInspectionAuthority(true); failure != nil {
		t.Fatalf("delete authority: %#v", failure)
	}
	deleted, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if deleted.State != "missing" || deleted.Ready {
		t.Fatalf("deleted status = %#v", deleted)
	}
}

func TestTLSInspectionAuthorityConcurrentEnsureIsStable(t *testing.T) {
	home := withTLSInspectionHome(t)
	const workers = 12
	statuses := make(chan *TLSInspectionAuthorityStatus, workers)
	failures := make(chan *MethodError, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, failure := ensureTLSInspectionAuthority()
			statuses <- status
			failures <- failure
		}()
	}
	wait.Wait()
	close(statuses)
	close(failures)

	for failure := range failures {
		if failure != nil {
			t.Fatalf("concurrent ensure failed: %#v", failure)
		}
	}
	var generation, fingerprint string
	for status := range statuses {
		if status == nil || !status.Ready {
			t.Fatalf("concurrent ensure status = %#v", status)
		}
		if generation == "" {
			generation = status.Generation
			fingerprint = status.FingerprintSHA256
			continue
		}
		if status.Generation != generation || status.FingerprintSHA256 != fingerprint {
			t.Fatalf("concurrent ensure rotated authority: %#v", status)
		}
	}
	entries, err := os.ReadDir(filepath.Join(home, tlsInspectionDirectoryName, "authorities"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != generation {
		t.Fatalf("concurrent generations = %#v", entries)
	}
}

func TestTLSInspectionAuthorityCleansStaleGenerationsOnRead(t *testing.T) {
	home := withTLSInspectionHome(t)
	created, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatal(failure)
	}
	stale := filepath.Join(home, tlsInspectionDirectoryName, "authorities", "stale-generation")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, tlsInspectionKeyFile), []byte("stale-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Generation != created.Generation {
		t.Fatalf("status after stale cleanup = %#v", status)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale generation still exists: %v", err)
	}
}

func TestTLSInspectionAuthorityFailsClosedWhenStaleMaterialCannotBeRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permissions are ACL-based")
	}
	home := withTLSInspectionHome(t)
	created, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatal(failure)
	}
	authoritiesRoot := filepath.Join(home, tlsInspectionDirectoryName, "authorities")
	stale := filepath.Join(authoritiesRoot, "stale-generation")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, tlsInspectionKeyFile), []byte("stale-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(authoritiesRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(authoritiesRoot, 0o700) })

	status, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.State != "stale-material-warning" || status.Issue != "stale-authority-material" {
		t.Fatalf("stale material status = %#v (active %s)", status, created.Generation)
	}
}

func TestTLSInspectionAuthorityRequiresConfirmation(t *testing.T) {
	withTLSInspectionHome(t)
	if _, failure := rotateTLSInspectionAuthority(false); failure == nil || failure.Code != "confirmation_required" {
		t.Fatalf("rotation confirmation = %#v", failure)
	}
	if failure := deleteTLSInspectionAuthority(false); failure == nil || failure.Code != "confirmation_required" {
		t.Fatalf("deletion confirmation = %#v", failure)
	}
}

func TestTLSInspectionAuthorityDetectsCorruption(t *testing.T) {
	home := withTLSInspectionHome(t)
	created, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatalf("create authority: %#v", failure)
	}
	keyPath := filepath.Join(
		home,
		tlsInspectionDirectoryName,
		"authorities",
		created.Generation,
		tlsInspectionKeyFile,
	)
	if err := os.WriteFile(keyPath, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.State != "corrupt" || status.Issue != "private-key-invalid" {
		t.Fatalf("corrupt status = %#v", status)
	}
	if _, failure := ensureTLSInspectionAuthority(); failure == nil || failure.Code != "authority_requires_rotation" {
		t.Fatalf("corrupt ensure = %#v", failure)
	}
}

func TestTLSInspectionAuthorityDetectsInvalidSelfSignature(t *testing.T) {
	home := withTLSInspectionHome(t)
	created, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatalf("create authority: %#v", failure)
	}
	certificatePath := filepath.Join(
		home,
		tlsInspectionDirectoryName,
		"authorities",
		created.Generation,
		tlsInspectionCertFile,
	)
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(certificatePEM)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatal("invalid generated certificate PEM")
	}
	block.Bytes[len(block.Bytes)-1] ^= 0x01
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatal(err)
	}

	status, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.State != "corrupt" || status.Issue != "certificate-signature-invalid" {
		t.Fatalf("signature status = %#v", status)
	}
}

func TestTLSInspectionAuthorityReportsPermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file permissions are ACL-based")
	}
	home := withTLSInspectionHome(t)
	created, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatalf("create authority: %#v", failure)
	}
	keyPath := filepath.Join(
		home,
		tlsInspectionDirectoryName,
		"authorities",
		created.Generation,
		tlsInspectionKeyFile,
	)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	status, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.State != "permissions-warning" || status.KeyPermissionsRestricted {
		t.Fatalf("permission status = %#v", status)
	}
}

func TestTLSInspectionAuthorityRejectsASymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation needs elevated privileges")
	}
	home := withTLSInspectionHome(t)
	outside := t.TempDir()
	root := filepath.Join(home, tlsInspectionDirectoryName)
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}

	if _, failure := ensureTLSInspectionAuthority(); failure == nil || failure.Code != "authority_requires_rotation" {
		t.Fatalf("symlinked root failure = %#v", failure)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target was modified: %#v", entries)
	}
}

func TestTLSInspectionAuthorityRejectsSymlinkedMaterial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation needs elevated privileges")
	}
	home := withTLSInspectionHome(t)
	created, failure := ensureTLSInspectionAuthority()
	if failure != nil {
		t.Fatal(failure)
	}
	generationRoot := tlsInspectionGenerationPath(
		filepath.Join(home, tlsInspectionDirectoryName),
		created.Generation,
	)
	keyPath := filepath.Join(generationRoot, tlsInspectionKeyFile)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(generationRoot, tlsInspectionCertFile), keyPath); err != nil {
		t.Fatal(err)
	}

	status, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.State != "corrupt" || status.Issue != "authority-material-missing" {
		t.Fatalf("symlinked material status = %#v", status)
	}
}

func TestTLSInspectionAuthorityBoundsTheActiveRecord(t *testing.T) {
	home := withTLSInspectionHome(t)
	root := filepath.Join(home, tlsInspectionDirectoryName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, tlsInspectionActiveFile),
		make([]byte, tlsInspectionMaxActiveSize+1),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	status, err := getTLSInspectionAuthorityStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.State != "unavailable" || status.Issue != "active-record-unreadable" {
		t.Fatalf("oversized active record status = %#v", status)
	}
}

func TestTLSInspectionAuthorityMethodsAreRegistered(t *testing.T) {
	for _, method := range []CoreMethod{
		getTLSInspectionAuthorityStatusMethod,
		ensureTLSInspectionAuthorityMethod,
		rotateTLSInspectionAuthorityMethod,
		deleteTLSInspectionAuthorityMethod,
		exportTLSInspectionCertificateMethod,
	} {
		if _, exists := methodHandlers[method]; !exists {
			t.Fatalf("Core method %s is not registered", method)
		}
	}
}
