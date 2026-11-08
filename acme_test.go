package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager(t *testing.T) *CertificateManager {
	t.Helper()
	dir := t.TempDir()
	return &CertificateManager{
		keyType:         certcrypto.EC256,
		domains:         []string{"example.com"},
		certificatePath: filepath.Join(dir, "certificate.pem"),
		privateKeyPath:  filepath.Join(dir, "privatekey.pem"),
	}
}

func newTestUser(t *testing.T) *AcmeUser {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &AcmeUser{LiveKey: key}
}

func generateKeyPair(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	return generateCustomKeyPair(t, generateKey(t, certcrypto.EC256), notBefore, notAfter, "example.com")
}

func generateKey(t *testing.T, keyType certcrypto.KeyType) crypto.Signer {
	t.Helper()
	key, err := certcrypto.GeneratePrivateKey(keyType)
	require.NoError(t, err)
	return key
}

func generateCustomKeyPair(
	t *testing.T,
	key crypto.Signer,
	notBefore, notAfter time.Time,
	domains ...string,
) (certPEM, keyPEM []byte) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writeKeyPair(t *testing.T, c *CertificateManager, certPEM, keyPEM []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(c.certificatePath, certPEM, 0600))
	require.NoError(t, os.WriteFile(c.privateKeyPath, keyPEM, 0600))
}

func TestNeedsCertificate(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	longLivedCert, longLivedKey := generateKeyPair(t, now.Add(-59*day), now.Add(31*day))
	expiringCert, expiringKey := generateKeyPair(t, now.Add(-61*day), now.Add(29*day))
	freshShortCert, freshShortKey := generateKeyPair(t, now.Add(-time.Hour), now.Add(6*day-time.Hour))
	expiringShortCert, expiringShortKey := generateKeyPair(t, now.Add(-5*day), now.Add(day))
	_, otherKey := generateKeyPair(t, now.Add(-time.Hour), now.AddDate(0, 0, 60))

	tests := []struct {
		name     string
		cert     []byte
		key      []byte
		expected bool
	}{
		{"more than a third of its lifetime left", longLivedCert, longLivedKey, false},
		{"less than a third of its lifetime left", expiringCert, expiringKey, true},
		{"newly issued short-lived certificate", freshShortCert, freshShortKey, false},
		{"short-lived certificate near expiry", expiringShortCert, expiringShortKey, true},
		{"key doesn't match certificate", longLivedCert, otherKey, true},
		{"truncated key", longLivedCert, longLivedKey[:10], true},
		{"empty certificate", []byte{}, longLivedKey, true},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				c := newTestManager(t)
				writeKeyPair(t, c, tt.cert, tt.key)
				assert.Equal(t, tt.expected, c.NeedsCertificate())
			},
		)
	}

	t.Run(
		"no files",
		func(t *testing.T) {
			assert.True(t, newTestManager(t).NeedsCertificate())
		},
	)
}

func TestNeedsCertificate_domainChanges(t *testing.T) {
	now := time.Now()
	key := generateKey(t, certcrypto.EC256)

	tests := []struct {
		name        string
		certDomains []string
		configured  []string
		expected    bool
	}{
		{"different order", []string{"a.example.com", "b.example.com"}, []string{"b.example.com", "a.example.com"}, false},
		{"different case", []string{"example.com"}, []string{"Example.COM"}, false},
		{"duplicate configured domain", []string{"example.com"}, []string{"example.com", "example.com"}, false},
		{"matching wildcard", []string{"example.com", "*.example.com"}, []string{"*.example.com", "example.com"}, false},
		{"unicode domain against punycode", []string{"xn--bcher-kva.example"}, []string{"bücher.example"}, false},
		{"mixed case unicode domain against punycode", []string{"xn--bcher-kva.example"}, []string{"Bücher.Example"}, false},
		{"unicode wildcard against punycode", []string{"*.xn--bcher-kva.example"}, []string{"*.bücher.example"}, false},
		{"different unicode domain", []string{"xn--bcher-kva.example"}, []string{"bucher.example"}, true},
		{"domain added", []string{"example.com"}, []string{"example.com", "www.example.com"}, true},
		{"domain removed", []string{"example.com", "www.example.com"}, []string{"example.com"}, true},
		{"domain replaced", []string{"example.com"}, []string{"example.org"}, true},
		{"wildcard replaced by its base domain", []string{"*.example.com"}, []string{"example.com"}, true},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				c := newTestManager(t)
				c.domains = tt.configured
				certPEM, keyPEM := generateCustomKeyPair(
					t,
					key,
					now.Add(-time.Hour),
					now.AddDate(0, 0, 90),
					tt.certDomains...,
				)
				writeKeyPair(t, c, certPEM, keyPEM)
				assert.Equal(t, tt.expected, c.NeedsCertificate())
			},
		)
	}
}

func TestNeedsCertificate_keyTypeChanges(t *testing.T) {
	now := time.Now()
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name       string
		certKey    crypto.Signer
		configured certcrypto.KeyType
		expected   bool
	}{
		{"same key type", generateKey(t, certcrypto.EC384), certcrypto.EC384, false},
		{"different curve", generateKey(t, certcrypto.EC256), certcrypto.EC384, true},
		{"EC to RSA", generateKey(t, certcrypto.EC384), certcrypto.RSA2048, true},
		{"RSA to EC", generateKey(t, certcrypto.RSA2048), certcrypto.EC256, true},
		{"different RSA size", generateKey(t, certcrypto.RSA2048), certcrypto.RSA3072, true},
		{"unknown certificate key type", p521Key, certcrypto.EC384, false},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				c := newTestManager(t)
				c.keyType = tt.configured
				certPEM, keyPEM := generateCustomKeyPair(
					t,
					tt.certKey,
					now.Add(-time.Hour),
					now.AddDate(0, 0, 90),
					"example.com",
				)
				writeKeyPair(t, c, certPEM, keyPEM)
				assert.Equal(t, tt.expected, c.NeedsCertificate())
			},
		)
	}
}

func TestHasValidCertificate(t *testing.T) {
	now := time.Now()
	validCert, validKey := generateKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour))
	expiredCert, expiredKey := generateKeyPair(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	futureCert, futureKey := generateKeyPair(t, now.Add(time.Hour), now.Add(2*time.Hour))

	tests := []struct {
		name     string
		cert     []byte
		key      []byte
		expected bool
	}{
		{"within its validity period", validCert, validKey, true},
		{"expired", expiredCert, expiredKey, false},
		{"not yet valid", futureCert, futureKey, false},
		{"key doesn't match certificate", validCert, expiredKey, false},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				c := newTestManager(t)
				writeKeyPair(t, c, tt.cert, tt.key)
				assert.Equal(t, tt.expected, c.HasValidCertificate())
			},
		)
	}

	t.Run(
		"no files",
		func(t *testing.T) {
			assert.False(t, newTestManager(t).HasValidCertificate())
		},
	)
}

func TestObtainCertificate_keepsExistingFilesWhenServerUnavailable(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	server.Close()

	now := time.Now()
	certPEM, keyPEM := generateKeyPair(t, now.Add(-time.Hour), now.AddDate(0, 0, 10))

	c := newTestManager(t)
	c.acmeProvider = server.URL
	c.user = newTestUser(t)
	writeKeyPair(t, c, certPEM, keyPEM)

	require.Error(t, c.ObtainCertificate())

	assert.True(t, c.HasValidCertificate())
	content, err := os.ReadFile(c.certificatePath)
	require.NoError(t, err)
	assert.Equal(t, certPEM, content)
}

func TestWriteFileAtomic_replacesFileAndTightensPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0644))
	require.NoError(t, os.Chmod(path, 0644))

	require.NoError(t, writeFileAtomic(path, []byte("new")))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new", string(content))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestWriteFileAtomic_leavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFileAtomic(filepath.Join(dir, "file"), []byte("data")))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "file", entries[0].Name())
}

func TestWriteFileAtomic_cleansUpWhenReplaceFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0700))

	require.Error(t, writeFileAtomic(target, []byte("data")))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "target", entries[0].Name())
}
