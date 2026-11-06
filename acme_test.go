package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager(t *testing.T) *CertificateManager {
	t.Helper()
	dir := t.TempDir()
	return &CertificateManager{
		certificatePath: filepath.Join(dir, "certificate.pem"),
		privateKeyPath:  filepath.Join(dir, "privatekey.pem"),
	}
}

func generateKeyPair(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeKeyPair(t *testing.T, c *CertificateManager, certPEM, keyPEM []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(c.certificatePath, certPEM, 0600))
	require.NoError(t, os.WriteFile(c.privateKeyPath, keyPEM, 0600))
}

func TestNeedsCertificate(t *testing.T) {
	now := time.Now()
	longLivedCert, longLivedKey := generateKeyPair(t, now.Add(-time.Hour), now.AddDate(0, 0, 60))
	expiringCert, expiringKey := generateKeyPair(t, now.Add(-time.Hour), now.AddDate(0, 0, 29))
	_, otherKey := generateKeyPair(t, now.Add(-time.Hour), now.AddDate(0, 0, 60))

	tests := []struct {
		name     string
		cert     []byte
		key      []byte
		expected bool
	}{
		{"valid outside the renewal window", longLivedCert, longLivedKey, false},
		{"inside the renewal window", expiringCert, expiringKey, true},
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
