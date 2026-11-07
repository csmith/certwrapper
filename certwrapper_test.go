package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanReplaceFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, canReplaceFile(filepath.Join(dir, "missing")))

	existing := filepath.Join(dir, "existing")
	require.NoError(t, os.WriteFile(existing, nil, 0600))
	require.NoError(t, canReplaceFile(existing))

	assert.Error(t, canReplaceFile(filepath.Join(dir, "no-such-dir", "file")))
}

func TestCanReplaceFile_writableFileInReadOnlyDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	assert.Error(t, canReplaceFile(path))
}

type fakeRenewer struct {
	needs      bool
	valid      bool
	obtainErr  error
	obtainRuns int
}

func (f *fakeRenewer) NeedsCertificate() bool    { return f.needs }
func (f *fakeRenewer) HasValidCertificate() bool { return f.valid }
func (f *fakeRenewer) ObtainCertificate() error {
	f.obtainRuns++
	return f.obtainErr
}

func TestEnsureCertificate(t *testing.T) {
	failure := errors.New("acme failure")

	tests := []struct {
		name         string
		renewer      fakeRenewer
		expectedErr  error
		expectedRuns int
	}{
		{"not needed", fakeRenewer{needs: false, valid: true}, nil, 0},
		{"obtained", fakeRenewer{needs: true}, nil, 1},
		{"failed with a valid certificate", fakeRenewer{needs: true, valid: true, obtainErr: failure}, nil, 1},
		{"failed without a valid certificate", fakeRenewer{needs: true, obtainErr: failure}, failure, 1},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				err := ensureCertificate(&tt.renewer)
				require.ErrorIs(t, err, tt.expectedErr)
				assert.Equal(t, tt.expectedRuns, tt.renewer.obtainRuns)
			},
		)
	}
}

func TestCheckCertificate(t *testing.T) {
	tests := []struct {
		name            string
		renewer         fakeRenewer
		expectedRuns    int
		expectedReloads int
	}{
		{"not needed", fakeRenewer{needs: false}, 0, 0},
		{"renewed", fakeRenewer{needs: true}, 1, 1},
		{"failed", fakeRenewer{needs: true, obtainErr: errors.New("acme failure")}, 1, 0},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				reloads := 0
				checkCertificate(
					&tt.renewer,
					func() error {
						reloads++
						return nil
					},
				)
				assert.Equal(t, tt.expectedRuns, tt.renewer.obtainRuns)
				assert.Equal(t, tt.expectedReloads, reloads)
			},
		)
	}
}

func TestParseKeyType(t *testing.T) {
	tests := []struct {
		name     string
		expected certcrypto.KeyType
	}{
		{"EC384", certcrypto.EC384},
		{"rsa4096", certcrypto.RSA4096},
		{"P256", certcrypto.EC256},
		{"p384", certcrypto.EC384},
		{"2048", certcrypto.RSA2048},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				kt, err := parseKeyType(tt.name)
				require.NoError(t, err)
				assert.Equal(t, tt.expected, kt)
			},
		)
	}
}

func TestParseKeyType_invalid(t *testing.T) {
	_, err := parseKeyType("P521")
	assert.Error(t, err)
}

func TestParseKeyType_defaultIsValid(t *testing.T) {
	_, err := parseKeyType(flag.Lookup("key-type").DefValue)
	assert.NoError(t, err)
}

func TestChildEnv(t *testing.T) {
	env := childEnv(
		[]string{
			"PATH=/usr/bin",
			"CERTWRAPPER_DOMAINS=example.com",
			"CF_DNS_API_TOKEN=secret",
			"CLOUDFLARE_DNS_API_TOKEN=secret",
			"CLOUDFLARE_EMAIL=me@example.com",
			"HOME=/root",
			"VALUE_WITH_EQUALS=a=b",
		},
		[]string{"CF_DNS_API_TOKEN", " CLOUDFLARE_* ", "", "HOM", "CERTWRAPPER_*"},
	)

	assert.Equal(t, []string{"PATH=/usr/bin", "HOME=/root", "VALUE_WITH_EQUALS=a=b"}, env)
}

func TestChildEnv_neverNil(t *testing.T) {
	env := childEnv([]string{"CERTWRAPPER_DOMAINS=example.com"}, []string{"CERTWRAPPER_*"})
	assert.NotNil(t, env)
	assert.Empty(t, env)
}

func TestSplitDomains(t *testing.T) {
	assert.Equal(
		t,
		[]string{"example.com", "*.example.com", "www.example.com"},
		splitDomains(" example.com, *.example.com ,,www.example.com,"),
	)
}
