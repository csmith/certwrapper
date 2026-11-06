package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanReplaceFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, canReplaceFile(filepath.Join(dir, "missing")))
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
