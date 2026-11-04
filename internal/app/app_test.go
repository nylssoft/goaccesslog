package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunWithoutRCEProtection(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "ufw"), []byte("#!/bin/sh\nexit 0\n"), 0700))
	t.Setenv("PATH", directory)
	accessLog := filepath.Join(directory, "access.log")
	require.NoError(t, os.WriteFile(accessLog, nil, 0600))
	data, err := json.Marshal(map[string]any{
		"nginx":    map[string]any{"accessLogFilename": accessLog},
		"database": map[string]any{"filename": filepath.Join(directory, "access.db")},
		"logger":   map[string]any{"filename": filepath.Join(directory, "app.log")},
	})
	require.NoError(t, err)
	filename := filepath.Join(directory, "config.json")
	require.NoError(t, os.WriteFile(filename, data, 0600))
	shutdown := make(chan bool, 1)
	shutdown <- true
	assert.Equal(t, 0, Run(filename, shutdown))
}
