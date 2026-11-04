package rce

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nylssoft/goaccesslog/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSystem struct {
	processes []*process
	killed    []int
	closed    int
	stopped   []string
	stopError error
	scanError error
	killError error
}

func (system *fakeSystem) pids() ([]int, error) {
	var pids []int
	for _, proc := range system.processes {
		pids = append(pids, proc.PID)
	}
	return pids, system.scanError
}

func (system *fakeSystem) inspect(pid int) (*process, error) {
	for _, proc := range system.processes {
		if proc.PID == pid {
			return proc, nil
		}
	}
	return nil, nil
}

func (system *fakeSystem) kill(proc *process) error {
	system.killed = append(system.killed, proc.PID)
	return system.killError
}

func (system *fakeSystem) close(proc *process) {
	system.closed++
}

func (system *fakeSystem) stop(ctx context.Context, service string) error {
	system.stopped = append(system.stopped, service)
	_, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		return errors.New("missing action timeout")
	}
	return system.stopError
}

func testMonitor(t *testing.T, mode string) (*Monitor, *fakeSystem) {
	uid := uint32(33)
	system := &fakeSystem{processes: []*process{
		{PID: 100, UIDs: []uint32{33}, Executable: "/usr/sbin/nginx"},
		{PID: 101, UIDs: []uint32{33}, Executable: "/usr/bin/bash"},
		{PID: 102, UIDs: []uint32{1000}, Executable: "/usr/bin/bash"},
	}}
	monitor := &Monitor{
		settings: config.RCEProtection{
			Enabled: true, Mode: mode, PollInterval: "1ms",
			Targets: []config.RCETarget{{UID: &uid, AllowedExecutables: []string{"/usr/sbin/nginx"}}},
			Response: config.RCEResponse{
				KillDetectedProcess: true, StopServices: []string{"nginx.service"},
				ActionTimeout: "1s", LatchFile: filepath.Join(t.TempDir(), "lockdown.json"),
			},
		},
		system: system, pending: make(map[string]bool), seen: make(map[string]bool),
	}
	return monitor, system
}

func TestMonitorOnly(t *testing.T) {
	monitor, system := testMonitor(t, "monitor")
	require.NoError(t, monitor.Check(context.Background()))
	assert.Empty(t, system.killed)
	assert.Empty(t, system.stopped)
	assert.False(t, monitor.Locked())
	assert.Len(t, monitor.seen, 1)
	assert.NoFileExists(t, monitor.settings.Response.LatchFile)
	assert.Equal(t, 3, system.closed)
}

func TestEnforcement(t *testing.T) {
	monitor, system := testMonitor(t, "enforce")
	require.NoError(t, monitor.Check(context.Background()))
	assert.Equal(t, []int{101}, system.killed)
	assert.Equal(t, []string{"nginx.service"}, system.stopped)
	assert.True(t, monitor.Locked())
	data, err := os.ReadFile(monitor.settings.Response.LatchFile)
	require.NoError(t, err)
	var evidence incident
	require.NoError(t, json.Unmarshal(data, &evidence))
	assert.Equal(t, 101, evidence.PID)
	assert.Equal(t, uint32(33), evidence.UID)
	assert.Equal(t, "/usr/bin/bash", evidence.Executable)
	system.processes = nil
	require.NoError(t, monitor.Check(context.Background()))
	assert.FileExists(t, monitor.settings.Response.LatchFile)
	assert.True(t, monitor.Locked())
	assert.Len(t, system.stopped, 2)
}

func TestResponseFailuresAndRetry(t *testing.T) {
	monitor, system := testMonitor(t, "enforce")
	system.killError = errors.New("kill denied")
	system.stopError = errors.New("stop denied")
	err := monitor.Check(context.Background())
	require.ErrorContains(t, err, "kill denied")
	assert.ErrorContains(t, err, "stop denied")
	assert.FileExists(t, monitor.settings.Response.LatchFile)
	system.processes = nil
	system.stopError = nil
	require.NoError(t, monitor.Check(context.Background()))
	assert.Len(t, system.stopped, 2)
	assert.True(t, monitor.pending["nginx.service"])
}

func TestLatchFailureStillContains(t *testing.T) {
	monitor, system := testMonitor(t, "enforce")
	monitor.settings.Response.LatchFile = filepath.Join(t.TempDir(), "missing", "lockdown.json")
	require.ErrorContains(t, monitor.Check(context.Background()), "persist lockdown")
	assert.Equal(t, []int{101}, system.killed)
	assert.Len(t, system.stopped, 1)
	assert.True(t, monitor.Locked())
}

func TestLatchWriteRetried(t *testing.T) {
	monitor, system := testMonitor(t, "enforce")
	directory := filepath.Join(t.TempDir(), "missing")
	monitor.settings.Response.LatchFile = filepath.Join(directory, "lockdown.json")
	require.Error(t, monitor.Check(context.Background()))
	require.NoError(t, os.Mkdir(directory, 0700))
	system.processes = nil
	require.NoError(t, monitor.Check(context.Background()))
	assert.FileExists(t, monitor.settings.Response.LatchFile)
}

func TestRestoreLockdown(t *testing.T) {
	monitor, _ := testMonitor(t, "enforce")
	require.NoError(t, monitor.Check(context.Background()))
	restored, system := testMonitor(t, "enforce")
	restored.settings.Response.LatchFile = monitor.settings.Response.LatchFile
	require.NoError(t, restored.loadLatch())
	assert.True(t, restored.Locked())
	system.processes = nil
	require.NoError(t, restored.Check(context.Background()))
	assert.Equal(t, []string{"nginx.service"}, system.stopped)
	assert.Empty(t, system.killed)
}

func TestInvalidLatch(t *testing.T) {
	monitor, _ := testMonitor(t, "enforce")
	require.NoError(t, os.WriteFile(monitor.settings.Response.LatchFile, []byte("broken"), 0600))
	assert.ErrorContains(t, monitor.loadLatch(), "invalid lockdown latch")
	require.NoError(t, os.Remove(monitor.settings.Response.LatchFile))
	require.NoError(t, os.Symlink("missing", monitor.settings.Response.LatchFile))
	assert.Error(t, monitor.loadLatch())
}

func TestScanFailureReported(t *testing.T) {
	monitor, system := testMonitor(t, "monitor")
	system.scanError = errors.New("proc unavailable")
	assert.ErrorContains(t, monitor.Check(context.Background()), "proc unavailable")
}

func TestRunCancellation(t *testing.T) {
	monitor, _ := testMonitor(t, "monitor")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		monitor.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop")
	}
}

func TestLinuxInspect(t *testing.T) {
	system := &linuxSystem{targets: map[uint32]bool{uint32(os.Getuid()): true}}
	proc, err := system.inspect(os.Getpid())
	require.NoError(t, err)
	require.NotNil(t, proc)
	defer system.close(proc)
	executable, err := os.Readlink("/proc/self/exe")
	require.NoError(t, err)
	assert.Equal(t, executable, proc.Executable)
	assert.Contains(t, proc.UIDs, uint32(os.Getuid()))
	assert.GreaterOrEqual(t, proc.FD, 0)
	missing, err := system.inspect(1 << 30)
	require.NoError(t, err)
	assert.Nil(t, missing)
}
