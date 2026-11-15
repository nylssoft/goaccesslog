package rce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	monitor.allowlists = executableAllowlists(monitor.settings.Targets)
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

func TestParseProcessStatus(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		uids [4]uint32
		dead bool
		fail bool
	}{
		{name: "four identities", data: "Name:\tnginx\nState:\tS (sleeping)\nUid:\t33\t34\t35\t36\nGid:\t33\n", uids: [4]uint32{33, 34, 35, 36}},
		{name: "state after UIDs", data: "Uid: 1 2 3 4\nState: R (running)", uids: [4]uint32{1, 2, 3, 4}},
		{name: "maximum UID", data: "State: S\nUid: 0 4294967295 33 0", uids: [4]uint32{0, ^uint32(0), 33, 0}},
		{name: "zombie", data: "State:\tZ (zombie)\n", dead: true},
		{name: "dead", data: "State:\tX (dead)\n", dead: true},
		{name: "missing UIDs", data: "State: S\nGid: 33 33 33 33\n", fail: true},
		{name: "too few UIDs", data: "State: S\nUid: 33 33 33\n", fail: true},
		{name: "too many UIDs", data: "State: S\nUid: 33 33 33 33 33\n", fail: true},
		{name: "invalid UID", data: "State: S\nUid: 33 invalid 33 33\n", fail: true},
		{name: "negative UID", data: "State: S\nUid: 33 -1 33 33\n", fail: true},
		{name: "overflow UID", data: "State: S\nUid: 33 4294967296 33 33\n", fail: true},
		{name: "empty", fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			uids, dead, err := parseProcessStatus([]byte(test.data))
			if test.fail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.uids, uids)
			assert.Equal(t, test.dead, dead)
		})
	}
}

func TestDisabledMonitorIgnoresTargets(t *testing.T) {
	monitor, err := New(context.Background(), config.RCEProtection{
		Targets: []config.RCETarget{{}},
	})
	require.NoError(t, err)
	require.NoError(t, monitor.Check(context.Background()))
}

func TestUnexpectedAllUIDs(t *testing.T) {
	uidA, uidB := uint32(33), uint32(34)
	monitor := &Monitor{allowlists: executableAllowlists([]config.RCETarget{
		{UID: &uidA, AllowedExecutables: []string{"/shared", "/only-a"}},
		{UID: &uidB, AllowedExecutables: []string{"/shared"}},
	})}
	for i := 0; i < 4; i++ {
		uids := []uint32{1000, 1000, 1000, 1000}
		uids[i] = uidB
		uid, unexpected := monitor.unexpected(&process{UIDs: uids, Executable: "/only-a"})
		assert.True(t, unexpected)
		assert.Equal(t, uidB, uid)
	}
	_, unexpected := monitor.unexpected(&process{UIDs: []uint32{uidA, uidB}, Executable: "/shared"})
	assert.False(t, unexpected)
	uid, unexpected := monitor.unexpected(&process{UIDs: []uint32{uidA, uidB}, Executable: "/only-a"})
	assert.True(t, unexpected)
	assert.Equal(t, uidB, uid)
	_, unexpected = monitor.unexpected(&process{UIDs: []uint32{1000}, Executable: "/unexpected"})
	assert.False(t, unexpected)
	_, unexpected = monitor.unexpected(&process{UIDs: []uint32{uidA}, Executable: "/shared (deleted)"})
	assert.False(t, unexpected)

	deletedSuffixPath := "/path (deleted)"
	monitor.allowlists[uidA][deletedSuffixPath] = true
	_, unexpected = monitor.unexpected(&process{UIDs: []uint32{uidA}, Executable: deletedSuffixPath})
	assert.False(t, unexpected)
}

func TestCheckReinspectsSamePID(t *testing.T) {
	for _, change := range []string{"executable", "UID"} {
		t.Run(change, func(t *testing.T) {
			monitor, system := testMonitor(t, "enforce")
			proc := &process{PID: 100, UIDs: []uint32{33, 33, 33, 33}, Executable: "/usr/sbin/nginx"}
			if change == "UID" {
				proc.UIDs = []uint32{1000, 1000, 1000, 1000}
				proc.Executable = "/usr/bin/bash"
			}
			system.processes = []*process{proc}
			require.NoError(t, monitor.Check(context.Background()))
			assert.False(t, monitor.Locked())
			assert.Empty(t, system.killed)
			if change == "executable" {
				proc.Executable = "/usr/bin/bash"
			} else {
				proc.UIDs[3] = 33
			}
			require.NoError(t, monitor.Check(context.Background()))
			assert.True(t, monitor.Locked())
			assert.Equal(t, []int{100}, system.killed)
			assert.Equal(t, 2, system.closed)
		})
	}
}

func TestLinuxPIDs(t *testing.T) {
	system := &linuxSystem{}
	pids, err := system.pids()
	require.NoError(t, err)
	assert.Contains(t, pids, os.Getpid())
	seen := make(map[int]bool)
	for _, pid := range pids {
		assert.Positive(t, pid)
		assert.False(t, seen[pid], "duplicate PID %d", pid)
		seen[pid] = true
	}
}

func BenchmarkLinuxInspect(b *testing.B) {
	system := &linuxSystem{targets: map[uint32]bool{uint32(os.Getuid()): true}}
	b.ReportAllocs()
	for b.Loop() {
		proc, err := system.inspect(os.Getpid())
		if err != nil || proc == nil {
			b.Fatalf("inspect: process=%v, error=%v", proc, err)
		}
		system.close(proc)
	}
}

func BenchmarkLinuxPIDs(b *testing.B) {
	system := &linuxSystem{}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := system.pids(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnexpected(b *testing.B) {
	for _, count := range []int{1, 100} {
		b.Run(fmt.Sprintf("targets=%d", count), func(b *testing.B) {
			monitor := &Monitor{}
			for i := 1; i <= count; i++ {
				uid := uint32(i)
				monitor.settings.Targets = append(monitor.settings.Targets, config.RCETarget{
					UID: &uid, AllowedExecutables: []string{"/usr/sbin/nginx", "/usr/sbin/apache2"},
				})
			}
			monitor.allowlists = executableAllowlists(monitor.settings.Targets)
			proc := &process{UIDs: []uint32{uint32(count), uint32(count), uint32(count), uint32(count)}, Executable: "/usr/sbin/nginx"}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, unexpected := monitor.unexpected(proc); unexpected {
					b.Fatal("allowed process rejected")
				}
			}
		})
	}
}
