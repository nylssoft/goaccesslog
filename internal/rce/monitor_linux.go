package rce

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nylssoft/goaccesslog/internal/config"
	"golang.org/x/sys/unix"
)

type process struct {
	PID        int
	UIDs       []uint32
	Executable string
	FD         int
}

type processSystem interface {
	pids() ([]int, error)
	inspect(int) (*process, error)
	kill(*process) error
	close(*process)
	stop(context.Context, string) error
}

type incident struct {
	DetectedAt   time.Time `json:"detectedAt"`
	PID          int       `json:"pid"`
	UID          uint32    `json:"uid"`
	Executable   string    `json:"executable"`
	StopServices []string  `json:"stopServices"`
}

type Monitor struct {
	settings   config.RCEProtection
	allowlists map[uint32]map[string]bool
	system     processSystem
	locked     atomic.Bool
	pending    map[string]bool
	seen       map[string]bool
	evidence   *incident
}

func New(ctx context.Context, settings config.RCEProtection) (*Monitor, error) {
	monitor := &Monitor{settings: settings, pending: make(map[string]bool), seen: make(map[string]bool)}
	if !settings.Enabled {
		return monitor, nil
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("RCE protection requires root to inspect all target processes")
	}
	monitor.allowlists = executableAllowlists(settings.Targets)
	system := &linuxSystem{targets: make(map[uint32]bool)}
	for _, target := range settings.Targets {
		system.targets[*target.UID] = true
	}
	monitor.system = system
	probe, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd support required: %w", err)
	}
	err = unix.PidfdSendSignal(probe, 0, nil, 0)
	unix.Close(probe)
	if err != nil {
		return nil, fmt.Errorf("pidfd signalling unavailable: %w", err)
	}
	if settings.Mode != "enforce" {
		return monitor, nil
	}
	if err := monitor.loadLatch(); err != nil {
		return nil, err
	}
	if len(settings.Response.StopServices) > 0 || len(monitor.pending) > 0 {
		system.systemctl, err = exec.LookPath("systemctl")
		if err != nil {
			return nil, err
		}
		system.systemctl, err = filepath.Abs(system.systemctl)
		if err != nil {
			return nil, err
		}
	}
	for _, service := range settings.Response.StopServices {
		checkCtx, cancel := context.WithTimeout(ctx, monitor.actionTimeout())
		output, err := exec.CommandContext(checkCtx, system.systemctl, "show", "--property=LoadState", "--value", "--", service).CombinedOutput()
		cancel()
		if err != nil || strings.TrimSpace(string(output)) != "loaded" {
			return nil, fmt.Errorf("service %s unavailable: %v: %s", service, err, output)
		}
	}
	return monitor, nil
}

func (monitor *Monitor) Locked() bool {
	return monitor.locked.Load()
}

func (monitor *Monitor) Run(ctx context.Context) {
	if !monitor.settings.Enabled {
		return
	}
	interval, _ := time.ParseDuration(monitor.settings.PollInterval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := monitor.Check(ctx); err != nil {
				log.Printf("ERROR: RCE protection: %v", err)
			}
		}
	}
}

func (monitor *Monitor) Check(ctx context.Context) error {
	if !monitor.settings.Enabled {
		return nil
	}
	pids, scanErr := monitor.system.pids()
	var failures []error
	if monitor.evidence != nil {
		if err := monitor.persist(); err != nil {
			failures = append(failures, err)
		}
	}
	if scanErr != nil {
		failures = append(failures, scanErr)
	}
	seen := make(map[string]bool)
	for _, pid := range pids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		proc, err := monitor.system.inspect(pid)
		if err != nil {
			failures = append(failures, fmt.Errorf("inspect PID %d: %w", pid, err))
			continue
		}
		if proc == nil {
			continue
		}
		uid, unexpected := monitor.unexpected(proc)
		if unexpected {
			key := fmt.Sprintf("%d:%d:%s", proc.PID, uid, proc.Executable)
			seen[key] = true
			if !monitor.seen[key] {
				log.Printf("CRITICAL: Unexpected executable %q, PID %d, UID %d (RCE mode: %s)", proc.Executable, proc.PID, uid, monitor.settings.Mode)
			}
			if monitor.settings.Mode == "enforce" {
				if !monitor.Locked() {
					monitor.locked.Store(true)
					for _, service := range monitor.settings.Response.StopServices {
						monitor.pending[service] = false
					}
					monitor.evidence = &incident{time.Now().UTC(), proc.PID, uid, proc.Executable, monitor.settings.Response.StopServices}
					if err := monitor.persist(); err != nil {
						failures = append(failures, err)
					}
				}
				if monitor.settings.Response.KillDetectedProcess {
					if err := monitor.system.kill(proc); err != nil && !errors.Is(err, unix.ESRCH) {
						failures = append(failures, fmt.Errorf("kill PID %d: %w", pid, err))
					} else {
						log.Printf("RCE response: PID %d terminated or already exited", pid)
					}
				}
			}
		}
		monitor.system.close(proc)
	}
	monitor.seen = seen
	for service := range monitor.pending {
		actionCtx, cancel := context.WithTimeout(ctx, monitor.actionTimeout())
		err := monitor.system.stop(actionCtx, service)
		cancel()
		if err != nil {
			monitor.pending[service] = false
			failures = append(failures, fmt.Errorf("stop %s: %w", service, err))
		} else {
			if !monitor.pending[service] {
				log.Printf("RCE response: stopped %s; lockdown remains latched", service)
			}
			monitor.pending[service] = true
		}
	}
	return errors.Join(failures...)
}

func (monitor *Monitor) unexpected(proc *process) (uint32, bool) {
	for i, uid := range proc.UIDs {
		if i > 0 && uid == proc.UIDs[i-1] {
			continue
		}
		if allowed, targeted := monitor.allowlists[uid]; targeted {
			if !allowed[proc.Executable] && !allowed[strings.TrimSuffix(proc.Executable, " (deleted)")] {
				return uid, true
			}
		}
	}
	return 0, false
}

func executableAllowlists(targets []config.RCETarget) map[uint32]map[string]bool {
	allowlists := make(map[uint32]map[string]bool, len(targets))
	for _, target := range targets {
		allowed := make(map[string]bool, len(target.AllowedExecutables))
		for _, executable := range target.AllowedExecutables {
			allowed[executable] = true
		}
		allowlists[*target.UID] = allowed
	}
	return allowlists
}

func (monitor *Monitor) actionTimeout() time.Duration {
	timeout, _ := time.ParseDuration(monitor.settings.Response.ActionTimeout)
	return timeout
}

func (monitor *Monitor) loadLatch() error {
	directory := filepath.Dir(monitor.settings.Response.LatchFile)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	var directoryStat unix.Stat_t
	if err := unix.Lstat(directory, &directoryStat); err != nil {
		return err
	}
	if !info.IsDir() || directoryStat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("latch directory must be root-owned and not group/world writable")
	}
	fd, err := unix.Open(monitor.settings.Response.LatchFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), monitor.settings.Response.LatchFile)
	defer file.Close()
	var fileStat unix.Stat_t
	if err := unix.Fstat(fd, &fileStat); err != nil {
		return err
	}
	if fileStat.Mode&unix.S_IFMT != unix.S_IFREG || fileStat.Uid != uint32(os.Geteuid()) || fileStat.Mode&0022 != 0 {
		return fmt.Errorf("latch must be a root-owned regular file, not group/world writable")
	}
	var evidence incident
	if err := json.NewDecoder(io.LimitReader(file, 1024*1024)).Decode(&evidence); err != nil {
		return fmt.Errorf("invalid lockdown latch: %w", err)
	}
	if evidence.PID <= 0 || evidence.DetectedAt.IsZero() {
		return fmt.Errorf("invalid lockdown incident")
	}
	monitor.locked.Store(true)
	for _, service := range append(evidence.StopServices, monitor.settings.Response.StopServices...) {
		monitor.pending[service] = false
	}
	log.Printf("RCE lockdown restored from %s; administrator recovery required", file.Name())
	return nil
}

func (monitor *Monitor) writeLatch(evidence incident) error {
	file, err := os.CreateTemp(filepath.Dir(monitor.settings.Response.LatchFile), ".rce-lockdown-*")
	if err != nil {
		return err
	}
	defer file.Close()
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(evidence); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), monitor.settings.Response.LatchFile); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(file.Name()))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (monitor *Monitor) persist() error {
	if err := monitor.writeLatch(*monitor.evidence); err != nil {
		return fmt.Errorf("persist lockdown: %w", err)
	}
	monitor.evidence = nil
	return nil
}

type linuxSystem struct {
	targets   map[uint32]bool
	systemctl string
}

func (system *linuxSystem) pids() ([]int, error) {
	directory, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, name := range names {
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid, err := strconv.Atoi(name)
		if err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func (system *linuxSystem) inspect(pid int) (*process, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	proc := &process{PID: pid, FD: fd}
	keep := false
	defer func() {
		if !keep {
			system.close(proc)
		}
	}()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	uids, dead, err := parseProcessStatus(data)
	if err != nil {
		return nil, err
	}
	if dead {
		return nil, nil
	}
	proc.UIDs = uids[:]
	matched := false
	for _, uid := range uids {
		matched = matched || system.targets[uid]
	}
	if !matched {
		return nil, nil
	}
	proc.Executable, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	var pollFDs = []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	var ready int
	var pollErr error
	for {
		ready, pollErr = unix.Poll(pollFDs, 0)
		if !errors.Is(pollErr, unix.EINTR) {
			break
		}
	}
	if pollErr != nil {
		return nil, pollErr
	}
	if ready != 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	keep = true
	return proc, nil
}

func parseProcessStatus(data []byte) ([4]uint32, bool, error) {
	var uids [4]uint32
	var haveUIDs, haveState bool
	for len(data) > 0 {
		line, rest, _ := bytes.Cut(data, []byte{'\n'})
		data = rest
		if bytes.HasPrefix(line, []byte("State:")) {
			fields := bytes.Fields(line)
			if len(fields) >= 2 {
				if bytes.Equal(fields[1], []byte("Z")) || bytes.Equal(fields[1], []byte("X")) {
					return uids, true, nil
				}
				haveState = true
			}
		} else if bytes.HasPrefix(line, []byte("Uid:")) {
			fields := bytes.Fields(line)
			if len(fields) != 5 {
				return uids, false, fmt.Errorf("missing process UIDs")
			}
			for i, field := range fields[1:] {
				uid, err := strconv.ParseUint(string(field), 10, 32)
				if err != nil {
					return uids, false, err
				}
				uids[i] = uint32(uid)
			}
			haveUIDs = true
		}
		if haveState && haveUIDs {
			break
		}
	}
	if !haveUIDs {
		return uids, false, fmt.Errorf("missing process UIDs")
	}
	return uids, false, nil
}

func (system *linuxSystem) kill(proc *process) error {
	return unix.PidfdSendSignal(proc.FD, unix.SIGKILL, nil, 0)
}

func (system *linuxSystem) close(proc *process) {
	unix.Close(proc.FD)
}

func (system *linuxSystem) stop(ctx context.Context, service string) error {
	output, err := exec.CommandContext(ctx, system.systemctl, "stop", "--", service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}
	return nil
}
