# goaccesslog

## Introduction

Copies nginx access log file entries into a sqlite database and optionally
adds firewall rules to reject malicious HTTP requests.
The rules used to detect malicious requests can be configured using a simple grammar, see [sample.json](configs/sample.json)
and [rule.go](internal/rule/rule.go).

Only a fixed nginx access log format is supported.
Start the program to see the required log format.

The program is intended to be used on linux servers.

## Optional RCE kill-switch

The `rceProtection` section in [sample.json](configs/sample.json) enables a
separate Linux process monitor. It is disabled by default; existing configurations
continue to work unchanged. It does not depend on HTTP rules or access-log activity.

- Set `enabled` to `true` and begin with `mode: "monitor"`. This only logs
    unexpected executables, without killing processes, stopping services, or creating
    a lockdown latch.
- Each target requires an explicit non-root `uid` and a nonempty
    `allowedExecutables` list of exact, absolute executable paths. UID 33 is commonly
    `www-data`; check your server. Paths must match `/proc/<pid>/exe`, including
    resolved symlinks. Do not copy the example paths without checking them.
- All four process UIDs (real, effective, saved, filesystem) are considered.
    Every matching target's allowlist must permit the executable. Names and command
    lines are not trusted as process identity.
- Every poll rechecks existing PIDs as well as new ones. Process inspection results
    are not cached: a process can change its executable or UIDs without changing its
    PID. Status parsing and allowlist lookups are optimized without increasing the
    detection interval.
- `pollInterval` defaults to `"1s"`. `response.actionTimeout` defaults to `"10s"`
    per service command. Both must be positive Go duration strings.
- After reviewing legitimate workloads, choose `mode: "enforce"`. Set
    `killDetectedProcess`, `stopServices`, or both. Service names must end in
    `.service`; include only services installed on your server. Commands run directly
    through systemctl, without a shell, with bounded execution time.

Protection requires root, readable host `/proc` entries, and a Linux kernel with
pidfd support (normally Linux 5.3 or newer). Enforcement with service stops also
requires a working systemd/systemctl setup. Startup fails if these checks or the
initial process scan fail. Runtime scan and response failures are logged; failed
service stops and latch writes are retried. Container privileges and restricted
`/proc` mounts may prevent inspection even when running as root.

On an unexpected executable in enforce mode, goaccesslog records the incident in
`response.latchFile`, signals the process using its pidfd if requested, and stops
the configured services. The latch uses atomic writes and survives application
restarts. Its directory and file must be root-owned and not group/world writable;
a missing directory is created with mode 0700. Keep configuration, executable
paths, and all latch-directory ancestors under administrator control.

While latched, service stops are reapplied on every scan, access-log analysis is
paused, and existing goaccesslog IP bans are not released on startup or shutdown.
On restart in enforce mode, services from both the recorded incident and current
configuration are stopped again. Recorded PIDs are never killed after restart.
No additional firewall isolation is installed: stopping web services does not
isolate the host or terminate every process belonging to the web user.

To recover, stop goaccesslog, investigate and remediate the incident, retain a copy
of its incident record, then remove the latch file explicitly. Review existing
firewall bans before restarting goaccesslog and the affected services. Removing
the file while goaccesslog is running does not clear its in-memory lockdown.
Disabling protection or switching to monitor mode deliberately bypasses latch
enforcement; protect write access to the configuration.

This detects unexpected processes, not RCE conclusively. Polling misses short-lived
processes, and arbitrary code inside an allowed executable or interpreter is not
detected. Linux appends ` (deleted)` to `/proc` paths for unlinked executables;
allowlist matching ignores that suffix, so upgrades of running services remain
allowed when their original executable path is allowlisted. An attacker may
also intentionally trigger a service outage. Use narrow allowlists and combine
this containment feature with patching, AppArmor/SELinux, and service sandboxing.

## How to build

- Install Go 1.27.3 (see [go.mod](go.mod)).
- Set CGO_ENABLED=1 and install gcc (required to build sqlite).
- go build
- Example setup for Windows WSL see below

The [GitHub Actions build workflow](.github/workflows/build.yml) builds and tests
all packages on Ubuntu for every push and pull request. It can also be run
manually, uses the Go version from go.mod, and enables CGO for SQLite.
Successful runs publish the Linux amd64 binary as the
`goaccesslog-linux-amd64` artifact on the workflow run page. After downloading
and extracting it, run `chmod +x goaccesslog` to restore executable permissions.

## Setup on Windows using WSL

### wsl
- wsl --update
- wsl --install -d Ubuntu-24.04 --name ubuntu-dev

### ubuntu update & upgrade
- cd
- sudo apt update
- sudo apt upgrade

### install build essential
- sudo apt install build-essential

### install nginx and adjust logging configuration

Note: no other process should listen on port 80

- sudo apt install nginx
- sudo nano /etc/nginx/nginx.conf

    log_format noreferer '$remote_addr - $remote_user [$time_local] $msec "$request" $request_length $status  $body_bytes_sent $request_time "$http_user_agent"';

    access_log /var/log/nginx/access.log noreferer;
- sudo nginx -t
- sudo nginx -s reload
- curl localhost
- sudo cat /var/log/nginx/access.log

### install or upgrade Go

These steps install Go 1.27.3 for Linux amd64 inside WSL. To upgrade an existing
manual installation in `/usr/local/go`, use the same steps: download and extract
the new version first, then remove the old `/usr/local/go` directory before moving
the new one into place. Do not extract a new release over an existing Go
installation. Removing this directory does not remove your project or module cache.

Run these commands from your WSL home directory, not from the project directory.
The removal command below is only for a manual installation at `/usr/local/go`.
If Go was installed using a package manager, upgrade or uninstall it through that
package manager instead.

- cd ~
- curl --fail --location https://dl.google.com/go/go1.27.3.linux-amd64.tar.gz --output go.tar.gz
- gunzip go.tar.gz
- tar xf go.tar
- sudo rm -rf /usr/local/go
- sudo mv go /usr/local/
- rm go.tar
- export PATH=/usr/local/go/bin:$PATH
- hash -r
- command -v go
- go version

Only continue to the next command if the previous one succeeds. Verify that
`command -v go` reports `/usr/local/go/bin/go` and `go version` reports
`go1.27.3 linux/amd64`. Keep `export PATH=/usr/local/go/bin:$PATH` in your
`~/.profile` so new WSL sessions use this installation. If an older version still
appears, run `type -a go` and check for other installations or shell aliases.

After upgrading, return to the project directory, rebuild with `go build`, and
run `go test ./...` with `CGO_ENABLED=1`. Redeploy the rebuilt binary and restart
the running application: installing a newer Go compiler does not update binaries
that were already built.

### download source
- git clone https://github.com/nylssoft/goaccesslog.git
- cd goaccesslog

### build & develop & run
- export CGO_ENABLED=1
- go build
- code .
- sudo ./goaccesslog -config configs/sample.json
- sudo cat /var/log/goaccesslog.log

### build sqlite

Start new bash

- cd
- curl https://www.sqlite.org/2025/sqlite-autoconf-3490200.tar.gz >sqlite.tar.gz
- gunzip sqlite.tar.gz
- tar xf sqlite.tar
- rm sqlite.tar
- cd sqlite-autoconf-3490200/
- ./configure
- make

### test view access log entries
- curl localhost
- wait 1 minute
- sudo ./sqlite3 ../goaccesslog/goaccesslog.db "select * from accesslog;"

### run unit tests and build test coverage
- go test ./... -coverprofile=cover.out
- go tool cover -html=cover.out
