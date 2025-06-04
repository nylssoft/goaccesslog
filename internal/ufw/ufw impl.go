package ufw

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type info struct {
	locked   bool
	from     time.Time
	to       time.Time
	occurred int
}

type ufw_impl struct {
	comment string
	ips     map[string]info
}

func (ufw *ufw_impl) Init() {
	ufw.ips = make(map[string]info)
	match := fmt.Sprintf("# %s", ufw.comment)
	res, err := exec.Command("ufw", "status").CombinedOutput()
	if err == nil {
		lines := strings.SplitSeq(string(res), "\n")
		for line := range lines {
			idx := strings.LastIndex(line, match)
			if idx > 0 {
				line = line[0:idx]
				idx = strings.LastIndex(line, "REJECT")
				if idx > 0 {
					ip := strings.TrimSpace(line[idx+len("REJECT"):])
					from := time.Now()
					until := from.Add(time.Hour * 1)
					ufw.ips[ip] = info{locked: true, from: from, to: until, occurred: 1}
				}
			}
		}
	}
	checkError("ufw status", err, res)
}

func (ufw *ufw_impl) ReleaseAll() {
	for ip, info := range ufw.ips {
		if info.locked {
			ufw.Release(ip)
		}
	}
}

func (ufw *ufw_impl) ReleaseIfExpired() {
	now := time.Now()
	for ip, info := range ufw.ips {
		if info.locked && now.After(info.to) {
			ufw.Release(ip)
		}
	}
}

func (locks *ufw_impl) IsRejected(ip string) bool {
	info := locks.ips[ip]
	return info.locked
}

func (locks *ufw_impl) Reject(ip string) bool {
	info := locks.ips[ip]
	res, err := exec.Command("ufw", "insert", "1", "reject", "from", ip, "to", "any", "comment", "goaccesslog").CombinedOutput()
	if err == nil {
		info.locked = true
		info.from = time.Now()
		info.to = info.from.Add(time.Hour * (1 << info.occurred))
		info.occurred += 1
		if info.occurred > 10 {
			info.occurred = 10
		}
		locks.ips[ip] = info
		log.Println("Lock IP", ip, "until", info.to, ". Detected", info.occurred, "times.")
		return true
	}
	checkError("ufw insert 1 reject from "+ip+" to any comment goaccesslog", err, res)
	return false
}

func (locks *ufw_impl) Release(ip string) {
	res, err := exec.Command("ufw", "delete", "reject", "from", ip, "to", "any").CombinedOutput()
	if err == nil {
		info := locks.ips[ip]
		info.locked = false
		locks.ips[ip] = info
		log.Println("Unlocked IP", ip)
	}
	checkError("ufw delete reject from "+ip+" to any", err, res)
}

// private

func checkError(cmd string, err error, res []byte) {
	if err != nil {
		log.Println("ERROR:", cmd, err, string(res))
	}
}
