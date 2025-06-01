package app

import (
	"log"
	"os/exec"
	"strings"
	"time"
)

// public

type Info struct {
	locked   bool
	from     time.Time
	to       time.Time
	occurred int
}

type Locks struct {
	ips map[string]Info
}

func NewLocks() *Locks {
	var locks Locks
	locks.ips = make(map[string]Info)
	res, err := exec.Command("ufw", "status").CombinedOutput()
	if err == nil {
		lines := strings.SplitSeq(string(res), "\n")
		for line := range lines {
			idx := strings.LastIndex(line, "# goaccesslog")
			if idx > 0 {
				line = line[0:idx]
				idx = strings.LastIndex(line, "REJECT")
				if idx > 0 {
					ip := strings.TrimSpace(line[idx+len("REJECT"):])
					from := time.Now()
					until := from.Add(time.Hour * 1)
					locks.ips[ip] = Info{locked: true, from: from, to: until, occurred: 1}
				}
			}
		}
	}
	checkError("ufw status", err, res)
	return &locks
}

func (locks *Locks) UnlockAll() {
	for ip, info := range locks.ips {
		if info.locked {
			locks.Unlock(ip)
		}
	}
}

func (locks *Locks) UnlockIfExpired() {
	now := time.Now()
	for ip, info := range locks.ips {
		if info.locked && now.After(info.to) {
			locks.Unlock(ip)
		}
	}
}

func (locks *Locks) IsLocked(ip string) bool {
	info := locks.ips[ip]
	return info.locked
}

func (locks *Locks) Lock(ip string) bool {
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

func (locks *Locks) Unlock(ip string) {
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
