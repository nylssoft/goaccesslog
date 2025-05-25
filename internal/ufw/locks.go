package ufw

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Locks struct {
	ips map[string]time.Time
}

func NewLocks() *Locks {
	var locks Locks
	locks.ips = make(map[string]time.Time)
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
					locks.ips[ip] = time.Now()
				}
			}
		}
	}
	checkError("ufw status", err, res)
	return &locks
}

func (locks *Locks) RemoveAll() {
	for ip := range locks.ips {
		locks.Remove(ip)
	}
}

func (locks *Locks) RemoveAfter(duration time.Duration) {
	now := time.Now()
	for ip, t := range locks.ips {
		dur := now.Sub(t)
		if dur > duration {
			locks.Remove(ip)
		}
	}
}

func (locks *Locks) Add(ip string) {
	res, err := exec.Command("ufw", "insert", "1", "reject", "from", ip, "to", "any", "comment", "goaccesslog").CombinedOutput()
	if err == nil {
		locks.ips[ip] = time.Now()
		fmt.Println("Lock IP", ip)
	}
	checkError("ufw insert 1 reject from "+ip+" to any comment goaccesslog", err, res)
}

func (locks *Locks) Remove(ip string) {
	res, err := exec.Command("ufw", "delete", "reject", "from", ip, "to", "any").CombinedOutput()
	if err == nil {
		delete(locks.ips, ip)
		fmt.Println("Unlocked IP", ip)
	}
	checkError("ufw delete reject from "+ip+" to any", err, res)
}

func checkError(cmd string, err error, res []byte) {
	if err != nil {
		fmt.Println("ERROR:", cmd, err, string(res))
	}
}
