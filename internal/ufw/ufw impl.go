package ufw

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nylssoft/goaccesslog/internal/executer"
)

type info struct {
	locked   bool
	from     time.Time
	to       time.Time
	occurred int
}

type ufw_impl struct {
	comment     string
	delay       time.Duration
	maxFailures int
	executer    executer.Executer
	ips         map[string]info
}

func (ufw *ufw_impl) Init() {
	ufw.ips = make(map[string]info)
	match := fmt.Sprintf("# %s", ufw.comment)
	res, err := ufw.executer.Exec("ufw", "status")
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
					until := from.Add(ufw.delay)
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

func (ufw *ufw_impl) IsRejected(ip string) bool {
	info := ufw.ips[ip]
	return info.locked
}

func (ufw *ufw_impl) Reject(ip string) bool {
	info := ufw.ips[ip]
	res, err := ufw.executer.Exec("ufw", "insert", "1", "reject", "from", ip, "to", "any", "comment", "goaccesslog")
	if err == nil {
		info.locked = true
		info.from = time.Now()
		info.to = info.from.Add(ufw.delay * (1 << info.occurred))
		info.occurred += 1
		if info.occurred > ufw.maxFailures {
			info.occurred = ufw.maxFailures
		}
		ufw.ips[ip] = info
		log.Println("Lock IP", ip, "until", info.to, ". Detected", info.occurred, "times.")
		return true
	}
	checkError("ufw insert 1 reject from "+ip+" to any comment goaccesslog", err, res)
	return false
}

func (ufw *ufw_impl) Release(ip string) {
	res, err := ufw.executer.Exec("ufw", "delete", "reject", "from", ip, "to", "any")
	if err == nil {
		info := ufw.ips[ip]
		info.locked = false
		ufw.ips[ip] = info
		log.Println("Unlocked IP", ip)
	}
	checkError("ufw delete reject from "+ip+" to any", err, res)
}

func checkError(cmd string, err error, res []byte) {
	if err != nil {
		log.Println("ERROR:", cmd, err, string(res))
	}
}
