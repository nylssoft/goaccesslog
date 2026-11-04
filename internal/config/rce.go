package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"time"
)

type RCEProtection struct {
	Enabled      bool        `json:"enabled"`
	Mode         string      `json:"mode"`
	PollInterval string      `json:"pollInterval"`
	Targets      []RCETarget `json:"targets"`
	Response     RCEResponse `json:"response"`
}

type RCETarget struct {
	UID                *uint32  `json:"uid"`
	AllowedExecutables []string `json:"allowedExecutables"`
}

type RCEResponse struct {
	KillDetectedProcess bool     `json:"killDetectedProcess"`
	StopServices        []string `json:"stopServices"`
	ActionTimeout       string   `json:"actionTimeout"`
	LatchFile           string   `json:"latchFile"`
}

func (settings *RCEProtection) validate() error {
	if !settings.Enabled {
		return nil
	}
	if settings.Mode == "" {
		settings.Mode = "monitor"
	}
	if settings.Mode != "monitor" && settings.Mode != "enforce" {
		return fmt.Errorf("mode must be monitor or enforce")
	}
	if settings.PollInterval == "" {
		settings.PollInterval = "1s"
	}
	if settings.Response.ActionTimeout == "" {
		settings.Response.ActionTimeout = "10s"
	}
	for _, duration := range []string{settings.PollInterval, settings.Response.ActionTimeout} {
		value, err := time.ParseDuration(duration)
		if err != nil || value <= 0 {
			return fmt.Errorf("invalid positive duration %q", duration)
		}
	}
	if len(settings.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	seen := make(map[uint32]bool)
	for _, target := range settings.Targets {
		if target.UID == nil || *target.UID == 0 {
			return fmt.Errorf("each target needs an explicit non-root uid")
		}
		if seen[*target.UID] {
			return fmt.Errorf("duplicate target uid %d", *target.UID)
		}
		seen[*target.UID] = true
		if len(target.AllowedExecutables) == 0 {
			return fmt.Errorf("uid %d has an empty executable allowlist", *target.UID)
		}
		for _, executable := range target.AllowedExecutables {
			if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
				return fmt.Errorf("executable must be a clean absolute path: %q", executable)
			}
		}
	}
	serviceName := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@:-]*\.service$`)
	for _, service := range settings.Response.StopServices {
		if !serviceName.MatchString(service) {
			return fmt.Errorf("invalid service name %q", service)
		}
	}
	if settings.Mode == "enforce" {
		if !settings.Response.KillDetectedProcess && len(settings.Response.StopServices) == 0 {
			return fmt.Errorf("enforce mode requires at least one response action")
		}
		if !filepath.IsAbs(settings.Response.LatchFile) || filepath.Clean(settings.Response.LatchFile) != settings.Response.LatchFile {
			return fmt.Errorf("enforce mode requires a clean absolute latchFile")
		}
	}
	return nil
}
