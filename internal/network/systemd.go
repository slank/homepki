package network

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type SystemdUnitSpec struct {
	Description      string
	AfterTargets     []string
	WantsTargets     []string
	ExecStart        string
	User             string
	WorkingDirectory string
	RestartPolicy    string
	Environment      map[string]string
}

func RenderSystemdUnit(spec SystemdUnitSpec) (string, error) {
	if strings.TrimSpace(spec.Description) == "" {
		return "", errors.New("description is required")
	}
	if strings.TrimSpace(spec.ExecStart) == "" {
		return "", errors.New("exec start is required")
	}

	if strings.TrimSpace(spec.User) == "" {
		spec.User = "homepki"
	}
	if strings.TrimSpace(spec.RestartPolicy) == "" {
		spec.RestartPolicy = "on-failure"
	}
	if strings.TrimSpace(spec.WorkingDirectory) == "" {
		spec.WorkingDirectory = "/var/lib/homepki"
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString(fmt.Sprintf("Description=%s\n", spec.Description))
	if len(spec.AfterTargets) > 0 {
		b.WriteString(fmt.Sprintf("After=%s\n", strings.Join(spec.AfterTargets, " ")))
	}
	if len(spec.WantsTargets) > 0 {
		b.WriteString(fmt.Sprintf("Wants=%s\n", strings.Join(spec.WantsTargets, " ")))
	}

	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString(fmt.Sprintf("User=%s\n", spec.User))
	b.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", spec.WorkingDirectory))
	b.WriteString(fmt.Sprintf("ExecStart=%s\n", spec.ExecStart))
	b.WriteString(fmt.Sprintf("Restart=%s\n", spec.RestartPolicy))

	if len(spec.Environment) > 0 {
		keys := make([]string, 0, len(spec.Environment))
		for key := range spec.Environment {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			b.WriteString(fmt.Sprintf("Environment=\"%s=%s\"\n", key, escapeSystemdValue(spec.Environment[key])))
		}
	}

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")

	return b.String(), nil
}

func escapeSystemdValue(value string) string {
	return strings.ReplaceAll(value, "\"", "\\\"")
}
