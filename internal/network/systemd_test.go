package network

import (
	"strings"
	"testing"
)

func TestRenderSystemdUnit(t *testing.T) {
	t.Parallel()

	unit, err := RenderSystemdUnit(SystemdUnitSpec{
		Description:  "HomePKI Service",
		AfterTargets: []string{"network-online.target"},
		WantsTargets: []string{"network-online.target"},
		ExecStart:    "/usr/local/bin/homepki -config /etc/homepki/config.yaml",
		Environment: map[string]string{
			"HOMEPKI_SESSION_SECRET": "test-secret",
		},
	})
	if err != nil {
		t.Fatalf("render systemd unit: %v", err)
	}

	requiredLines := []string{
		"[Unit]",
		"Description=HomePKI Service",
		"After=network-online.target",
		"[Service]",
		"ExecStart=/usr/local/bin/homepki -config /etc/homepki/config.yaml",
		"Environment=\"HOMEPKI_SESSION_SECRET=test-secret\"",
		"[Install]",
		"WantedBy=multi-user.target",
	}

	for _, line := range requiredLines {
		if !strings.Contains(unit, line) {
			t.Fatalf("expected unit to contain %q, got:\n%s", line, unit)
		}
	}
}
