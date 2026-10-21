package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileThenEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sf.yaml")
	os.WriteFile(path, []byte("http_addr: \":9090\"\nflush_interval: 5s\nrules_dir: /etc/rules\n"), 0o644)
	t.Setenv("SF_RULES_DIR", "/override")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":9090" || cfg.FlushInterval != 5*time.Second || cfg.RulesDir != "/override" || cfg.SyslogUDP != ":5514" {
		t.Fatalf("cfg = %+v", cfg)
	}
}
