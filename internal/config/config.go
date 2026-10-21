// Package config loads SilentFabric settings from YAML and the environment.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SyslogUDP     string        `yaml:"syslog_udp"`
	HTTPAddr      string        `yaml:"http_addr"`
	ClickHouseDSN string        `yaml:"clickhouse_dsn"`
	RulesDir      string        `yaml:"rules_dir"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	AlertWebhook  string        `yaml:"alert_webhook"`
}

func Default() Config {
	return Config{
		SyslogUDP:     ":5514",
		HTTPAddr:      ":8080",
		ClickHouseDSN: "clickhouse://default:@localhost:9000/silentfabric",
		RulesDir:      "rules",
		BatchSize:     5000,
		FlushInterval: 2 * time.Second,
	}
}

// Load reads path (if non-empty) over the defaults, then applies SF_*
// environment variables, which win.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("%s: %w", path, err)
		}
	}
	env := map[string]*string{
		"SF_SYSLOG_UDP":     &cfg.SyslogUDP,
		"SF_HTTP_ADDR":      &cfg.HTTPAddr,
		"SF_CLICKHOUSE_DSN": &cfg.ClickHouseDSN,
		"SF_RULES_DIR":      &cfg.RulesDir,
		"SF_ALERT_WEBHOOK":  &cfg.AlertWebhook,
	}
	for k, dst := range env {
		if v, ok := os.LookupEnv(k); ok {
			*dst = v
		}
	}
	return cfg, nil
}
