// Package detect runs Sigma rules against events as they stream through.
package detect

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

// Alert is produced when an event matches a rule.
type Alert struct {
	Time      time.Time
	RuleID    string
	RuleTitle string
	Level     string
	Tags      []string
	Host      string
	EventRaw  string
}

type rule struct {
	path string
	sigma.Rule
	eval *evaluator.RuleEvaluator
}

// Engine holds the compiled rule set.
type Engine struct {
	rules []rule
}

// LoadDir parses every .yml/.yaml Sigma rule under dir. All parse errors are
// collected so a rules check reports every broken file at once.
func LoadDir(dir string) (*Engine, error) {
	var (
		e    Engine
		errs []string
	)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		r, err := sigma.ParseRule(b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if len(r.Detection.Conditions) == 0 {
			errs = append(errs, fmt.Sprintf("%s: rule has no condition", path))
			return nil
		}
		e.rules = append(e.rules, rule{path: path, Rule: r, eval: evaluator.ForRule(r)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return &e, fmt.Errorf("%d invalid rule(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return &e, nil
}

// Len reports how many rules are loaded.
func (e *Engine) Len() int { return len(e.rules) }

// Evaluate returns one alert per rule the event matches.
func (e *Engine) Evaluate(ctx context.Context, ev *event.Event) ([]Alert, error) {
	view := ev.SigmaView()
	var alerts []Alert
	for _, r := range e.rules {
		res, err := r.eval.Matches(ctx, view)
		if err != nil {
			return alerts, fmt.Errorf("rule %s: %w", r.path, err)
		}
		if !res.Match {
			continue
		}
		id := r.ID
		if id == "" {
			id = r.path
		}
		alerts = append(alerts, Alert{
			Time:      ev.Time,
			RuleID:    id,
			RuleTitle: r.Title,
			Level:     r.Level,
			Tags:      r.Tags,
			Host:      ev.Host,
			EventRaw:  ev.Raw,
		})
	}
	return alerts, nil
}
