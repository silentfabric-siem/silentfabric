// Package store writes events and alerts to ClickHouse.
package store

import (
	"context"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/silentfabric-siem/silentfabric/internal/detect"
	"github.com/silentfabric-siem/silentfabric/internal/event"
)

// ClickHouse is a batch writer backed by the schema in deploy/clickhouse.
type ClickHouse struct {
	conn driver.Conn
}

// OpenClickHouse connects using a DSN such as
// clickhouse://default:@localhost:9000/silentfabric.
func OpenClickHouse(ctx context.Context, dsn string) (*ClickHouse, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse clickhouse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}
	return &ClickHouse{conn: conn}, nil
}

func (c *ClickHouse) WriteEvents(ctx context.Context, evs []event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	batch, err := c.conn.PrepareBatch(ctx, "INSERT INTO events (time, received_at, source, host, message, fields, raw)")
	if err != nil {
		return err
	}
	for i := range evs {
		ev := &evs[i]
		if err := batch.Append(ev.Time, ev.ReceivedAt, ev.Source, ev.Host, ev.Message, ev.Fields, ev.Raw); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *ClickHouse) WriteAlerts(ctx context.Context, alerts []detect.Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	batch, err := c.conn.PrepareBatch(ctx, "INSERT INTO alerts (time, rule_id, rule_title, level, tags, host, event_raw)")
	if err != nil {
		return err
	}
	for _, a := range alerts {
		tags := a.Tags
		if tags == nil {
			tags = []string{}
		}
		if err := batch.Append(a.Time, a.RuleID, a.RuleTitle, a.Level, tags, a.Host, a.EventRaw); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *ClickHouse) Close() error { return c.conn.Close() }
