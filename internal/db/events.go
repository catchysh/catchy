package db

import (
	"context"
	"fmt"
	"time"
)

// Event kinds: what happened to a hook as a whole. What happens to each of
// its handlers is in its attempts.
const (
	EventHandled   = "handled"   // its handlers succeeded, or someone marked it handled
	EventDiscarded = "discarded" // someone discarded it
	EventRetried   = "retried"   // someone retried it
	EventFailed    = "failed"    // a handler gave up
)

// eventKinds is the event recorded for each status a hook is set to.
var eventKinds = map[string]string{
	StatusHandled:   EventHandled,
	StatusDiscarded: EventDiscarded,
	StatusPending:   EventRetried,
	StatusFailed:    EventFailed,
}

// Event is something that happened to a hook, and who did it.
type Event struct {
	ID        string
	HookID    string
	Kind      string // one of the Event* constants
	Actor     string // a user's email, "api:" and a key's label, a handler's name, or empty for Catchy
	Message   string // why, for failed
	CreatedAt time.Time
}

// HookEvents returns the events of the given hooks, by hook ID, oldest first.
func (d *DB) HookEvents(ctx context.Context, hookIDs []string) (map[string][]Event, error) {
	out := map[string][]Event{}
	for _, id := range hookIDs {
		rows, err := d.sql.QueryContext(ctx, d.q(`SELECT id, hook_id, kind, actor, message, created_at FROM events WHERE hook_id = ? ORDER BY id`), id)
		if err != nil {
			return nil, fmt.Errorf("listing events: %w", err)
		}
		for rows.Next() {
			var e Event
			if err := rows.Scan(&e.ID, &e.HookID, &e.Kind, &e.Actor, &e.Message, &e.CreatedAt); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scanning event: %w", err)
			}
			out[id] = append(out[id], e)
		}
		rows.Close()
	}
	return out, nil
}
