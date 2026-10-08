package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// DefaultChannel catches hooks sent without a channel.
const DefaultChannel = "default"

var channelPattern = regexp.MustCompile(`^[a-z0-9]+(?:[_-][a-z0-9]+)*$`)

// ValidChannel reports whether name is a valid channel name: up to 64
// lowercase letters and digits, optionally separated by single "_" or "-".
func ValidChannel(name string) bool {
	return len(name) <= 64 && channelPattern.MatchString(name)
}

// Hook statuses. Hooks start pending; consumers set the others.
const (
	StatusPending   = "pending"
	StatusProcessed = "processed"
	StatusFailed    = "failed"
	StatusDiscarded = "discarded"
)

// Statuses lists every hook status, in display order.
var Statuses = []string{StatusPending, StatusProcessed, StatusFailed, StatusDiscarded}

// ValidStatus reports whether s is a hook status.
func ValidStatus(s string) bool {
	for _, v := range Statuses {
		if s == v {
			return true
		}
	}
	return false
}

// NewID returns a new hook ID: a lowercase ULID, so IDs sort by creation time.
func NewID() string {
	return strings.ToLower(ulid.Make().String())
}

// Hook is one request caught by a channel, stored as received.
type Hook struct {
	ID          string
	Channel     string
	Status      string // one of the Status* constants
	Method      string
	Query       string // raw query string, without "?"
	Headers     map[string]string
	ContentType string
	Body        []byte
	IP          string
	Failures    []Failure // failures reported for the hook, oldest first
	CreatedAt   time.Time
	FinalizedAt *time.Time // when processed or discarded; nil otherwise
}

// Failure is a failure a consumer reported for a hook.
type Failure struct {
	At      time.Time `json:"at"`
	Message string    `json:"message"`
}

// ChannelStats counts a channel's hooks by status.
type ChannelStats struct {
	Pending   int64
	Processed int64
	Failed    int64
	Discarded int64
}

func (s ChannelStats) Total() int64 {
	return s.Pending + s.Processed + s.Failed + s.Discarded
}

func (s *ChannelStats) add(status string, n int64) {
	switch status {
	case StatusPending:
		s.Pending += n
	case StatusProcessed:
		s.Processed += n
	case StatusFailed:
		s.Failed += n
	case StatusDiscarded:
		s.Discarded += n
	}
}

// Channel groups hooks.
type Channel struct {
	Name     string
	PausedAt *time.Time // set while the channel refuses new hooks
	Guards   []string   // names of the guards its hooks must pass
	Stats    ChannelStats
}

func (c *Channel) Paused() bool { return c.PausedAt != nil }

// Channels

// EnsureChannel creates the channel if it doesn't exist yet. New channels
// have no guards.
func (d *DB) EnsureChannel(ctx context.Context, name string) error {
	if _, err := d.sql.ExecContext(ctx, d.q(`INSERT INTO channels (name) VALUES (?) ON CONFLICT (name) DO NOTHING`), name); err != nil {
		return fmt.Errorf("creating channel: %w", err)
	}
	return nil
}

const channelColumns = `name, paused_at`

func scanChannel(row interface{ Scan(...any) error }) (*Channel, error) {
	var c Channel
	var pausedAt sql.NullTime
	if err := row.Scan(&c.Name, &pausedAt); err != nil {
		return nil, err
	}
	if pausedAt.Valid {
		c.PausedAt = &pausedAt.Time
	}
	c.Guards = []string{}
	return &c, nil
}

// channelStats counts hooks by channel and status; an empty channel counts
// all channels.
func (d *DB) channelStats(ctx context.Context, channel string) (map[string]*ChannelStats, error) {
	query := `SELECT channel, status, COUNT(*) FROM hooks`
	var args []any
	if channel != "" {
		query += ` WHERE channel = ?`
		args = append(args, channel)
	}
	query += ` GROUP BY channel, status`
	rows, err := d.sql.QueryContext(ctx, d.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("counting hooks: %w", err)
	}
	defer rows.Close()

	stats := map[string]*ChannelStats{}
	for rows.Next() {
		var ch, status string
		var n int64
		if err := rows.Scan(&ch, &status, &n); err != nil {
			return nil, fmt.Errorf("scanning hook count: %w", err)
		}
		if stats[ch] == nil {
			stats[ch] = &ChannelStats{}
		}
		stats[ch].add(status, n)
	}
	return stats, rows.Err()
}

func (d *DB) GetChannel(ctx context.Context, name string) (*Channel, error) {
	c, err := scanChannel(d.sql.QueryRowContext(ctx, d.q(`SELECT `+channelColumns+` FROM channels WHERE name = ?`), name))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("channel not found: %s", name)
		}
		return nil, fmt.Errorf("getting channel: %w", err)
	}
	stats, err := d.channelStats(ctx, name)
	if err != nil {
		return nil, err
	}
	if s := stats[name]; s != nil {
		c.Stats = *s
	}
	guards, err := d.channelGuardNames(ctx, name)
	if err != nil {
		return nil, err
	}
	if g := guards[name]; g != nil {
		c.Guards = g
	}
	return c, nil
}

// ListChannels returns all channels with their stats, sorted by name.
func (d *DB) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+channelColumns+` FROM channels ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing channels: %w", err)
	}
	defer rows.Close()

	var channels []Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning channel: %w", err)
		}
		channels = append(channels, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	stats, err := d.channelStats(ctx, "")
	if err != nil {
		return nil, err
	}
	guards, err := d.channelGuardNames(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range channels {
		if s := stats[channels[i].Name]; s != nil {
			channels[i].Stats = *s
		}
		if g := guards[channels[i].Name]; g != nil {
			channels[i].Guards = g
		}
	}
	return channels, nil
}

// SetChannelPaused pauses or resumes a channel and returns it. Pausing an
// already paused channel keeps its original pause time.
func (d *DB) SetChannelPaused(ctx context.Context, name string, paused bool) (*Channel, error) {
	query := d.q(`UPDATE channels SET paused_at = NULL WHERE name = ?`)
	args := []any{name}
	if paused {
		query = d.q(`UPDATE channels SET paused_at = COALESCE(paused_at, ?) WHERE name = ?`)
		args = []any{time.Now().UTC(), name}
	}
	result, err := d.sql.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("updating channel: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("channel not found: %s", name)
	}
	return d.GetChannel(ctx, name)
}

// DeleteChannel deletes a channel and all its hooks.
func (d *DB) DeleteChannel(ctx context.Context, name string) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("deleting channel: %w", err)
	}
	defer tx.Rollback()
	// Hooks go explicitly: SQLite only enforces ON DELETE CASCADE when
	// foreign keys are enabled on the connection.
	if _, err := tx.ExecContext(ctx, d.q(`DELETE FROM hooks WHERE channel = ?`), name); err != nil {
		return fmt.Errorf("deleting hooks: %w", err)
	}
	if _, err := tx.ExecContext(ctx, d.q(`DELETE FROM channels_guards WHERE channel = ?`), name); err != nil {
		return fmt.Errorf("detaching guards: %w", err)
	}
	result, err := tx.ExecContext(ctx, d.q(`DELETE FROM channels WHERE name = ?`), name)
	if err != nil {
		return fmt.Errorf("deleting channel: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("channel not found: %s", name)
	}
	return tx.Commit()
}

// Hooks

const hookColumns = `id, channel, status, method, query, headers, content_type, body, ip, failures, created_at, finalized_at`

func scanHook(row interface{ Scan(...any) error }) (*Hook, error) {
	var h Hook
	var headers, failures string
	var finalizedAt sql.NullTime
	if err := row.Scan(&h.ID, &h.Channel, &h.Status, &h.Method, &h.Query, &headers,
		&h.ContentType, &h.Body, &h.IP, &failures, &h.CreatedAt, &finalizedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(headers), &h.Headers); err != nil {
		return nil, fmt.Errorf("decoding headers of hook %s: %w", h.ID, err)
	}
	if err := json.Unmarshal([]byte(failures), &h.Failures); err != nil {
		return nil, fmt.Errorf("decoding failures of hook %s: %w", h.ID, err)
	}
	if finalizedAt.Valid {
		h.FinalizedAt = &finalizedAt.Time
	}
	return &h, nil
}

// CreateHook inserts h as a pending hook, creating its channel if needed, and
// returns it with its ID and creation time set.
func (d *DB) CreateHook(ctx context.Context, h Hook) (*Hook, error) {
	if err := d.EnsureChannel(ctx, h.Channel); err != nil {
		return nil, err
	}
	h.ID = NewID()
	h.Status = StatusPending
	h.Failures = []Failure{}
	h.FinalizedAt = nil
	if h.Headers == nil {
		h.Headers = map[string]string{}
	}
	if h.Body == nil {
		h.Body = []byte{}
	}
	headers, err := json.Marshal(h.Headers)
	if err != nil {
		return nil, fmt.Errorf("encoding headers: %w", err)
	}

	// Times are stored in UTC so SQLite, which compares them as text, orders
	// them correctly. It's read back because Postgres stores microseconds.
	query := d.q(`INSERT INTO hooks (` + hookColumns + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, NULL) RETURNING created_at`)
	if err := d.sql.QueryRowContext(ctx, query,
		h.ID, h.Channel, h.Status, h.Method, h.Query, string(headers),
		h.ContentType, h.Body, h.IP, time.Now().UTC()).
		Scan(&h.CreatedAt); err != nil {
		return nil, fmt.Errorf("inserting hook: %w", err)
	}
	return &h, nil
}

func (d *DB) GetHook(ctx context.Context, id string) (*Hook, error) {
	h, err := scanHook(d.sql.QueryRowContext(ctx, d.q(`SELECT `+hookColumns+` FROM hooks WHERE id = ?`), id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("hook not found: %s", id)
		}
		return nil, fmt.Errorf("getting hook: %w", err)
	}
	return h, nil
}

// HookFilter narrows ListHooks. Empty fields match everything.
type HookFilter struct {
	Channel string
	Status  string
	After   string // a hook ID; only older hooks match
}

// ListHooks returns up to limit hooks matching f, newest first.
func (d *DB) ListHooks(ctx context.Context, f HookFilter, limit int) ([]Hook, error) {
	query := `SELECT ` + hookColumns + ` FROM hooks WHERE 1 = 1`
	var args []any
	if f.Channel != "" {
		query += ` AND channel = ?`
		args = append(args, f.Channel)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	if f.After != "" {
		query += ` AND id < ?`
		args = append(args, f.After)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := d.sql.QueryContext(ctx, d.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("listing hooks: %w", err)
	}
	defer rows.Close()

	var hooks []Hook
	for rows.Next() {
		h, err := scanHook(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning hook: %w", err)
		}
		hooks = append(hooks, *h)
	}
	return hooks, rows.Err()
}

// SetHookStatus sets a hook's status and returns the hook. "processed" and
// "discarded" set its finalized time; "failed" appends message to its
// failures and needs one; "pending" queues it again. Failures are never
// cleared.
func (d *DB) SetHookStatus(ctx context.Context, id, status, message string) (*Hook, error) {
	if !ValidStatus(status) {
		return nil, fmt.Errorf("invalid status: %s", status)
	}
	if status == StatusFailed && message == "" {
		return nil, fmt.Errorf("a failed status needs a message")
	}

	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("updating hook: %w", err)
	}
	defer tx.Rollback()

	var failures string
	if err := tx.QueryRowContext(ctx, d.q(`SELECT failures FROM hooks WHERE id = ?`), id).Scan(&failures); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("hook not found: %s", id)
		}
		return nil, fmt.Errorf("getting hook: %w", err)
	}

	now := time.Now().UTC()
	var finalizedAt sql.NullTime
	switch status {
	case StatusProcessed, StatusDiscarded:
		finalizedAt = sql.NullTime{Time: now, Valid: true}
	case StatusFailed:
		var list []Failure
		if err := json.Unmarshal([]byte(failures), &list); err != nil {
			return nil, fmt.Errorf("decoding failures of hook %s: %w", id, err)
		}
		b, err := json.Marshal(append(list, Failure{At: now, Message: message}))
		if err != nil {
			return nil, fmt.Errorf("encoding failures: %w", err)
		}
		failures = string(b)
	}

	query := d.q(`UPDATE hooks SET status = ?, failures = ?, finalized_at = ? WHERE id = ?`)
	if _, err := tx.ExecContext(ctx, query, status, failures, finalizedAt, id); err != nil {
		return nil, fmt.Errorf("updating hook: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("updating hook: %w", err)
	}
	return d.GetHook(ctx, id)
}

func (d *DB) DeleteHook(ctx context.Context, id string) error {
	result, err := d.sql.ExecContext(ctx, d.q(`DELETE FROM hooks WHERE id = ?`), id)
	if err != nil {
		return fmt.Errorf("deleting hook: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("hook not found: %s", id)
	}
	return nil
}
