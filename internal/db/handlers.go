package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Handler is something that runs on each hook a channel catches. What Type and
// Options mean is up to internal/handler.
type Handler struct {
	Name      string
	Type      string
	Options   string // JSON object of its settings
	Channels  []string
	CreatedAt time.Time
}

// ErrHandlerInUse is returned when deleting a handler that's still
// attached to channels.
var ErrHandlerInUse = errors.New("handler is still attached to channels")

// Attempt statuses. An attempt is one try; a handler's state for a hook
// is its latest try.
const (
	AttemptPending   = "pending"   // scheduled, not tried yet
	AttemptSucceeded = "succeeded" // went through
	AttemptFailed    = "failed"    // didn't; a retry is a new attempt
)

// Attempt is one try at sending a hook to a handler.
type Attempt struct {
	ID         string
	HookID     string
	Handler    string
	Number     int    // 1 for the first try, counting up through retries
	Status     string // one of the Attempt* constants
	DueAt      time.Time
	Code       int    // the response code: an HTTP status for http handlers; 0 when there was none
	Error      string // why it failed
	Output     string // what a script logged
	MS         int64  // how long it took
	CreatedAt  time.Time
	FinishedAt *time.Time // when it was tried; nil while pending
}

// Outcome is how a try went.
type Outcome struct {
	Code   int
	Error  string // empty when it succeeded
	Output string // what a script logged
	MS     int64
}

const handlerColumns = `name, type, options, created_at`

func scanHandler(row interface{ Scan(...any) error }) (*Handler, error) {
	var dst Handler
	if err := row.Scan(&dst.Name, &dst.Type, &dst.Options, &dst.CreatedAt); err != nil {
		return nil, err
	}
	dst.Channels = []string{}
	return &dst, nil
}

// CreateHandler stores dst and returns it.
func (d *DB) CreateHandler(ctx context.Context, dst Handler) (*Handler, error) {
	if dst.Options == "" {
		dst.Options = "{}"
	}
	query := d.q(`INSERT INTO handlers (name, type, options, created_at)
		VALUES (?, ?, ?, ?)`)
	if _, err := d.sql.ExecContext(ctx, query, dst.Name, dst.Type, dst.Options, time.Now().UTC()); err != nil {
		if d.isUniqueViolation(err) {
			return nil, fmt.Errorf("handler already exists: %s", dst.Name)
		}
		return nil, fmt.Errorf("creating handler: %w", err)
	}
	return d.GetHandler(ctx, dst.Name)
}

// GetHandler returns a handler with its channels.
func (d *DB) GetHandler(ctx context.Context, name string) (*Handler, error) {
	dst, err := scanHandler(d.sql.QueryRowContext(ctx, d.q(`SELECT `+handlerColumns+` FROM handlers WHERE name = ?`), name))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("handler not found: %s", name)
		}
		return nil, fmt.Errorf("getting handler: %w", err)
	}
	links, err := d.channelHandlerNames(ctx)
	if err != nil {
		return nil, err
	}
	for ch, names := range links {
		if slices.Contains(names, name) {
			dst.Channels = append(dst.Channels, ch)
		}
	}
	slices.Sort(dst.Channels)
	return dst, nil
}

// ListHandlers returns all handlers with their channels, sorted by
// name.
func (d *DB) ListHandlers(ctx context.Context) ([]Handler, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+handlerColumns+` FROM handlers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing handlers: %w", err)
	}
	defer rows.Close()
	var dsts []Handler
	for rows.Next() {
		dst, err := scanHandler(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning handler: %w", err)
		}
		dsts = append(dsts, *dst)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	links, err := d.channelHandlerNames(ctx)
	if err != nil {
		return nil, err
	}
	for i := range dsts {
		for ch, names := range links {
			if slices.Contains(names, dsts[i].Name) {
				dsts[i].Channels = append(dsts[i].Channels, ch)
			}
		}
		slices.Sort(dsts[i].Channels)
	}
	return dsts, nil
}

// UpdateHandler replaces a handler's type and options. Attempts already
// queued use the new settings when they run.
func (d *DB) UpdateHandler(ctx context.Context, dst Handler) (*Handler, error) {
	if dst.Options == "" {
		dst.Options = "{}"
	}
	result, err := d.sql.ExecContext(ctx, d.q(`UPDATE handlers SET type = ?, options = ? WHERE name = ?`), dst.Type, dst.Options, dst.Name)
	if err != nil {
		return nil, fmt.Errorf("updating handler: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("handler not found: %s", dst.Name)
	}
	return d.GetHandler(ctx, dst.Name)
}

// LastAttempts returns each handler's latest finished attempt, by handler
// name; handlers that never ran have none.
func (d *DB) LastAttempts(ctx context.Context) (map[string]Attempt, error) {
	rows, err := d.sql.QueryContext(ctx, d.q(`SELECT `+attemptColumns+` FROM attempts a WHERE a.finished_at IS NOT NULL
		AND a.id = (SELECT MAX(id) FROM attempts l WHERE l.handler = a.handler AND l.finished_at IS NOT NULL)`))
	if err != nil {
		return nil, fmt.Errorf("listing last attempts: %w", err)
	}
	defer rows.Close()
	out := map[string]Attempt{}
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning attempt: %w", err)
		}
		out[a.Handler] = *a
	}
	return out, rows.Err()
}

// DeleteHandler deletes a handler. It refuses with
// ErrHandlerInUse while the handler is attached to any channel.
func (d *DB) DeleteHandler(ctx context.Context, name string) error {
	dst, err := d.GetHandler(ctx, name)
	if err != nil {
		return err
	}
	if len(dst.Channels) > 0 {
		return fmt.Errorf("%w: %v", ErrHandlerInUse, dst.Channels)
	}
	if _, err := d.sql.ExecContext(ctx, d.q(`DELETE FROM handlers WHERE name = ?`), name); err != nil {
		return fmt.Errorf("deleting handler: %w", err)
	}
	return nil
}

// channelHandlerNames returns the handler names attached to each
// channel, sorted.
func (d *DB) channelHandlerNames(ctx context.Context) (map[string][]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT channel, handler FROM channels_handlers ORDER BY channel, handler`)
	if err != nil {
		return nil, fmt.Errorf("listing channel handlers: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var ch, dst string
		if err := rows.Scan(&ch, &dst); err != nil {
			return nil, fmt.Errorf("scanning channel handler: %w", err)
		}
		out[ch] = append(out[ch], dst)
	}
	return out, rows.Err()
}

// ChannelHandlers returns the names of the handlers attached to a
// channel.
func (d *DB) ChannelHandlers(ctx context.Context, channel string) ([]string, error) {
	links, err := d.channelHandlerNames(ctx)
	if err != nil {
		return nil, err
	}
	if links[channel] == nil {
		return []string{}, nil
	}
	return links[channel], nil
}

// SetChannelHandlers replaces the handlers attached to a channel.
func (d *DB) SetChannelHandlers(ctx context.Context, channel string, handlers []string) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("setting channel handlers: %w", err)
	}
	defer tx.Rollback()
	for _, dst := range handlers {
		var n int
		if err := tx.QueryRowContext(ctx, d.q(`SELECT COUNT(*) FROM handlers WHERE name = ?`), dst).Scan(&n); err != nil {
			return fmt.Errorf("getting handler: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("handler not found: %s", dst)
		}
	}
	if _, err := tx.ExecContext(ctx, d.q(`DELETE FROM channels_handlers WHERE channel = ?`), channel); err != nil {
		return fmt.Errorf("detaching handlers: %w", err)
	}
	for _, dst := range handlers {
		if _, err := tx.ExecContext(ctx, d.q(`INSERT INTO channels_handlers (channel, handler) VALUES (?, ?) ON CONFLICT DO NOTHING`), channel, dst); err != nil {
			return fmt.Errorf("attaching handler: %w", err)
		}
	}
	return tx.Commit()
}

// Attempts

const attemptColumns = `id, hook_id, handler, number, status, due_at, code, error, output, ms, created_at, finished_at`

func scanAttempt(row interface{ Scan(...any) error }) (*Attempt, error) {
	var dl Attempt
	var finished sql.NullTime
	if err := row.Scan(&dl.ID, &dl.HookID, &dl.Handler, &dl.Number, &dl.Status, &dl.DueAt,
		&dl.Code, &dl.Error, &dl.Output, &dl.MS, &dl.CreatedAt, &finished); err != nil {
		return nil, err
	}
	if finished.Valid {
		dl.FinishedAt = &finished.Time
	}
	return &dl, nil
}

// schedule queues a try of a hook to a handler.
// querier is a database or a transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (d *DB) schedule(ctx context.Context, hookID, handler string, attempt int, due time.Time) error {
	return d.scheduleIn(ctx, d.sql, hookID, handler, attempt, due)
}

func (d *DB) scheduleIn(ctx context.Context, q querier, hookID, handler string, attempt int, due time.Time) error {
	query := d.q(`INSERT INTO attempts (id, hook_id, handler, number, status, due_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if _, err := q.ExecContext(ctx, query, NewID(), hookID, handler, attempt, AttemptPending, due, time.Now().UTC()); err != nil {
		return fmt.Errorf("queueing attempt: %w", err)
	}
	return nil
}

// EnqueueAttempts queues a hook for every handler attached to its
// channel, due now. It returns how many were queued. CreateHook already
// does this for a new hook.
func (d *DB) EnqueueAttempts(ctx context.Context, hookID, channel string) (int, error) {
	return d.enqueue(ctx, d.sql, hookID, channel)
}

func (d *DB) enqueue(ctx context.Context, q querier, hookID, channel string) (int, error) {
	rows, err := q.QueryContext(ctx, d.q(`SELECT handler FROM channels_handlers WHERE channel = ? ORDER BY handler`), channel)
	if err != nil {
		return 0, fmt.Errorf("listing channel handlers: %w", err)
	}
	var dsts []string
	for rows.Next() {
		var dst string
		if err := rows.Scan(&dst); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scanning channel handler: %w", err)
		}
		dsts = append(dsts, dst)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("listing channel handlers: %w", err)
	}
	now := time.Now().UTC()
	for _, dst := range dsts {
		if err := d.scheduleIn(ctx, q, hookID, dst, 1, now); err != nil {
			return 0, err
		}
	}
	return len(dsts), nil
}

// HookAttempts returns every try for the given hooks, by hook ID, sorted
// by handler and then oldest first.
func (d *DB) HookAttempts(ctx context.Context, hookIDs []string) (map[string][]Attempt, error) {
	out := map[string][]Attempt{}
	for _, id := range hookIDs {
		rows, err := d.sql.QueryContext(ctx, d.q(`SELECT `+attemptColumns+` FROM attempts WHERE hook_id = ? ORDER BY handler, id`), id)
		if err != nil {
			return nil, fmt.Errorf("listing attempts: %w", err)
		}
		for rows.Next() {
			dl, err := scanAttempt(rows)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("scanning attempt: %w", err)
			}
			out[id] = append(out[id], *dl)
		}
		rows.Close()
	}
	return out, nil
}

// DueAttempt is a claimed attempt with what's needed to send it.
type DueAttempt struct {
	Attempt
	Handler Handler
	Hook    Hook
}

// ClaimDueAttempts claims up to limit pending attempts that are due,
// leasing each for lease so no other worker sends it meanwhile. A claimed
// attempt whose handler is gone is failed on the spot.
func (d *DB) ClaimDueAttempts(ctx context.Context, limit int, lease time.Duration) ([]DueAttempt, error) {
	now := time.Now().UTC()
	rows, err := d.sql.QueryContext(ctx, d.q(`SELECT `+attemptColumns+` FROM attempts
		WHERE status = ? AND due_at <= ? ORDER BY due_at LIMIT ?`), AttemptPending, now, limit)
	if err != nil {
		return nil, fmt.Errorf("listing due attempts: %w", err)
	}
	var due []Attempt
	for rows.Next() {
		dl, err := scanAttempt(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning attempt: %w", err)
		}
		due = append(due, *dl)
	}
	rows.Close()

	var claimed []DueAttempt
	for _, dl := range due {
		// Claim by moving due_at forward, only if no one else has.
		res, err := d.sql.ExecContext(ctx, d.q(`UPDATE attempts SET due_at = ?
			WHERE id = ? AND status = ? AND due_at = ?`), now.Add(lease), dl.ID, AttemptPending, dl.DueAt)
		if err != nil {
			return nil, fmt.Errorf("claiming attempt: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}

		var dst Handler
		err = d.sql.QueryRowContext(ctx, d.q(`SELECT name, type, options FROM handlers WHERE name = ?`), dl.Handler).
			Scan(&dst.Name, &dst.Type, &dst.Options)
		if err == sql.ErrNoRows {
			if err := d.FinishAttempt(ctx, dl.ID, Outcome{Error: "handler was deleted"}, 0); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("getting handler: %w", err)
		}
		hook, err := d.GetHook(ctx, dl.HookID)
		if err != nil {
			// The hook was deleted since; nothing left to do.
			if _, derr := d.sql.ExecContext(ctx, d.q(`DELETE FROM attempts WHERE id = ?`), dl.ID); derr != nil {
				return nil, fmt.Errorf("deleting orphaned attempt: %w", derr)
			}
			continue
		}
		claimed = append(claimed, DueAttempt{Attempt: dl, Handler: dst, Hook: *hook})
	}
	return claimed, nil
}

// FinishAttempt records how a try went. When it failed, retryIn schedules
// the next try, and zero gives up. When every handler's latest try has
// succeeded the hook becomes handled; when one gives up the hook becomes
// failed with the reason.
func (d *DB) FinishAttempt(ctx context.Context, id string, o Outcome, retryIn time.Duration) error {
	now := time.Now().UTC()
	var dl Attempt
	err := d.sql.QueryRowContext(ctx, d.q(`SELECT hook_id, handler, number FROM attempts WHERE id = ?`), id).
		Scan(&dl.HookID, &dl.Handler, &dl.Number)
	if err != nil {
		return fmt.Errorf("getting attempt: %w", err)
	}
	status := AttemptSucceeded
	if o.Error != "" {
		status = AttemptFailed
	}
	query := d.q(`UPDATE attempts SET status = ?, code = ?, error = ?, output = ?, ms = ?, finished_at = ? WHERE id = ?`)
	if _, err := d.sql.ExecContext(ctx, query, status, o.Code, o.Error, o.Output, o.MS, now, id); err != nil {
		return fmt.Errorf("updating attempt: %w", err)
	}

	// A hook marked handled or discarded meanwhile keeps that status: an
	// attempt that was already running doesn't change it or retry.
	var hookStatus string
	if err := d.sql.QueryRowContext(ctx, d.q(`SELECT status FROM hooks WHERE id = ?`), dl.HookID).Scan(&hookStatus); err != nil {
		return fmt.Errorf("getting hook: %w", err)
	}
	if hookStatus == StatusHandled || hookStatus == StatusDiscarded {
		return nil
	}

	switch {
	case status == AttemptFailed && retryIn > 0:
		return d.schedule(ctx, dl.HookID, dl.Handler, dl.Number+1, now.Add(retryIn))
	case status == AttemptFailed:
		_, err := d.SetHookStatus(ctx, dl.HookID, StatusFailed, dl.Handler, o.Error)
		return err
	}
	// Succeeded: the hook is handled once every handler's latest try has.
	var open int
	err = d.sql.QueryRowContext(ctx, d.q(`SELECT COUNT(*) FROM attempts d WHERE d.hook_id = ? AND d.status <> ?
		AND d.id = (SELECT MAX(id) FROM attempts l WHERE l.hook_id = d.hook_id AND l.handler = d.handler)`),
		dl.HookID, AttemptSucceeded).Scan(&open)
	if err != nil {
		return fmt.Errorf("counting attempts: %w", err)
	}
	if open == 0 {
		_, err := d.SetHookStatus(ctx, dl.HookID, StatusHandled, "", "")
		return err
	}
	return nil
}

// RetryAttempts tries a hook again for each handler whose latest try
// failed, due now and starting over from the first attempt. It returns how
// many.
func (d *DB) RetryAttempts(ctx context.Context, hookID string) (int, error) {
	rows, err := d.sql.QueryContext(ctx, d.q(`SELECT d.handler FROM attempts d WHERE d.hook_id = ? AND d.status = ?
		AND d.id = (SELECT MAX(id) FROM attempts l WHERE l.hook_id = d.hook_id AND l.handler = d.handler)`),
		hookID, AttemptFailed)
	if err != nil {
		return 0, fmt.Errorf("retrying attempts: %w", err)
	}
	var dsts []string
	for rows.Next() {
		var dst string
		if err := rows.Scan(&dst); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scanning attempt: %w", err)
		}
		dsts = append(dsts, dst)
	}
	rows.Close()
	now := time.Now().UTC()
	for _, dst := range dsts {
		if err := d.schedule(ctx, hookID, dst, 1, now); err != nil {
			return 0, err
		}
	}
	return len(dsts), nil
}
