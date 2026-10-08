package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Destination is where a channel's hooks are delivered. What Protocol and
// Options mean is up to internal/destination.
type Destination struct {
	Name      string
	Protocol  string
	Options   string // JSON object of its settings
	Channels  []string
	CreatedAt time.Time
}

// ErrDestinationInUse is returned when deleting a destination that's still
// attached to channels.
var ErrDestinationInUse = errors.New("destination is still attached to channels")

// Delivery statuses. A delivery is one try; a destination's state for a hook
// is its latest try.
const (
	DeliveryPending   = "pending"   // scheduled, not tried yet
	DeliveryDelivered = "delivered" // went through
	DeliveryFailed    = "failed"    // didn't; a retry is a new delivery
)

// Delivery is one try at sending a hook to a destination.
type Delivery struct {
	ID          string
	HookID      string
	Destination string
	Attempt     int    // 1 for the first try, counting up through retries
	Status      string // one of the Delivery* constants
	DueAt       time.Time
	HTTPStatus  int    // the response's status, when there was one
	Error       string // why it failed
	MS          int64  // how long the request took
	CreatedAt   time.Time
	FinishedAt  *time.Time // when it was tried; nil while pending
}

// Outcome is how a try went.
type Outcome struct {
	HTTPStatus int
	Error      string // empty when it was delivered
	MS         int64
}

const destinationColumns = `name, protocol, options, created_at`

func scanDestination(row interface{ Scan(...any) error }) (*Destination, error) {
	var dst Destination
	if err := row.Scan(&dst.Name, &dst.Protocol, &dst.Options, &dst.CreatedAt); err != nil {
		return nil, err
	}
	dst.Channels = []string{}
	return &dst, nil
}

// CreateDestination stores dst and returns it.
func (d *DB) CreateDestination(ctx context.Context, dst Destination) (*Destination, error) {
	if dst.Options == "" {
		dst.Options = "{}"
	}
	query := d.q(`INSERT INTO destinations (name, protocol, options, created_at)
		VALUES (?, ?, ?, ?)`)
	if _, err := d.sql.ExecContext(ctx, query, dst.Name, dst.Protocol, dst.Options, time.Now().UTC()); err != nil {
		if d.isUniqueViolation(err) {
			return nil, fmt.Errorf("destination already exists: %s", dst.Name)
		}
		return nil, fmt.Errorf("creating destination: %w", err)
	}
	return d.GetDestination(ctx, dst.Name)
}

// GetDestination returns a destination with its channels.
func (d *DB) GetDestination(ctx context.Context, name string) (*Destination, error) {
	dst, err := scanDestination(d.sql.QueryRowContext(ctx, d.q(`SELECT `+destinationColumns+` FROM destinations WHERE name = ?`), name))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("destination not found: %s", name)
		}
		return nil, fmt.Errorf("getting destination: %w", err)
	}
	links, err := d.channelDestinationNames(ctx)
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

// ListDestinations returns all destinations with their channels, sorted by
// name.
func (d *DB) ListDestinations(ctx context.Context) ([]Destination, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+destinationColumns+` FROM destinations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing destinations: %w", err)
	}
	defer rows.Close()
	var dsts []Destination
	for rows.Next() {
		dst, err := scanDestination(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning destination: %w", err)
		}
		dsts = append(dsts, *dst)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	links, err := d.channelDestinationNames(ctx)
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

// DeleteDestination deletes a destination. It refuses with
// ErrDestinationInUse while the destination is attached to any channel.
func (d *DB) DeleteDestination(ctx context.Context, name string) error {
	dst, err := d.GetDestination(ctx, name)
	if err != nil {
		return err
	}
	if len(dst.Channels) > 0 {
		return fmt.Errorf("%w: %v", ErrDestinationInUse, dst.Channels)
	}
	if _, err := d.sql.ExecContext(ctx, d.q(`DELETE FROM destinations WHERE name = ?`), name); err != nil {
		return fmt.Errorf("deleting destination: %w", err)
	}
	return nil
}

// channelDestinationNames returns the destination names attached to each
// channel, sorted.
func (d *DB) channelDestinationNames(ctx context.Context) (map[string][]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT channel, destination FROM channels_destinations ORDER BY channel, destination`)
	if err != nil {
		return nil, fmt.Errorf("listing channel destinations: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var ch, dst string
		if err := rows.Scan(&ch, &dst); err != nil {
			return nil, fmt.Errorf("scanning channel destination: %w", err)
		}
		out[ch] = append(out[ch], dst)
	}
	return out, rows.Err()
}

// ChannelDestinations returns the names of the destinations attached to a
// channel.
func (d *DB) ChannelDestinations(ctx context.Context, channel string) ([]string, error) {
	links, err := d.channelDestinationNames(ctx)
	if err != nil {
		return nil, err
	}
	if links[channel] == nil {
		return []string{}, nil
	}
	return links[channel], nil
}

// SetChannelDestinations replaces the destinations attached to a channel.
func (d *DB) SetChannelDestinations(ctx context.Context, channel string, destinations []string) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("setting channel destinations: %w", err)
	}
	defer tx.Rollback()
	for _, dst := range destinations {
		var n int
		if err := tx.QueryRowContext(ctx, d.q(`SELECT COUNT(*) FROM destinations WHERE name = ?`), dst).Scan(&n); err != nil {
			return fmt.Errorf("getting destination: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("destination not found: %s", dst)
		}
	}
	if _, err := tx.ExecContext(ctx, d.q(`DELETE FROM channels_destinations WHERE channel = ?`), channel); err != nil {
		return fmt.Errorf("detaching destinations: %w", err)
	}
	for _, dst := range destinations {
		if _, err := tx.ExecContext(ctx, d.q(`INSERT INTO channels_destinations (channel, destination) VALUES (?, ?) ON CONFLICT DO NOTHING`), channel, dst); err != nil {
			return fmt.Errorf("attaching destination: %w", err)
		}
	}
	return tx.Commit()
}

// Deliveries

const deliveryColumns = `id, hook_id, destination, attempt, status, due_at, http_status, error, ms, created_at, finished_at`

func scanDelivery(row interface{ Scan(...any) error }) (*Delivery, error) {
	var dl Delivery
	var finished sql.NullTime
	if err := row.Scan(&dl.ID, &dl.HookID, &dl.Destination, &dl.Attempt, &dl.Status, &dl.DueAt,
		&dl.HTTPStatus, &dl.Error, &dl.MS, &dl.CreatedAt, &finished); err != nil {
		return nil, err
	}
	if finished.Valid {
		dl.FinishedAt = &finished.Time
	}
	return &dl, nil
}

// schedule queues a try of a hook to a destination.
func (d *DB) schedule(ctx context.Context, hookID, destination string, attempt int, due time.Time) error {
	query := d.q(`INSERT INTO deliveries (id, hook_id, destination, attempt, status, due_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if _, err := d.sql.ExecContext(ctx, query, NewID(), hookID, destination, attempt, DeliveryPending, due, time.Now().UTC()); err != nil {
		return fmt.Errorf("queueing delivery: %w", err)
	}
	return nil
}

// EnqueueDeliveries queues a hook for every destination attached to its
// channel, due now. It returns how many were queued.
func (d *DB) EnqueueDeliveries(ctx context.Context, hookID, channel string) (int, error) {
	dsts, err := d.ChannelDestinations(ctx, channel)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	for _, dst := range dsts {
		if err := d.schedule(ctx, hookID, dst, 1, now); err != nil {
			return 0, err
		}
	}
	return len(dsts), nil
}

// HookDeliveries returns every try for the given hooks, by hook ID, sorted
// by destination and then oldest first.
func (d *DB) HookDeliveries(ctx context.Context, hookIDs []string) (map[string][]Delivery, error) {
	out := map[string][]Delivery{}
	for _, id := range hookIDs {
		rows, err := d.sql.QueryContext(ctx, d.q(`SELECT `+deliveryColumns+` FROM deliveries WHERE hook_id = ? ORDER BY destination, id`), id)
		if err != nil {
			return nil, fmt.Errorf("listing deliveries: %w", err)
		}
		for rows.Next() {
			dl, err := scanDelivery(rows)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("scanning delivery: %w", err)
			}
			out[id] = append(out[id], *dl)
		}
		rows.Close()
	}
	return out, nil
}

// DueDelivery is a claimed delivery with what's needed to send it.
type DueDelivery struct {
	Delivery
	Destination Destination
	Hook        Hook
}

// ClaimDueDeliveries claims up to limit pending deliveries that are due,
// leasing each for lease so no other worker sends it meanwhile. A claimed
// delivery whose destination is gone is failed on the spot.
func (d *DB) ClaimDueDeliveries(ctx context.Context, limit int, lease time.Duration) ([]DueDelivery, error) {
	now := time.Now().UTC()
	rows, err := d.sql.QueryContext(ctx, d.q(`SELECT `+deliveryColumns+` FROM deliveries
		WHERE status = ? AND due_at <= ? ORDER BY due_at LIMIT ?`), DeliveryPending, now, limit)
	if err != nil {
		return nil, fmt.Errorf("listing due deliveries: %w", err)
	}
	var due []Delivery
	for rows.Next() {
		dl, err := scanDelivery(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning delivery: %w", err)
		}
		due = append(due, *dl)
	}
	rows.Close()

	var claimed []DueDelivery
	for _, dl := range due {
		// Claim by moving due_at forward, only if no one else has.
		res, err := d.sql.ExecContext(ctx, d.q(`UPDATE deliveries SET due_at = ?
			WHERE id = ? AND status = ? AND due_at = ?`), now.Add(lease), dl.ID, DeliveryPending, dl.DueAt)
		if err != nil {
			return nil, fmt.Errorf("claiming delivery: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}

		var dst Destination
		err = d.sql.QueryRowContext(ctx, d.q(`SELECT name, protocol, options FROM destinations WHERE name = ?`), dl.Destination).
			Scan(&dst.Name, &dst.Protocol, &dst.Options)
		if err == sql.ErrNoRows {
			if err := d.FinishDelivery(ctx, dl.ID, Outcome{Error: "destination was deleted"}, 0); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("getting destination: %w", err)
		}
		hook, err := d.GetHook(ctx, dl.HookID)
		if err != nil {
			// The hook was deleted since; nothing left to deliver.
			if _, derr := d.sql.ExecContext(ctx, d.q(`DELETE FROM deliveries WHERE id = ?`), dl.ID); derr != nil {
				return nil, fmt.Errorf("deleting orphaned delivery: %w", derr)
			}
			continue
		}
		claimed = append(claimed, DueDelivery{Delivery: dl, Destination: dst, Hook: *hook})
	}
	return claimed, nil
}

// FinishDelivery records how a try went. When it failed, retryIn schedules
// the next try, and zero gives up. When every destination's latest try is
// delivered the hook becomes processed; when one gives up the hook becomes
// failed with the reason.
func (d *DB) FinishDelivery(ctx context.Context, id string, o Outcome, retryIn time.Duration) error {
	now := time.Now().UTC()
	var dl Delivery
	err := d.sql.QueryRowContext(ctx, d.q(`SELECT hook_id, destination, attempt FROM deliveries WHERE id = ?`), id).
		Scan(&dl.HookID, &dl.Destination, &dl.Attempt)
	if err != nil {
		return fmt.Errorf("getting delivery: %w", err)
	}
	status := DeliveryDelivered
	if o.Error != "" {
		status = DeliveryFailed
	}
	query := d.q(`UPDATE deliveries SET status = ?, http_status = ?, error = ?, ms = ?, finished_at = ? WHERE id = ?`)
	if _, err := d.sql.ExecContext(ctx, query, status, o.HTTPStatus, o.Error, o.MS, now, id); err != nil {
		return fmt.Errorf("updating delivery: %w", err)
	}

	switch {
	case status == DeliveryFailed && retryIn > 0:
		return d.schedule(ctx, dl.HookID, dl.Destination, dl.Attempt+1, now.Add(retryIn))
	case status == DeliveryFailed:
		_, err := d.SetHookStatus(ctx, dl.HookID, StatusFailed, dl.Destination+": "+o.Error)
		return err
	}
	// Delivered: the hook is processed once every destination's latest try is.
	var open int
	err = d.sql.QueryRowContext(ctx, d.q(`SELECT COUNT(*) FROM deliveries d WHERE d.hook_id = ? AND d.status <> ?
		AND d.id = (SELECT MAX(id) FROM deliveries l WHERE l.hook_id = d.hook_id AND l.destination = d.destination)`),
		dl.HookID, DeliveryDelivered).Scan(&open)
	if err != nil {
		return fmt.Errorf("counting deliveries: %w", err)
	}
	if open == 0 {
		_, err := d.SetHookStatus(ctx, dl.HookID, StatusProcessed, "")
		return err
	}
	return nil
}

// RetryDeliveries tries a hook again for each destination whose latest try
// failed, due now and starting over from the first attempt. It returns how
// many.
func (d *DB) RetryDeliveries(ctx context.Context, hookID string) (int, error) {
	rows, err := d.sql.QueryContext(ctx, d.q(`SELECT d.destination FROM deliveries d WHERE d.hook_id = ? AND d.status = ?
		AND d.id = (SELECT MAX(id) FROM deliveries l WHERE l.hook_id = d.hook_id AND l.destination = d.destination)`),
		hookID, DeliveryFailed)
	if err != nil {
		return 0, fmt.Errorf("retrying deliveries: %w", err)
	}
	var dsts []string
	for rows.Next() {
		var dst string
		if err := rows.Scan(&dst); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scanning delivery: %w", err)
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
