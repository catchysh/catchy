package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Guard is a configured check that hooks must pass on the channels it's
// attached to. What Type and Scheme mean is up to internal/guard.
type Guard struct {
	Name       string
	Type       string
	Scheme     string // for signature guards: how the signature is checked
	Options    string // JSON object of scheme settings
	Secret     string // plaintext; only set by ChannelPolicy, for checking hooks
	SecretHint string // masked form of the secret, safe to show
	Channels   []string
	CreatedAt  time.Time
}

// ErrGuardInUse is returned when deleting a guard that's still attached to
// channels.
var ErrGuardInUse = errors.New("guard is still attached to channels")

// secretHint masks a secret for display: its last four characters.
func secretHint(secret string) string {
	switch {
	case secret == "":
		return ""
	case len(secret) < 12:
		return "…"
	default:
		return "…" + secret[len(secret)-4:]
	}
}

func (d *DB) sealSecret(secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	if d.sealer == nil {
		return "", errors.New("can't store a secret: ENCRYPTION_KEY isn't set")
	}
	return d.sealer.Seal(secret)
}

const guardColumns = `name, type, scheme, options, secret_hint, created_at`

func scanGuard(row interface{ Scan(...any) error }) (*Guard, error) {
	var g Guard
	if err := row.Scan(&g.Name, &g.Type, &g.Scheme, &g.Options, &g.SecretHint, &g.CreatedAt); err != nil {
		return nil, err
	}
	g.Channels = []string{}
	return &g, nil
}

// CreateGuard stores g, sealing its secret, and returns it.
func (d *DB) CreateGuard(ctx context.Context, g Guard) (*Guard, error) {
	sealed, err := d.sealSecret(g.Secret)
	if err != nil {
		return nil, err
	}
	if g.Options == "" {
		g.Options = "{}"
	}
	query := d.q(`INSERT INTO guards (name, type, scheme, options, secret, secret_hint, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if _, err := d.sql.ExecContext(ctx, query, g.Name, g.Type, g.Scheme, g.Options, sealed, secretHint(g.Secret), time.Now().UTC()); err != nil {
		if d.isUniqueViolation(err) {
			return nil, fmt.Errorf("guard already exists: %s", g.Name)
		}
		return nil, fmt.Errorf("creating guard: %w", err)
	}
	return d.GetGuard(ctx, g.Name)
}

// GetGuard returns a guard with the channels it's attached to, without its
// secret.
func (d *DB) GetGuard(ctx context.Context, name string) (*Guard, error) {
	g, err := scanGuard(d.sql.QueryRowContext(ctx, d.q(`SELECT `+guardColumns+` FROM guards WHERE name = ?`), name))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("guard not found: %s", name)
		}
		return nil, fmt.Errorf("getting guard: %w", err)
	}
	rows, err := d.sql.QueryContext(ctx, d.q(`SELECT channel FROM channels_guards WHERE guard = ? ORDER BY channel`), name)
	if err != nil {
		return nil, fmt.Errorf("listing guard channels: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ch string
		if err := rows.Scan(&ch); err != nil {
			return nil, fmt.Errorf("scanning guard channel: %w", err)
		}
		g.Channels = append(g.Channels, ch)
	}
	return g, rows.Err()
}

// ListGuards returns all guards with their channels, sorted by name, without
// secrets.
func (d *DB) ListGuards(ctx context.Context) ([]Guard, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+guardColumns+` FROM guards ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing guards: %w", err)
	}
	defer rows.Close()

	var guards []Guard
	for rows.Next() {
		g, err := scanGuard(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning guard: %w", err)
		}
		guards = append(guards, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	links, err := d.channelGuardNames(ctx, "")
	if err != nil {
		return nil, err
	}
	for ch, names := range links {
		for _, name := range names {
			if i := slices.IndexFunc(guards, func(g Guard) bool { return g.Name == name }); i >= 0 {
				guards[i].Channels = append(guards[i].Channels, ch)
			}
		}
	}
	for i := range guards {
		slices.Sort(guards[i].Channels)
	}
	return guards, nil
}

// RotateGuardSecret replaces a guard's secret and returns the guard.
func (d *DB) RotateGuardSecret(ctx context.Context, name, secret string) (*Guard, error) {
	if _, err := d.GetGuard(ctx, name); err != nil {
		return nil, err
	}
	sealed, err := d.sealSecret(secret)
	if err != nil {
		return nil, err
	}
	query := d.q(`UPDATE guards SET secret = ?, secret_hint = ? WHERE name = ?`)
	if _, err := d.sql.ExecContext(ctx, query, sealed, secretHint(secret), name); err != nil {
		return nil, fmt.Errorf("updating guard: %w", err)
	}
	return d.GetGuard(ctx, name)
}

// DeleteGuard deletes a guard. It refuses with ErrGuardInUse while the guard
// is attached to any channel, so no channel loses protection by accident.
func (d *DB) DeleteGuard(ctx context.Context, name string) error {
	g, err := d.GetGuard(ctx, name)
	if err != nil {
		return err
	}
	if len(g.Channels) > 0 {
		return fmt.Errorf("%w: %v", ErrGuardInUse, g.Channels)
	}
	if _, err := d.sql.ExecContext(ctx, d.q(`DELETE FROM guards WHERE name = ?`), name); err != nil {
		return fmt.Errorf("deleting guard: %w", err)
	}
	return nil
}

// channelGuardNames returns the guard names attached to each channel, sorted;
// an empty channel lists all channels.
func (d *DB) channelGuardNames(ctx context.Context, channel string) (map[string][]string, error) {
	query := `SELECT channel, guard FROM channels_guards`
	var args []any
	if channel != "" {
		query += ` WHERE channel = ?`
		args = append(args, channel)
	}
	query += ` ORDER BY channel, guard`
	rows, err := d.sql.QueryContext(ctx, d.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("listing channel guards: %w", err)
	}
	defer rows.Close()

	out := map[string][]string{}
	for rows.Next() {
		var ch, g string
		if err := rows.Scan(&ch, &g); err != nil {
			return nil, fmt.Errorf("scanning channel guard: %w", err)
		}
		out[ch] = append(out[ch], g)
	}
	return out, rows.Err()
}

// SetChannelGuards replaces the guards attached to a channel, creating the
// channel if it doesn't exist, and returns it.
func (d *DB) SetChannelGuards(ctx context.Context, channel string, guards []string) (*Channel, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("setting channel guards: %w", err)
	}
	defer tx.Rollback()

	for _, g := range guards {
		var n int
		if err := tx.QueryRowContext(ctx, d.q(`SELECT COUNT(*) FROM guards WHERE name = ?`), g).Scan(&n); err != nil {
			return nil, fmt.Errorf("getting guard: %w", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("guard not found: %s", g)
		}
	}
	if _, err := tx.ExecContext(ctx, d.q(`INSERT INTO channels (name) VALUES (?) ON CONFLICT (name) DO NOTHING`), channel); err != nil {
		return nil, fmt.Errorf("creating channel: %w", err)
	}
	if _, err := tx.ExecContext(ctx, d.q(`DELETE FROM channels_guards WHERE channel = ?`), channel); err != nil {
		return nil, fmt.Errorf("detaching guards: %w", err)
	}
	for _, g := range guards {
		if _, err := tx.ExecContext(ctx, d.q(`INSERT INTO channels_guards (channel, guard) VALUES (?, ?) ON CONFLICT DO NOTHING`), channel, g); err != nil {
			return nil, fmt.Errorf("attaching guard: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("setting channel guards: %w", err)
	}
	return d.GetChannel(ctx, channel)
}

// ChannelPolicy returns what applies to a hook sent to the channel: whether
// it exists, whether it's paused, and its guards with their secrets opened. A
// channel that doesn't exist yet has no guards.
func (d *DB) ChannelPolicy(ctx context.Context, channel string) (exists, paused bool, guards []Guard, err error) {
	var pausedAt sql.NullTime
	err = d.sql.QueryRowContext(ctx, d.q(`SELECT paused_at FROM channels WHERE name = ?`), channel).Scan(&pausedAt)
	if err == sql.ErrNoRows {
		return false, false, nil, nil
	}
	if err != nil {
		return false, false, nil, fmt.Errorf("getting channel: %w", err)
	}

	rows, err := d.sql.QueryContext(ctx, d.q(`SELECT g.name, g.type, g.scheme, g.options, g.secret FROM guards g
		JOIN channels_guards cg ON cg.guard = g.name WHERE cg.channel = ? ORDER BY g.name`), channel)
	if err != nil {
		return false, false, nil, fmt.Errorf("listing channel guards: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var g Guard
		var sealed string
		if err := rows.Scan(&g.Name, &g.Type, &g.Scheme, &g.Options, &sealed); err != nil {
			return false, false, nil, fmt.Errorf("scanning guard: %w", err)
		}
		if sealed != "" {
			if d.sealer == nil {
				return false, false, nil, fmt.Errorf("guard %s: can't open its secret: ENCRYPTION_KEY isn't set", g.Name)
			}
			if g.Secret, err = d.sealer.Open(sealed); err != nil {
				return false, false, nil, fmt.Errorf("guard %s: %w", g.Name, err)
			}
		}
		guards = append(guards, g)
	}
	return true, pausedAt.Valid, guards, rows.Err()
}

// isUniqueViolation reports whether err is a primary key or unique
// constraint violation.
func (d *DB) isUniqueViolation(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "SQLSTATE 23505")
}
