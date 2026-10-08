package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/catchysh/catchy/internal/seal"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()

	database, err := New(t.Context(), "sqlite", "file:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })

	if err := database.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	sealer, err := seal.New("test-key")
	if err != nil {
		t.Fatal(err)
	}
	database.UseSealer(sealer)
	return database
}

func createHook(t *testing.T, database *DB, channel string) *Hook {
	t.Helper()

	h, err := database.CreateHook(t.Context(), Hook{
		Channel:     channel,
		Method:      "POST",
		Headers:     map[string]string{"Content-Type": "application/json"},
		ContentType: "application/json",
		Body:        []byte(`{"a":"b"}`),
	})
	if err != nil {
		t.Fatalf("CreateHook: %v", err)
	}
	return h
}

func TestValidChannel(t *testing.T) {
	for name, want := range map[string]bool{
		"default":               true,
		"contact-form_2":        true,
		"9lives":                true,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		"":                      false,
		"-contact":              false,
		"contact-":              false,
		"a--b":                  false,
		"Contact":               false,
		"con tact":              false,
		"contact/x":             false,
	} {
		if got := ValidChannel(name); got != want {
			t.Errorf("ValidChannel(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNewIDSortsByTime(t *testing.T) {
	a := NewID()
	time.Sleep(2 * time.Millisecond)
	b := NewID()
	if len(a) != 26 || a != strings.ToLower(a) || a >= b {
		t.Fatalf("NewID: %q then %q, want lowercase 26-char IDs in increasing order", a, b)
	}
}

func TestCreateHookRoundTrip(t *testing.T) {
	database := newTestDB(t)
	h := createHook(t, database, "stripe")

	got, err := database.GetHook(t.Context(), h.ID)
	if err != nil {
		t.Fatalf("GetHook: %v", err)
	}
	if got.Status != StatusPending || got.Channel != "stripe" || string(got.Body) != `{"a":"b"}` ||
		got.Headers["Content-Type"] != "application/json" || got.Method != "POST" ||
		len(got.Failures) != 0 || got.FinalizedAt != nil || !got.CreatedAt.Equal(h.CreatedAt) {
		t.Fatalf("hook = %+v", got)
	}

	// Binary bodies are kept byte for byte.
	raw, err := database.CreateHook(t.Context(), Hook{Channel: "stripe", Method: "POST", Body: []byte{0xff, 0x00}})
	if err != nil {
		t.Fatalf("CreateHook: %v", err)
	}
	got, _ = database.GetHook(t.Context(), raw.ID)
	if len(got.Body) != 2 || got.Body[0] != 0xff {
		t.Fatalf("raw hook = %+v", got)
	}
}

func TestSetHookStatus(t *testing.T) {
	database := newTestDB(t)
	h := createHook(t, database, "contact")

	// Two failures, a retry, then success: the failures are kept.
	got, err := database.SetHookStatus(t.Context(), h.ID, StatusFailed, "slack 500")
	if err != nil {
		t.Fatalf("SetHookStatus: %v", err)
	}
	if got.Status != StatusFailed || len(got.Failures) != 1 || got.Failures[0].Message != "slack 500" || got.FinalizedAt != nil {
		t.Fatalf("after failure: %+v", got)
	}
	database.SetHookStatus(t.Context(), h.ID, StatusFailed, "timeout")
	got, _ = database.SetHookStatus(t.Context(), h.ID, StatusPending, "ignored")
	if got.Status != StatusPending || len(got.Failures) != 2 || got.FinalizedAt != nil {
		t.Fatalf("after retry: %+v", got)
	}
	got, _ = database.SetHookStatus(t.Context(), h.ID, StatusProcessed, "")
	if got.Status != StatusProcessed || got.FinalizedAt == nil || len(got.Failures) != 2 ||
		got.Failures[0].Message != "slack 500" || got.Failures[1].Message != "timeout" || got.Failures[1].At.Before(got.Failures[0].At) {
		t.Fatalf("after processing: %+v", got)
	}

	// Going back to pending clears the finalized time.
	got, _ = database.SetHookStatus(t.Context(), h.ID, StatusPending, "")
	if got.FinalizedAt != nil {
		t.Fatalf("finalized_at kept after reopening: %v", got.FinalizedAt)
	}

	if _, err := database.SetHookStatus(t.Context(), h.ID, StatusFailed, ""); err == nil {
		t.Fatal("SetHookStatus accepted a failure without a message")
	}
	if _, err := database.SetHookStatus(t.Context(), h.ID, "done", ""); err == nil {
		t.Fatal("SetHookStatus accepted an invalid status")
	}
	if _, err := database.SetHookStatus(t.Context(), "missing", StatusProcessed, ""); err == nil {
		t.Fatal("SetHookStatus on a missing hook succeeded")
	}
}

func TestChannelStats(t *testing.T) {
	database := newTestDB(t)
	a := createHook(t, database, "contact")
	b := createHook(t, database, "contact")
	createHook(t, database, "contact")
	createHook(t, database, "newsletter")
	database.SetHookStatus(t.Context(), a.ID, StatusProcessed, "")
	database.SetHookStatus(t.Context(), b.ID, StatusFailed, "boom")

	channels, err := database.ListChannels(t.Context())
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels) != 2 || channels[0].Name != "contact" || channels[1].Name != "newsletter" {
		t.Fatalf("channels = %+v", channels)
	}
	if got, want := channels[0].Stats, (ChannelStats{Pending: 1, Processed: 1, Failed: 1}); got != want {
		t.Fatalf("contact stats = %+v, want %+v", got, want)
	}
	c, _ := database.GetChannel(t.Context(), "newsletter")
	if got, want := c.Stats, (ChannelStats{Pending: 1}); got != want {
		t.Fatalf("newsletter stats = %+v, want %+v", got, want)
	}
}

func TestDeleteChannelDeletesHooks(t *testing.T) {
	database := newTestDB(t)
	createHook(t, database, "contact")
	keep := createHook(t, database, "newsletter")

	if err := database.DeleteChannel(t.Context(), "contact"); err != nil {
		t.Fatalf("DeleteChannel: %v", err)
	}
	if _, err := database.GetChannel(t.Context(), "contact"); err == nil {
		t.Fatal("channel still exists")
	}
	hooks, _ := database.ListHooks(t.Context(), HookFilter{}, 10)
	if len(hooks) != 1 || hooks[0].ID != keep.ID {
		t.Fatalf("hooks = %+v, want only %s", hooks, keep.ID)
	}
	if err := database.DeleteChannel(t.Context(), "contact"); err == nil {
		t.Fatal("deleting a missing channel succeeded")
	}
}

func TestDeleteHook(t *testing.T) {
	database := newTestDB(t)
	h := createHook(t, database, "contact")

	if err := database.DeleteHook(t.Context(), h.ID); err != nil {
		t.Fatalf("DeleteHook: %v", err)
	}
	if _, err := database.GetHook(t.Context(), h.ID); err == nil {
		t.Fatal("hook still exists")
	}
	if err := database.DeleteHook(t.Context(), h.ID); err == nil {
		t.Fatal("deleting a missing hook succeeded")
	}
}

func TestListHooksFiltersAndPages(t *testing.T) {
	database := newTestDB(t)

	// Six hooks, alternating channels; IDs increase with creation.
	var ids []string
	for i := 0; i < 6; i++ {
		channel := "a"
		if i%2 == 1 {
			channel = "b"
		}
		ids = append(ids, createHook(t, database, channel).ID)
	}
	database.SetHookStatus(t.Context(), ids[4], StatusProcessed, "")

	page := func(f HookFilter) []string {
		var got []string
		for range 5 {
			hooks, err := database.ListHooks(t.Context(), f, 2)
			if err != nil {
				t.Fatalf("ListHooks: %v", err)
			}
			if len(hooks) == 0 {
				break
			}
			for _, h := range hooks {
				got = append(got, h.ID)
			}
			f.After = hooks[len(hooks)-1].ID
		}
		return got
	}

	if got, want := page(HookFilter{}), []string{ids[5], ids[4], ids[3], ids[2], ids[1], ids[0]}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("all: got %v, want %v", got, want)
	}
	if got, want := page(HookFilter{Channel: "a"}), []string{ids[4], ids[2], ids[0]}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("channel a: got %v, want %v", got, want)
	}
	if got, want := page(HookFilter{Channel: "a", Status: StatusPending}), []string{ids[2], ids[0]}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("channel a pending: got %v, want %v", got, want)
	}
}

func TestPauseChannel(t *testing.T) {
	database := newTestDB(t)
	createHook(t, database, "contact")

	if _, paused, _, err := database.ChannelPolicy(t.Context(), "contact"); err != nil || paused {
		t.Fatalf("ChannelPolicy paused = %v, %v; want false", paused, err)
	}
	c, err := database.SetChannelPaused(t.Context(), "contact", true)
	if err != nil || !c.Paused() || c.Stats.Pending != 1 {
		t.Fatalf("SetChannelPaused(true) = %+v, %v", c, err)
	}
	pausedAt := *c.PausedAt

	// Pausing again keeps the original time.
	c, _ = database.SetChannelPaused(t.Context(), "contact", true)
	if !c.PausedAt.Equal(pausedAt) {
		t.Fatalf("paused_at moved from %v to %v", pausedAt, c.PausedAt)
	}
	if _, paused, _, _ := database.ChannelPolicy(t.Context(), "contact"); !paused {
		t.Fatal("ChannelPolicy paused = false after pausing")
	}

	c, _ = database.SetChannelPaused(t.Context(), "contact", false)
	if c.Paused() {
		t.Fatal("still paused after resuming")
	}
	if _, err := database.SetChannelPaused(t.Context(), "missing", true); err == nil {
		t.Fatal("pausing a missing channel succeeded")
	}
}

func TestGuards(t *testing.T) {
	database := newTestDB(t)

	// The seeded honeypot is the only guard.
	guards, err := database.ListGuards(t.Context())
	if err != nil || len(guards) != 1 || guards[0].Name != "honeypot" || guards[0].Type != "honeypot" {
		t.Fatalf("seeded guards = %+v, %v", guards, err)
	}

	g, err := database.CreateGuard(t.Context(), Guard{Name: "stripe-prod", Type: "signature", Scheme: "stripe", Secret: "whsec_abcdefgh1234"})
	if err != nil {
		t.Fatalf("CreateGuard: %v", err)
	}
	if g.SecretHint != "…1234" || g.Secret != "" {
		t.Fatalf("guard = %+v", g)
	}
	if _, err := database.CreateGuard(t.Context(), Guard{Name: "stripe-prod", Type: "honeypot"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate CreateGuard = %v", err)
	}

	// The secret is stored sealed, not in plaintext.
	var stored string
	database.sql.QueryRowContext(t.Context(), `SELECT secret FROM guards WHERE name = 'stripe-prod'`).Scan(&stored)
	if stored == "" || strings.Contains(stored, "whsec") {
		t.Fatalf("stored secret = %q", stored)
	}

	// Rotate the secret.
	g, err = database.RotateGuardSecret(t.Context(), "stripe-prod", "whsec_new_secret_9876")
	if err != nil || g.SecretHint != "…9876" {
		t.Fatalf("RotateGuardSecret = %+v, %v", g, err)
	}

	// Short secrets get no hint characters.
	g, _ = database.CreateGuard(t.Context(), Guard{Name: "short", Type: "captcha", Scheme: "turnstile", Secret: "abc"})
	if g.SecretHint != "…" {
		t.Fatalf("short hint = %q", g.SecretHint)
	}

	// Without a sealer, secrets can't be stored.
	database.UseSealer(nil)
	if _, err := database.CreateGuard(t.Context(), Guard{Name: "nokey", Type: "captcha", Scheme: "turnstile", Secret: "abc"}); err == nil {
		t.Fatal("stored a secret without a sealer")
	}
}

func TestChannelGuards(t *testing.T) {
	database := newTestDB(t)
	database.CreateGuard(t.Context(), Guard{Name: "jobs-hmac", Type: "signature", Scheme: "hmac", Secret: "s3cret-key-value"})

	// A channel that doesn't exist yet has no guards.
	exists, paused, guards, err := database.ChannelPolicy(t.Context(), "stripe")
	if err != nil || exists || paused || len(guards) != 0 {
		t.Fatalf("ChannelPolicy(missing) = %v, %v, %+v, %v", exists, paused, guards, err)
	}

	// A channel created by a hook starts without guards.
	createHook(t, database, "contact")
	if c, _ := database.GetChannel(t.Context(), "contact"); len(c.Guards) != 0 {
		t.Fatalf("contact guards = %v", c.Guards)
	}
	database.SetChannelGuards(t.Context(), "contact", []string{"honeypot"})

	// Setting guards creates the channel before any hook.
	c, err := database.SetChannelGuards(t.Context(), "jobs", []string{"jobs-hmac"})
	if err != nil || fmt.Sprint(c.Guards) != "[jobs-hmac]" {
		t.Fatalf("SetChannelGuards = %+v, %v", c, err)
	}
	exists, _, guards, _ = database.ChannelPolicy(t.Context(), "jobs")
	if !exists {
		t.Fatal("jobs doesn't exist")
	}
	if len(guards) != 1 || guards[0].Secret != "s3cret-key-value" || guards[0].Scheme != "hmac" {
		t.Fatalf("jobs policy = %+v", guards)
	}
	if _, err := database.SetChannelGuards(t.Context(), "jobs", []string{"missing"}); err == nil {
		t.Fatal("attached a missing guard")
	}

	// A guard in use can't be deleted until detached.
	if err := database.DeleteGuard(t.Context(), "jobs-hmac"); !errors.Is(err, ErrGuardInUse) {
		t.Fatalf("DeleteGuard in use = %v", err)
	}
	g, _ := database.GetGuard(t.Context(), "jobs-hmac")
	if fmt.Sprint(g.Channels) != "[jobs]" {
		t.Fatalf("guard channels = %v", g.Channels)
	}
	database.SetChannelGuards(t.Context(), "jobs", nil)
	if err := database.DeleteGuard(t.Context(), "jobs-hmac"); err != nil {
		t.Fatalf("DeleteGuard: %v", err)
	}

	// Deleting a channel detaches its guards.
	database.DeleteChannel(t.Context(), "contact")
	if g, _ := database.GetGuard(t.Context(), "honeypot"); len(g.Channels) != 0 {
		t.Fatalf("honeypot still on %v", g.Channels)
	}
}
