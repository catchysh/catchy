package web

import (
	"github.com/catchysh/catchy/internal/db"
	"testing"
	"time"
)

func TestAgo(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.Local)
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{10 * time.Second, "just now"},
		{5 * time.Minute, "5m ago"},
		{3 * time.Hour, "3h ago"},
		{50 * time.Hour, "2d ago"},
		{30 * 24 * time.Hour, "Sep 8"},
		{400 * 24 * time.Hour, "Sep 3, 2025"},
	} {
		if got := ago(now.Add(-tc.d), now); got != tc.want {
			t.Errorf("ago(-%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestSummary(t *testing.T) {
	fs := []field{{"email", "jane@example.com"}, {"empty", " "}, {"message", "Hi\n  there"}}
	if got := summary(fs, "ignored"); got != "jane@example.com · Hi there" {
		t.Errorf("summary(fields) = %q", got)
	}
	if got := summary(nil, "<event>\n ping</event>"); got != "<event> ping</event>" {
		t.Errorf("summary(body) = %q", got)
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if got := []rune(summary(nil, string(long))); len(got) != 201 || got[200] != '…' {
		t.Errorf("long summary has %d runes", len(got))
	}
}

func TestAttemptRows(t *testing.T) {
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.Local)
	done := func(d time.Duration) *time.Time { t := at.Add(d); return &t }
	rows := hookHandlerRows([]db.Attempt{
		{Handler: "broken", Number: 1, Status: db.AttemptFailed, Error: "refused", FinishedAt: done(0)},
		{Handler: "broken", Number: 2, Status: db.AttemptFailed, Error: "HTTP 503", HTTPStatus: 503, FinishedAt: done(10 * time.Second)},
		{Handler: "broken", Number: 3, Status: db.AttemptPending, DueAt: at.Add(50 * time.Second)},
		{Handler: "echo", Number: 1, Status: db.AttemptSucceeded, HTTPStatus: 200, MS: 12, FinishedAt: done(0)},
		{Handler: "new", Number: 1, Status: db.AttemptPending, DueAt: at},
	})
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	if b := rows[0]; b.Status != db.AttemptPending || b.Attempts != 2 || b.LastError != "HTTP 503" || b.NextAt != "12:00:50" || len(b.History) != 2 || b.History[1].Status != 503 {
		t.Errorf("broken = %+v", b)
	}
	if e := rows[1]; e.Status != db.AttemptSucceeded || e.Attempts != 1 || e.NextAt != "" || e.History[0].MS != 12 {
		t.Errorf("echo = %+v", e)
	}
	if n := rows[2]; n.Status != db.AttemptPending || n.Attempts != 0 || n.NextAt != "" || n.History != nil {
		t.Errorf("new = %+v", n)
	}
}

func TestSummarizeHandlers(t *testing.T) {
	if summarizeHandlers(nil) != nil {
		t.Fatal("a hook without handlers has a summary")
	}
	ok := hookHandlerRow{Handler: "echo", Status: db.AttemptSucceeded}
	retrying := hookHandlerRow{Handler: "slack", Status: db.AttemptPending, NextAt: "10:50:13", LastError: "HTTP 503"}
	gaveUp := hookHandlerRow{Handler: "broken", Status: db.AttemptFailed, LastError: "refused"}
	for _, tc := range []struct {
		rows  []hookHandlerRow
		state string
		done  int
	}{
		{[]hookHandlerRow{ok, ok}, db.AttemptSucceeded, 2},
		{[]hookHandlerRow{ok, retrying}, db.AttemptPending, 1},
		{[]hookHandlerRow{retrying, gaveUp, ok}, db.AttemptFailed, 1},
	} {
		s := summarizeHandlers(tc.rows)
		if s.State != tc.state || s.Done != tc.done || s.Total != len(tc.rows) {
			t.Errorf("summary = %+v, want %s %d/%d", s, tc.state, tc.done, len(tc.rows))
		}
	}
	if s := summarizeHandlers([]hookHandlerRow{retrying, gaveUp}); s.Title != "slack: retry at 10:50:13: HTTP 503\nbroken: gave up: refused" {
		t.Errorf("title = %q", s.Title)
	}
}
