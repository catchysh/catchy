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

func TestDeliveryRows(t *testing.T) {
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.Local)
	done := func(d time.Duration) *time.Time { t := at.Add(d); return &t }
	rows := deliveryRows([]db.Delivery{
		{Destination: "broken", Attempt: 1, Status: db.DeliveryFailed, Error: "refused", FinishedAt: done(0)},
		{Destination: "broken", Attempt: 2, Status: db.DeliveryFailed, Error: "HTTP 503", HTTPStatus: 503, FinishedAt: done(10 * time.Second)},
		{Destination: "broken", Attempt: 3, Status: db.DeliveryPending, DueAt: at.Add(50 * time.Second)},
		{Destination: "echo", Attempt: 1, Status: db.DeliveryDelivered, HTTPStatus: 200, MS: 12, FinishedAt: done(0)},
		{Destination: "new", Attempt: 1, Status: db.DeliveryPending, DueAt: at},
	})
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	if b := rows[0]; b.Status != db.DeliveryPending || b.Attempts != 2 || b.LastError != "HTTP 503" || b.NextAt != "12:00:50" || len(b.History) != 2 || b.History[1].Status != 503 {
		t.Errorf("broken = %+v", b)
	}
	if e := rows[1]; e.Status != db.DeliveryDelivered || e.Attempts != 1 || e.NextAt != "" || e.History[0].MS != 12 {
		t.Errorf("echo = %+v", e)
	}
	if n := rows[2]; n.Status != db.DeliveryPending || n.Attempts != 0 || n.NextAt != "" || n.History != nil {
		t.Errorf("new = %+v", n)
	}
}
