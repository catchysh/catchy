package env

import (
	"slices"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	e, skipped := Load([]string{
		"CATCHY_VAR_to=team@acme.dev", "CATCHY_VAR_subject=a=b", "CATCHY_SECRET_RESEND=re_123",
		"ENCRYPTION_KEY=nope", "SESSION_SECRET=nope", "SECRET_KEY_BASE=nope", "VAR_x=nope", "CATCHY_VAR_=x", "CATCHY_VAR_bad-name=x", "PATH=/bin",
	})
	if e.Vars["to"] != "team@acme.dev" || e.Vars["subject"] != "a=b" || len(e.Vars) != 2 {
		t.Fatalf("vars = %v", e.Vars)
	}
	if e.Secrets["RESEND"] != "re_123" || len(e.Secrets) != 1 {
		t.Fatalf("secrets = %v", e.Secrets)
	}
	if !slices.Equal(skipped, []string{"CATCHY_VAR_", "CATCHY_VAR_bad-name"}) {
		t.Fatalf("skipped = %v", skipped)
	}
}

func TestSecret(t *testing.T) {
	e := Env{Secrets: map[string]string{"STRIPE": "whsec_12345678"}}
	if v, err := e.Secret("STRIPE"); v != "whsec_12345678" || err != nil {
		t.Fatalf("Secret = %q, %v", v, err)
	}
	if _, err := e.Secret("MISSING"); err == nil || !strings.Contains(err.Error(), "CATCHY_SECRET_MISSING") {
		t.Fatalf("missing secret error = %v", err)
	}
}
