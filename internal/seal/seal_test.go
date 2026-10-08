package seal

import (
	"strings"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	s, err := New("test-key")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Seal("whsec_123")
	b, _ := s.Seal("whsec_123")
	if a == b || strings.Contains(a, "whsec") {
		t.Fatalf("sealed values should be random and opaque: %q, %q", a, b)
	}
	if got, err := s.Open(a); err != nil || got != "whsec_123" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestOpenFailures(t *testing.T) {
	s, _ := New("test-key")
	other, _ := New("other-key")
	sealed, _ := s.Seal("secret")

	if _, err := other.Open(sealed); err == nil {
		t.Fatal("opened with the wrong key")
	}
	tampered := sealed[:len(sealed)-2] + "AA"
	if _, err := s.Open(tampered); err == nil {
		t.Fatal("opened a tampered value")
	}
	for _, bad := range []string{"", "secret", "v1:", "v1:!!!"} {
		if _, err := s.Open(bad); err == nil {
			t.Fatalf("opened %q", bad)
		}
	}
	if _, err := New(""); err == nil {
		t.Fatal("New accepted an empty key")
	}
}
