package client

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestFlexInt(t *testing.T) {
	cases := map[string]FlexInt{
		`1`: Int(1), `"1"`: Int(1), `true`: Int(1), `false`: Int(0), `0`: Int(0),
		`null`: {}, `""`: {}, `"42"`: Int(42), `-3`: Int(-3),
	}
	for in, want := range cases {
		var got FlexInt
		if err := json.Unmarshal([]byte(in), &got); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s: got %+v want %+v", in, got, want)
		}
	}
	var bad FlexInt
	if err := json.Unmarshal([]byte(`"abc"`), &bad); err == nil {
		t.Error("expected error")
	}
	b, _ := json.Marshal(struct {
		A *FlexInt `json:"a,omitempty"`
		B FlexInt  `json:"b"`
	}{B: Int(5)})
	if string(b) != `{"b":5}` {
		t.Errorf("marshal = %s", b)
	}
}

func TestValidateHostname(t *testing.T) {
	ok := []string{"api.ibosscloud.com", "cn-1976866141-46-vnsg13450.ibosscloud.com", "A.B.example"}
	bad := []string{"", "localhost", "https://api.ibosscloud.com", "api.ibosscloud.com:443", "a..b", "-a.example", "a.example/x", "10.0.0.1", "a b.example", "user@a.example"}
	for _, h := range ok {
		if err := ValidateHostname(h); err != nil {
			t.Errorf("%q: %v", h, err)
		}
	}
	for _, h := range bad {
		if err := ValidateHostname(h); err == nil {
			t.Errorf("%q: expected error", h)
		}
	}
}

func TestAllowedSuffix(t *testing.T) {
	s := []string{".ibosscloud.com"}
	if !hasAllowedSuffix("cn-1.ibosscloud.com", s) {
		t.Error("expected allowed")
	}
	for _, h := range []string{"ibosscloud.com", "evilibosscloud.com", "cn-1.ibosscloud.com.evil.example"} {
		if hasAllowedSuffix(h, s) {
			t.Errorf("%q should be rejected", h)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("7", now); got != 7*time.Second {
		t.Errorf("seconds: %v", got)
	}
	if got := parseRetryAfter(now.Add(3*time.Second).Format(http.TimeFormat), now); got != 3*time.Second {
		t.Errorf("date: %v", got)
	}
	for _, v := range []string{"", "-1", "soon"} {
		if got := parseRetryAfter(v, now); got != 0 {
			t.Errorf("%q: %v", v, got)
		}
	}
}

func TestFindURLEntry(t *testing.T) {
	entries := []URLListEntry{{URL: "google.com"}, {URL: "dropbox.com/"}, {URL: "Dup.example"}, {URL: "dup.example/"}}
	if e, ok, _ := FindURLEntry(entries, "google.com"); !ok || e.URL != "google.com" {
		t.Error("exact match")
	}
	if e, ok, _ := FindURLEntry(entries, "Dropbox.com"); !ok || e.URL != "dropbox.com/" {
		t.Error("equivalent match")
	}
	if _, ok, err := FindURLEntry(entries, "missing.example"); ok || err != nil {
		t.Error("absent")
	}
	if _, _, err := FindURLEntry(entries, "DUP.EXAMPLE"); err == nil {
		t.Error("ambiguous equivalents must error")
	}
	if e, ok, err := FindURLEntry(entries, "dup.example/"); !ok || err != nil || e.URL != "dup.example/" {
		t.Error("exact match wins over ambiguity")
	}
}

func TestRedact(t *testing.T) {
	c := &Client{cfg: Config{APIKey: "key-abcdef", Password: "pw-123456"}}
	s := &session{token: "tok-zzzz", cloudXSRF: "xsrf-yyyy"}
	got := c.redact(s, "key-abcdef pw-123456 tok-zzzz xsrf-yyyy ok")
	if got != "[REDACTED] [REDACTED] [REDACTED] [REDACTED] ok" {
		t.Errorf("got %q", got)
	}
}
