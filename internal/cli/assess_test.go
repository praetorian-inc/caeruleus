package cli

import "testing"

func TestLooksLikeCredential(t *testing.T) {
	cases := map[string]bool{
		"admin:password123":                    true,  // keyword + user:pass form
		"svc:hunter2longenough":                true,  // user:pass form, no keyword
		"my password is correcthorse":          true,  // keyword
		"apikey=ABCDEF0123456789":              true,  // keyword
		"-----BEGIN RSA PRIVATE KEY-----":      true,  // PEM header
		"Caeruleus-Target":                     false, // device name
		"Nordic Semiconductor":                 false, // manufacturer
		"John Doe, john@example.com, 555-0123": false, // PII, not a credential pattern
		"0000":                                 false,
		"":                                     false,
	}
	for in, want := range cases {
		if got := looksLikeCredential(in); got != want {
			t.Errorf("looksLikeCredential(%q) = %v, want %v", in, got, want)
		}
	}
}
