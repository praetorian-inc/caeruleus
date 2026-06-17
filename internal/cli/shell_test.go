package cli

import (
	"testing"
	"time"
)

func TestParseScanDuration(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		interactive bool
		wantDur     time.Duration
		wantErr     bool // expect a non-empty errMsg
	}{
		{"positive integer", []string{"8"}, true, 8 * time.Second, false},
		{"positive integer without a terminal is fine", []string{"8"}, false, 8 * time.Second, false},
		{"zero is rejected", []string{"0"}, true, 0, true},
		{"negative is rejected", []string{"-3"}, true, 0, true},
		{"non-numeric is rejected", []string{"abc"}, true, 0, true},
		{"no arg with terminal allows indefinite", nil, true, 0, false},
		{"no arg without terminal requires a duration", nil, false, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dur, errMsg := parseScanDuration(tc.args, tc.interactive)
			if gotErr := errMsg != ""; gotErr != tc.wantErr {
				t.Errorf("errMsg = %q (err=%v), want err=%v", errMsg, gotErr, tc.wantErr)
			}
			if dur != tc.wantDur {
				t.Errorf("dur = %v, want %v", dur, tc.wantDur)
			}
		})
	}
}

func TestResolveConnectTarget(t *testing.T) {
	list := []string{"AA:AA:AA:AA:AA:01", "BB:BB:BB:BB:BB:02", "CC:CC:CC:CC:CC:03"}

	cases := []struct {
		name        string
		list        []string
		tok         string
		wantAddr    string
		wantIsIndex bool
		wantErr     bool // expect a non-empty errMsg
	}{
		{"non-numeric is treated as an address", list, "DD:DD:DD:DD:DD:04", "", false, false},
		{"first index", list, "1", "AA:AA:AA:AA:AA:01", true, false},
		{"middle index", list, "2", "BB:BB:BB:BB:BB:02", true, false},
		{"last index", list, "3", "CC:CC:CC:CC:CC:03", true, false},
		{"zero is out of range (1-based)", list, "0", "", true, true},
		{"negative is out of range", list, "-1", "", true, true},
		{"past the end is out of range", list, "99", "", true, true},
		{"numeric with no prior scan", nil, "2", "", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, isIndex, errMsg := resolveConnectTarget(tc.list, tc.tok)
			if isIndex != tc.wantIsIndex {
				t.Errorf("isIndex = %v, want %v", isIndex, tc.wantIsIndex)
			}
			if addr != tc.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tc.wantAddr)
			}
			if gotErr := errMsg != ""; gotErr != tc.wantErr {
				t.Errorf("errMsg = %q (err=%v), want err=%v", errMsg, gotErr, tc.wantErr)
			}
		})
	}
}
