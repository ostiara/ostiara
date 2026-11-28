package main

import "testing"

func TestParsePorts(t *testing.T) {
	cases := []struct {
		spec          string
		local, remote int
		ok            bool
	}{
		{"5432", 5432, 5432, true},
		{"15432:5432", 15432, 5432, true},
		{"0", 0, 0, false},
		{"70000", 0, 0, false},
		{"abc", 0, 0, false},
		{":5432", 0, 0, false},
		{"8080:", 0, 0, false},
	}
	for _, tc := range cases {
		local, remote, err := parsePorts(tc.spec)
		if (err == nil) != tc.ok || local != tc.local || remote != tc.remote {
			t.Errorf("parsePorts(%q) = (%d, %d, %v), want (%d, %d, ok=%v)", tc.spec, local, remote, err, tc.local, tc.remote, tc.ok)
		}
	}
}
