package privacy

import (
	"testing"
)

func TestMaskIP(t *testing.T) {
	cases := []struct {
		in         string
		wantMasked string
		wantPrefix string
		wantOK     bool
	}{
		{"192.168.1.7", "192.168.1.x", "192.168.1.0/24", true},
		{"10.0.0.255", "10.0.0.x", "10.0.0.0/24", true},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::x", "2001:db8:1:2::/64", true},
		{"2001:db8::abcd:1", "2001:db8::x", "2001:db8::/64", true},
		{"2001:db8::1", "2001:db8::x", "2001:db8::/64", true},
		{"::1", "::x", "::/64", true},
		{"fe80::1%eth0", "fe80::x", "fe80::/64", true},
		{"::ffff:192.168.1.7", "192.168.1.x", "192.168.1.0/24", true},
		{"", "unknown", "", false},
		{"not-an-ip", "unknown", "", false},
		{"192.168.1.999", "unknown", "", false},
		{"2001:db8:::1", "unknown", "", false},
		{"-", "unknown", "", false},
	}

	for _, tc := range cases {
		if got := MaskIP(tc.in); got != tc.wantMasked {
			t.Errorf("MaskIP(%q) = %q, want %q", tc.in, got, tc.wantMasked)
		}
		p, ok := NetworkPrefix(tc.in)
		if ok != tc.wantOK {
			t.Errorf("NetworkPrefix(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && p.String() != tc.wantPrefix {
			t.Errorf("NetworkPrefix(%q) = %q, want %q", tc.in, p.String(), tc.wantPrefix)
		}
	}
}
