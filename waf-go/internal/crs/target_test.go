package crs

import "testing"

func TestTargetName(t *testing.T) {
	for tg, want := range map[Target]string{
		{Rule: 941120, Variable: "REQUEST_FILENAME"}:          "REQUEST_FILENAME",
		{Rule: 942290, Variable: "ARGS", Key: "pwd"}:          "ARGS:pwd",
		{Rule: 942290, Variable: "ARGS", Key: "/a.b/"}:        `ARGS:/^/a\.b/$/`,
		{Rule: 942290, Variable: "REQUEST_COOKIES", Key: "/"}: "REQUEST_COOKIES:/",
	} {
		if got := tg.Name(); got != want {
			t.Errorf("%+v: %s, want %s", tg, got, want)
		}
	}
}
