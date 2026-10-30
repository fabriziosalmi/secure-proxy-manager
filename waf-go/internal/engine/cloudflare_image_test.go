package engine

import "testing"

func TestWithoutCloudflareImageRedirect(t *testing.T) {
	for in, want := range map[string]string{
		"http://a.example/cdn-cgi/image/onerror=redirect,width=640/x.jpg": "http://a.example/cdn-cgi/image/width=640/x.jpg",
		"http://a.example/cdn-cgi/image/width=640,onerror=redirect/x.jpg": "http://a.example/cdn-cgi/image/width=640/x.jpg",
		"http://a.example/cdn-cgi/image/onerror=redirect/x.jpg":           "http://a.example/cdn-cgi/image//x.jpg",
		// Left as they are: another value, an encoded form, the option in
		// the source or the query, the prefix anywhere but at the start of
		// the path, and an option list with no source after it.
		"http://a.example/cdn-cgi/image/onerror=alert(1),width=640/x.jpg": "",
		"http://a.example/cdn-cgi/image/onerror%3Dredirect/x.jpg":         "",
		"http://a.example/cdn-cgi/image/width=640/onerror=redirect/x.jpg": "",
		"http://a.example/x.jpg?u=/cdn-cgi/image/onerror=redirect/y":      "",
		"http://a.example/p/cdn-cgi/image/onerror=redirect/x.jpg":         "",
		"http://a.example/cdn-cgi/image/onerror=redirect":                 "",
		"/cdn-cgi/image/onerror=redirect/x.jpg":                           "",
	} {
		if want == "" {
			want = in
		}
		if got := WithoutCloudflareImageRedirect(in); got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
}
