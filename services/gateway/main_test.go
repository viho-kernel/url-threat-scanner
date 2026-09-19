package main

import "testing"

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		shouldErr bool
	}{
		{"public HTTPS", "https://example.com/path?q=test", false},
		{"public HTTP", "http://example.com", false},
		{"empty URL", "", true},
		{"unsupported scheme", "file:///etc/passwd", true},
		{"FTP scheme", "ftp://example.com", true},
		{"missing hostname", "https:///path", true},
		{"credentials", "https://admin:password@example.com", true},
		{"fragment", "https://example.com/#section", true},
		{"custom port", "https://example.com:8443", true},
		{"localhost", "http://localhost", true},
		{"local domain", "http://service.internal", true},
		{"IPv4 loopback", "http://127.0.0.1", true},
		{"IPv4 private", "http://10.0.0.1", true},
		{"link local metadata", "http://169.254.169.254", true},
		{"IPv6 loopback", "http://[::1]", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateURL(test.url)

			if test.shouldErr && err == nil {
				t.Fatalf("expected %q to be rejected", test.url)
			}

			if !test.shouldErr && err != nil {
				t.Fatalf("expected %q to be accepted, got: %v", test.url, err)
			}
		})
	}
}
