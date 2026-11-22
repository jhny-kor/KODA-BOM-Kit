package main

import "testing"

func TestValidAssetTag(t *testing.T) {
	for tag, want := range map[string]bool{
		"": true, "web-01": true, "서버-01 (DMZ)": true,
		" web": false, "web ": false, "a\nb": false, "a\x00b": false, string(make([]byte, 129)): false,
	} {
		if got := validAssetTag(tag); got != want {
			t.Errorf("validAssetTag(%q) = %v, want %v", tag, got, want)
		}
	}
}
