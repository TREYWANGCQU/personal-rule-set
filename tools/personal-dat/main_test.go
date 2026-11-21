// tools/personal-dat/main_test.go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseAndRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	sample := "payload:\n" +
		"  # comment\n" +
		"  - DOMAIN-SUFFIX,Example.COM\n" +
		"  - DOMAIN,api.example.com\n" +
		"  - DOMAIN-KEYWORD,linkedin\n" +
		"  - DOMAIN-REGEX,^ads\\.[a-z]+\\.com$\n" +
		"  - IP-CIDR,1.1.1.1/32,no-resolve\n" +
		"  - domain:example.com\n" + // duplicate of DOMAIN-SUFFIX,Example.COM
		"  - full:exact.test.org\n" +
		"  - keyword:internal\n" +
		"  - regexp:^cdn[0-9]+\\.test\\.net$\n"

	if err := os.WriteFile(filepath.Join(tmp, "sample_rules.txt"), []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}

	list1, err := buildGeoSiteList(tmp)
	if err != nil {
		t.Fatalf("buildGeoSiteList failed: %v", err)
	}
	list2, err := buildGeoSiteList(tmp)
	if err != nil {
		t.Fatalf("second buildGeoSiteList failed: %v", err)
	}

	raw1 := marshalGeoSiteList(list1)
	raw2 := marshalGeoSiteList(list2)
	if !bytes.Equal(raw1, raw2) {
		t.Fatalf("marshal output is not deterministic")
	}

	decoded, err := unmarshalGeoSiteList(raw1)
	if err != nil {
		t.Fatalf("unmarshalGeoSiteList failed: %v", err)
	}
	if len(decoded.Entry) != 1 {
		t.Fatalf("expected 1 GeoSite entry, got %d", len(decoded.Entry))
	}
	site := decoded.Entry[0]
	if site.Code != "SAMPLE_RULES" {
		t.Fatalf("expected code SAMPLE_RULES, got %q", site.Code)
	}
	// 7 unique domain rules (IP-CIDR skipped, duplicate example.com deduplicated)
	if len(site.Domain) != 7 {
		t.Fatalf("expected 7 deduplicated domains, got %d: %+v", len(site.Domain), site.Domain)
	}

	// Verify matching across all 4 DomainType variants
	cases := []struct {
		domain string
		want   bool
	}{
		{"sub.example.com", true},
		{"example.com", true},
		{"api.example.com", true},
		{"my-linkedin-app.io", true},
		{"ads.google.com", true},
		{"cdn42.test.net", true},
		{"exact.test.org", true},
		{"unmatched.invalid", false},
	}
	for _, tc := range cases {
		matched := false
		for _, d := range site.Domain {
			if matchDomain(d, tc.domain) {
				matched = true
				break
			}
		}
		if matched != tc.want {
			t.Errorf("match(%q) = %v, want %v", tc.domain, matched, tc.want)
		}
	}
}

func TestInvalidRegexFailsBuild(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "bad.txt"), []byte("payload:\n  - DOMAIN-REGEX,[unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildGeoSiteList(tmp); err == nil {
		t.Fatalf("expected error for invalid regex, got nil")
	}
}
