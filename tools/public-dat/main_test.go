// tools/public-dat/main_test.go
package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/TREYWANGCQU/personal-rule-set/tools/internal/geowire"
)

func TestSliceGeoSiteLosslessAndDeterministic(t *testing.T) {
	// Construct a CN entry with a Domain Attribute (field 3) to verify lossless raw passthrough.
	var attr []byte
	attr = geowire.AppendBytesField(attr, 1, []byte("cn"))
	attr = geowire.AppendTag(attr, 2, geowire.WireVarint)
	attr = append(attr, 1)

	domCN := geowire.MarshalDomain(geowire.Domain{Type: geowire.DomainDomain, Value: "baidu.com"})
	domCN = geowire.AppendBytesField(domCN, 3, attr)

	var siteCN []byte
	siteCN = geowire.AppendBytesField(siteCN, 1, []byte("CN"))
	siteCN = geowire.AppendBytesField(siteCN, 2, domCN)

	sitePrivate := geowire.MarshalGeoSite(geowire.GeoSite{
		Code:   "PRIVATE",
		Domain: []geowire.Domain{{Type: geowire.DomainDomain, Value: "local"}},
	})
	siteUS := geowire.MarshalGeoSite(geowire.GeoSite{
		Code:   "US",
		Domain: []geowire.Domain{{Type: geowire.DomainDomain, Value: "google.com"}},
	})

	// Deliberately place PRIVATE before CN and include US.
	var upstream []byte
	upstream = geowire.AppendBytesField(upstream, 1, siteUS)
	upstream = geowire.AppendBytesField(upstream, 1, sitePrivate)
	upstream = geowire.AppendBytesField(upstream, 1, siteCN)

	sliced, kept, err := sliceDatBytes(upstream, []string{"CN", "PRIVATE"})
	if err != nil {
		t.Fatalf("sliceDatBytes failed: %v", err)
	}
	if len(kept) != 2 || kept[0].Code != "CN" || kept[1].Code != "PRIVATE" {
		t.Fatalf("expected sorted [CN, PRIVATE], got %+v", kept)
	}
	if !bytes.Equal(kept[0].Raw, siteCN) {
		t.Fatalf("CN raw entry bytes were modified; Domain.attribute was not preserved")
	}

	if err := verifyGeoSite("mem", sliced, []string{"CN", "PRIVATE"}, 2, "www.baidu.com", "google.com", ""); err != nil {
		t.Fatalf("verifyGeoSite failed: %v", err)
	}
}

func TestSliceGeoIPPreservesReverseMatchAndRejectsMissing(t *testing.T) {
	upstream := geowire.MarshalGeoIPList(&geowire.GeoIPList{
		Entry: []geowire.GeoIP{
			{
				Code: "PRIVATE",
				CIDR: []geowire.CIDR{{IP: net.ParseIP("192.168.0.0").To4(), Prefix: 16}},
			},
			{
				Code:         "CN",
				CIDR:         []geowire.CIDR{{IP: net.ParseIP("114.114.114.0").To4(), Prefix: 24}},
				ReverseMatch: true,
			},
			{
				Code: "US",
				CIDR: []geowire.CIDR{{IP: net.ParseIP("8.8.8.0").To4(), Prefix: 24}},
			},
		},
	})

	sliced, _, err := sliceDatBytes(upstream, []string{"CN", "PRIVATE"})
	if err != nil {
		t.Fatalf("sliceDatBytes failed: %v", err)
	}

	decoded, err := geowire.UnmarshalGeoIPList(sliced)
	if err != nil {
		t.Fatalf("UnmarshalGeoIPList failed: %v", err)
	}
	if len(decoded.Entry) != 2 || decoded.Entry[0].Code != "CN" || !decoded.Entry[0].ReverseMatch {
		t.Fatalf("expected CN with ReverseMatch=true first, got %+v", decoded.Entry)
	}

	if err := verifyGeoIP("mem", sliced, []string{"CN", "PRIVATE"}, 2, "114.114.114.114", "8.8.8.8", ""); err != nil {
		t.Fatalf("verifyGeoIP failed: %v", err)
	}

	if _, _, err := sliceDatBytes(upstream, []string{"CN", "JP"}); err == nil {
		t.Fatalf("expected error for missing required code JP, got nil")
	}
}

func TestBuildAntiADValidAndCircuitBreakers(t *testing.T) {
	tmp := t.TempDir()
	sample := "\ufeff# anti-AD header\n" +
		"! adblock comment\n" +
		"// slash comment\n" +
		"Ad.Example.COM\n" +
		"ad.example.com.\n" + // duplicate after lowercase + trailing dot trim
		"tracker.test.org # inline comment\n" +
		"bad line with spaces\n" +
		"analytics.ads.net\n"

	// 4 non-comment lines, 1 invalid -> 25% invalid ratio; test both pass (ratio 0.30) and trip (ratio 0.05).
	inFile := filepath.Join(tmp, "anti-ad-domains.txt")
	if err := os.WriteFile(inFile, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := buildAntiADGeoSite(inFile, "ANTI-AD", 2, 0.05); err == nil {
		t.Fatalf("expected invalid ratio circuit breaker to trigger")
	}

	list, stats, err := buildAntiADGeoSite(inFile, "ANTI-AD", 3, 0.30)
	if err != nil {
		t.Fatalf("buildAntiADGeoSite failed: %v", err)
	}
	if stats.UniqueDomains != 3 || stats.InvalidLines != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if len(list.Entry) != 1 || list.Entry[0].Code != "ANTI-AD" {
		t.Fatalf("unexpected GeoSite entry: %+v", list.Entry)
	}

	raw := geowire.MarshalGeoSiteList(list)
	if err := verifyGeoSite("mem", raw, []string{"ANTI-AD"}, 3, "sub.ad.example.com", "clean.example.org", "ANTI-AD"); err != nil {
		t.Fatalf("verifyGeoSite failed: %v", err)
	}

	// Minimum rules circuit breaker.
	if _, _, err := buildAntiADGeoSite(inFile, "ANTI-AD", 10, 0.30); err == nil {
		t.Fatalf("expected min-rules circuit breaker to trigger")
	}
}
