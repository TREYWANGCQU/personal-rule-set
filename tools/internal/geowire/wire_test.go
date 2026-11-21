// tools/internal/geowire/wire_test.go
package geowire

import (
	"bytes"
	"net"
	"testing"
)

func TestRawEntryPreservesUnknownAttributesAndReverseMatch(t *testing.T) {
	// Build a GeoSite Domain with field 3 (Attribute: key="cn", bool_value=true) manually.
	var attr []byte
	attr = AppendBytesField(attr, 1, []byte("cn"))
	attr = AppendTag(attr, 2, WireVarint)
	attr = append(attr, 1)

	dom := MarshalDomain(Domain{Type: DomainDomain, Value: "baidu.com"})
	dom = AppendBytesField(dom, 3, attr)

	var siteCN []byte
	siteCN = AppendBytesField(siteCN, 1, []byte("CN"))
	siteCN = AppendBytesField(siteCN, 2, dom)

	siteUS := MarshalGeoSite(GeoSite{
		Code:   "US",
		Domain: []Domain{{Type: DomainDomain, Value: "google.com"}},
	})

	var listBytes []byte
	listBytes = AppendBytesField(listBytes, 1, siteUS)
	listBytes = AppendBytesField(listBytes, 1, siteCN)

	entries, err := ExtractRawEntries(listBytes)
	if err != nil {
		t.Fatalf("ExtractRawEntries failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[1].Code != "CN" || entries[1].PayloadCount != 1 {
		t.Fatalf("unexpected CN metadata: %+v", entries[1])
	}
	if !bytes.Equal(entries[1].Raw, siteCN) {
		t.Fatalf("raw CN entry bytes were mutated (lost attribute field)")
	}
}

func TestGeoIPRoundTripAndMatch(t *testing.T) {
	list := &GeoIPList{
		Entry: []GeoIP{
			{
				Code: "CN",
				CIDR: []CIDR{
					{IP: net.ParseIP("114.114.114.0").To4(), Prefix: 24},
					{IP: net.ParseIP("2400:3200::").To16(), Prefix: 32},
				},
				ReverseMatch: true,
			},
		},
	}

	raw := MarshalGeoIPList(list)
	decoded, err := UnmarshalGeoIPList(raw)
	if err != nil {
		t.Fatalf("UnmarshalGeoIPList failed: %v", err)
	}
	if len(decoded.Entry) != 1 || decoded.Entry[0].Code != "CN" || !decoded.Entry[0].ReverseMatch {
		t.Fatalf("unexpected decoded GeoIPList: %+v", decoded)
	}
	if !MatchCIDR(decoded.Entry[0].CIDR[0], net.ParseIP("114.114.114.114")) {
		t.Errorf("expected 114.114.114.114 to match 114.114.114.0/24")
	}
	if MatchCIDR(decoded.Entry[0].CIDR[0], net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8 not to match 114.114.114.0/24")
	}
	if !MatchCIDR(decoded.Entry[0].CIDR[1], net.ParseIP("2400:3200::1")) {
		t.Errorf("expected 2400:3200::1 to match 2400:3200::/32")
	}
}
