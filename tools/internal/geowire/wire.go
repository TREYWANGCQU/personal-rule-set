// tools/internal/geowire/wire.go
package geowire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DomainType mirrors xray.common.geodata.Domain_Type in common/geodata/geodat.proto.
type DomainType uint32

const (
	DomainSubstr DomainType = 0
	DomainRegex  DomainType = 1
	DomainDomain DomainType = 2
	DomainFull   DomainType = 3
)

func (t DomainType) String() string {
	switch t {
	case DomainSubstr:
		return "Substr"
	case DomainRegex:
		return "Regex"
	case DomainDomain:
		return "Domain"
	case DomainFull:
		return "Full"
	default:
		return fmt.Sprintf("DomainType(%d)", uint32(t))
	}
}

// Domain mirrors xray.common.geodata.Domain (fields 1 and 2; field 3 attributes are preserved in raw slicing).
type Domain struct {
	Type  DomainType
	Value string
}

// GeoSite mirrors xray.common.geodata.GeoSite.
type GeoSite struct {
	Code   string
	Domain []Domain
}

// GeoSiteList mirrors xray.common.geodata.GeoSiteList.
type GeoSiteList struct {
	Entry []GeoSite
}

// CIDR mirrors xray.common.geodata.CIDR.
type CIDR struct {
	IP     []byte
	Prefix uint32
}

// GeoIP mirrors xray.common.geodata.GeoIP.
type GeoIP struct {
	Code         string
	CIDR         []CIDR
	ReverseMatch bool
}

// GeoIPList mirrors xray.common.geodata.GeoIPList.
type GeoIPList struct {
	Entry []GeoIP
}

// RawEntry holds a top-level GeoSite or GeoIP entry verbatim with its parsed metadata.
type RawEntry struct {
	Code         string
	PayloadCount int
	Raw          []byte
}

// Proto3 wire types.
const (
	WireVarint  = 0
	WireFixed64 = 1
	WireBytes   = 2
	WireFixed32 = 5
)

func AppendTag(b []byte, fieldNum uint64, wireType uint64) []byte {
	return binary.AppendUvarint(b, (fieldNum<<3)|wireType)
}

func AppendBytesField(b []byte, fieldNum uint64, val []byte) []byte {
	b = AppendTag(b, fieldNum, WireBytes)
	b = binary.AppendUvarint(b, uint64(len(val)))
	return append(b, val...)
}

func ConsumeVarint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n == 0 {
		return 0, 0, errors.New("truncated varint")
	}
	if n < 0 {
		return 0, 0, errors.New("varint overflow")
	}
	return v, n, nil
}

func ConsumeBytes(b []byte) ([]byte, int, error) {
	l, n, err := ConsumeVarint(b)
	if err != nil {
		return nil, 0, err
	}
	if l > uint64(len(b)-n) {
		return nil, 0, errors.New("truncated length-delimited field")
	}
	end := n + int(l)
	return b[n:end], end, nil
}

func SkipField(b []byte, wireType uint64) (int, error) {
	switch wireType {
	case WireVarint:
		_, n, err := ConsumeVarint(b)
		return n, err
	case WireFixed64:
		if len(b) < 8 {
			return 0, errors.New("truncated fixed64")
		}
		return 8, nil
	case WireBytes:
		_, n, err := ConsumeBytes(b)
		return n, err
	case WireFixed32:
		if len(b) < 4 {
			return 0, errors.New("truncated fixed32")
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported wire type %d", wireType)
	}
}

// --- GeoSiteList encode/decode ---

func MarshalDomain(d Domain) []byte {
	var b []byte
	if d.Type != 0 {
		b = AppendTag(b, 1, WireVarint)
		b = binary.AppendUvarint(b, uint64(d.Type))
	}
	if d.Value != "" {
		b = AppendBytesField(b, 2, []byte(d.Value))
	}
	return b
}

func MarshalGeoSite(s GeoSite) []byte {
	var b []byte
	if s.Code != "" {
		b = AppendBytesField(b, 1, []byte(s.Code))
	}
	for _, d := range s.Domain {
		b = AppendBytesField(b, 2, MarshalDomain(d))
	}
	return b
}

func MarshalGeoSiteList(list *GeoSiteList) []byte {
	var b []byte
	if list == nil {
		return b
	}
	for _, e := range list.Entry {
		b = AppendBytesField(b, 1, MarshalGeoSite(e))
	}
	return b
}

func UnmarshalDomain(b []byte) (Domain, error) {
	var d Domain
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return Domain{}, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireVarint:
			v, m, err := ConsumeVarint(b)
			if err != nil {
				return Domain{}, err
			}
			d.Type = DomainType(v)
			b = b[m:]
		case fieldNum == 2 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return Domain{}, err
			}
			d.Value = string(raw)
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return Domain{}, err
			}
			b = b[m:]
		}
	}
	return d, nil
}

func UnmarshalGeoSite(b []byte) (GeoSite, error) {
	var s GeoSite
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return GeoSite{}, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return GeoSite{}, err
			}
			s.Code = string(raw)
			b = b[m:]
		case fieldNum == 2 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return GeoSite{}, err
			}
			d, err := UnmarshalDomain(raw)
			if err != nil {
				return GeoSite{}, err
			}
			s.Domain = append(s.Domain, d)
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return GeoSite{}, err
			}
			b = b[m:]
		}
	}
	return s, nil
}

func UnmarshalGeoSiteList(b []byte) (*GeoSiteList, error) {
	list := &GeoSiteList{}
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return nil, err
			}
			site, err := UnmarshalGeoSite(raw)
			if err != nil {
				return nil, err
			}
			list.Entry = append(list.Entry, site)
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return nil, err
			}
			b = b[m:]
		}
	}
	return list, nil
}

// --- GeoIPList encode/decode ---

func MarshalCIDR(c CIDR) []byte {
	var b []byte
	if len(c.IP) > 0 {
		b = AppendBytesField(b, 1, c.IP)
	}
	if c.Prefix != 0 {
		b = AppendTag(b, 2, WireVarint)
		b = binary.AppendUvarint(b, uint64(c.Prefix))
	}
	return b
}

func MarshalGeoIP(g GeoIP) []byte {
	var b []byte
	if g.Code != "" {
		b = AppendBytesField(b, 1, []byte(g.Code))
	}
	for _, c := range g.CIDR {
		b = AppendBytesField(b, 2, MarshalCIDR(c))
	}
	if g.ReverseMatch {
		b = AppendTag(b, 3, WireVarint)
		b = binary.AppendUvarint(b, 1)
	}
	return b
}

func MarshalGeoIPList(list *GeoIPList) []byte {
	var b []byte
	if list == nil {
		return b
	}
	for _, e := range list.Entry {
		b = AppendBytesField(b, 1, MarshalGeoIP(e))
	}
	return b
}

func UnmarshalCIDR(b []byte) (CIDR, error) {
	var c CIDR
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return CIDR{}, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return CIDR{}, err
			}
			ipCopy := make([]byte, len(raw))
			copy(ipCopy, raw)
			c.IP = ipCopy
			b = b[m:]
		case fieldNum == 2 && wireType == WireVarint:
			v, m, err := ConsumeVarint(b)
			if err != nil {
				return CIDR{}, err
			}
			c.Prefix = uint32(v)
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return CIDR{}, err
			}
			b = b[m:]
		}
	}
	return c, nil
}

func UnmarshalGeoIP(b []byte) (GeoIP, error) {
	var g GeoIP
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return GeoIP{}, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return GeoIP{}, err
			}
			g.Code = string(raw)
			b = b[m:]
		case fieldNum == 2 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return GeoIP{}, err
			}
			c, err := UnmarshalCIDR(raw)
			if err != nil {
				return GeoIP{}, err
			}
			g.CIDR = append(g.CIDR, c)
			b = b[m:]
		case fieldNum == 3 && wireType == WireVarint:
			v, m, err := ConsumeVarint(b)
			if err != nil {
				return GeoIP{}, err
			}
			g.ReverseMatch = v != 0
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return GeoIP{}, err
			}
			b = b[m:]
		}
	}
	return g, nil
}

func UnmarshalGeoIPList(b []byte) (*GeoIPList, error) {
	list := &GeoIPList{}
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return nil, err
			}
			entry, err := UnmarshalGeoIP(raw)
			if err != nil {
				return nil, err
			}
			list.Entry = append(list.Entry, entry)
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return nil, err
			}
			b = b[m:]
		}
	}
	return list, nil
}

// --- Lossless wire-level entry extraction & re-wrapping (works for both GeoSiteList and GeoIPList) ---

// InspectEntry scans a single GeoSite or GeoIP message without altering bytes,
// returning its code (field 1) and count of payload items (field 2).
func InspectEntry(b []byte) (string, int, error) {
	var code string
	var count int
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return "", 0, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return "", 0, err
			}
			code = string(raw)
			b = b[m:]
		case fieldNum == 2 && wireType == WireBytes:
			_, m, err := ConsumeBytes(b)
			if err != nil {
				return "", 0, err
			}
			count++
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return "", 0, err
			}
			b = b[m:]
		}
	}
	return code, count, nil
}

// ExtractRawEntries extracts all top-level field 1 entries from a GeoSiteList or GeoIPList verbatim.
func ExtractRawEntries(b []byte) ([]RawEntry, error) {
	var entries []RawEntry
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == WireBytes:
			raw, m, err := ConsumeBytes(b)
			if err != nil {
				return nil, err
			}
			code, count, err := InspectEntry(raw)
			if err != nil {
				return nil, fmt.Errorf("inspect entry: %w", err)
			}
			rawCopy := make([]byte, len(raw))
			copy(rawCopy, raw)
			entries = append(entries, RawEntry{
				Code:         code,
				PayloadCount: count,
				Raw:          rawCopy,
			})
			b = b[m:]
		default:
			m, err := SkipField(b, wireType)
			if err != nil {
				return nil, err
			}
			b = b[m:]
		}
	}
	return entries, nil
}

// MarshalRawEntries wraps raw GeoSite/GeoIP entry payloads verbatim into a GeoSiteList/GeoIPList.
func MarshalRawEntries(entries []RawEntry) []byte {
	var total int
	for _, e := range entries {
		total += len(e.Raw) + 8
	}
	b := make([]byte, 0, total)
	for _, e := range entries {
		b = AppendBytesField(b, 1, e.Raw)
	}
	return b
}

// --- Matching helpers ---

func MatchDomain(d Domain, target string) bool {
	switch d.Type {
	case DomainFull:
		return target == d.Value
	case DomainDomain:
		return target == d.Value || strings.HasSuffix(target, "."+d.Value)
	case DomainSubstr:
		return strings.Contains(target, d.Value)
	case DomainRegex:
		re, err := regexp.Compile(d.Value)
		return err == nil && re.MatchString(target)
	default:
		return false
	}
}

func MatchCIDR(c CIDR, ip net.IP) bool {
	if ip == nil {
		return false
	}
	switch len(c.IP) {
	case net.IPv4len:
		v4 := ip.To4()
		if v4 == nil || c.Prefix > 32 {
			return false
		}
		mask := net.CIDRMask(int(c.Prefix), 32)
		ipNet := net.IPNet{IP: net.IP(c.IP).Mask(mask), Mask: mask}
		return ipNet.Contains(v4)
	case net.IPv6len:
		v6 := ip.To16()
		if v6 == nil || c.Prefix > 128 {
			return false
		}
		// Reject IPv4-mapped IPv6 matching against pure IPv6 unless target is actually v6.
		if ip.To4() != nil && net.IP(c.IP).To4() == nil {
			return false
		}
		mask := net.CIDRMask(int(c.Prefix), 128)
		ipNet := net.IPNet{IP: net.IP(c.IP).Mask(mask), Mask: mask}
		return ipNet.Contains(v6)
	default:
		return false
	}
}

// --- Atomic file & SHA256 helpers ---

func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func WriteWithSHA256(path string, data []byte, writeSHA bool) (string, error) {
	if err := WriteAtomic(path, data); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	if writeSHA {
		shaContent := fmt.Sprintf("%s  %s\n", hexSum, filepath.Base(path))
		if err := WriteAtomic(path+".sha256", []byte(shaContent)); err != nil {
			return "", err
		}
	}
	return hexSum, nil
}
