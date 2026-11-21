// tools/personal-dat/main.go
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// Domain mirrors xray.common.geodata.Domain (fields 1 and 2).
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

type domainKey struct {
	typ   DomainType
	value string
}

func main() {
	inDir := flag.String("in", "", "Input directory containing *.txt rule files")
	outFile := flag.String("out", "personal.dat", "Output .dat file path")
	writeSHA := flag.Bool("sha256", true, "Write <out>.sha256 alongside the output .dat file")
	verifyOnly := flag.Bool("verify", false, "Verify an existing .dat file specified by -out")
	testDomain := flag.String("test-domain", "", "Optional domain to test against loaded rules")
	testCode := flag.String("test-code", "", "Optional site code to filter -test-domain (default: all)")
	flag.Parse()

	if *verifyOnly {
		if err := verifyDat(*outFile, *testDomain, *testCode); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] verify failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *inDir == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] -in directory is required unless -verify is set")
		flag.Usage()
		os.Exit(2)
	}

	list, err := buildGeoSiteList(*inDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] build failed: %v\n", err)
		os.Exit(1)
	}

	data := marshalGeoSiteList(list)

	if err := writeAtomic(*outFile, data); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] write output failed: %v\n", err)
		os.Exit(1)
	}

	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])

	if *writeSHA {
		shaContent := fmt.Sprintf("%s  %s\n", hexSum, filepath.Base(*outFile))
		if err := writeAtomic(*outFile+".sha256", []byte(shaContent)); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] write sha256 failed: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("[OK] wrote %s (%d bytes, %d codes, sha256=%s)\n", *outFile, len(data), len(list.Entry), hexSum)
	for _, entry := range list.Entry {
		fmt.Printf("  - ext:%s:%s (%d rules)\n", filepath.Base(*outFile), strings.ToLower(entry.Code), len(entry.Domain))
	}

	if *testDomain != "" {
		if err := verifyDat(*outFile, *testDomain, *testCode); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] post-build verify failed: %v\n", err)
			os.Exit(1)
		}
	}
}

func buildGeoSiteList(inDir string) (*GeoSiteList, error) {
	entries, err := os.ReadDir(inDir)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", inDir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(e.Name()), ".txt") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	if len(files) == 0 {
		return nil, fmt.Errorf("no .txt files found in %q", inDir)
	}

	siteMap := make(map[string]map[domainKey]struct{})
	for _, name := range files {
		stem := strings.TrimSuffix(name, filepath.Ext(name))
		code := strings.ToUpper(strings.TrimSpace(stem))
		if code == "" {
			continue
		}
		fullPath := filepath.Join(inDir, name)
		domains, err := parseRuleFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", fullPath, err)
		}
		if len(domains) == 0 {
			continue
		}
		set, ok := siteMap[code]
		if !ok {
			set = make(map[domainKey]struct{})
			siteMap[code] = set
		}
		for _, d := range domains {
			set[d] = struct{}{}
		}
	}

	codes := make([]string, 0, len(siteMap))
	for c := range siteMap {
		codes = append(codes, c)
	}
	sort.Strings(codes)

	out := &GeoSiteList{
		Entry: make([]GeoSite, 0, len(codes)),
	}
	for _, code := range codes {
		keys := make([]domainKey, 0, len(siteMap[code]))
		for k := range siteMap[code] {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].typ != keys[j].typ {
				return keys[i].typ < keys[j].typ
			}
			return keys[i].value < keys[j].value
		})

		domains := make([]Domain, 0, len(keys))
		for _, k := range keys {
			domains = append(domains, Domain{
				Type:  k.typ,
				Value: k.value,
			})
		}
		out.Entry = append(out.Entry, GeoSite{
			Code:   code,
			Domain: domains,
		})
	}
	return out, nil
}

func parseRuleFile(path string) ([]domainKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result []domainKey
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if lineNo == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.EqualFold(line, "payload:") {
			continue
		}
		if strings.HasPrefix(line, "- ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		}
		line = trimQuotes(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		dk, ok, err := parseRuleLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d (%q): %w", lineNo, line, err)
		}
		if ok {
			result = append(result, dk)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func parseRuleLine(line string) (domainKey, bool, error) {
	// Clash rule format: TYPE,VALUE[,no-resolve]
	if idx := strings.IndexByte(line, ','); idx > 0 {
		prefix := strings.ToUpper(strings.TrimSpace(line[:idx]))
		rest := strings.TrimSpace(line[idx+1:])
		if comma := strings.IndexByte(rest, ','); comma >= 0 {
			rest = strings.TrimSpace(rest[:comma])
		}
		rest = trimQuotes(rest)
		switch prefix {
		case "DOMAIN-SUFFIX":
			return domainKey{typ: DomainDomain, value: strings.ToLower(rest)}, rest != "", nil
		case "DOMAIN":
			return domainKey{typ: DomainFull, value: strings.ToLower(rest)}, rest != "", nil
		case "DOMAIN-KEYWORD":
			return domainKey{typ: DomainSubstr, value: strings.ToLower(rest)}, rest != "", nil
		case "DOMAIN-REGEX":
			if _, err := regexp.Compile(rest); err != nil {
				return domainKey{}, false, fmt.Errorf("invalid regex: %w", err)
			}
			return domainKey{typ: DomainRegex, value: rest}, rest != "", nil
		case "IP-CIDR", "IP-CIDR6", "GEOIP", "PROCESS-NAME", "DST-PORT", "SRC-IP-CIDR":
			fmt.Fprintf(os.Stderr, "[WARN] skipping non-domain rule: %s\n", line)
			return domainKey{}, false, nil
		}
	}

	// Xray native format: domain:x / full:x / keyword:x / regexp:x
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "domain:"):
		val := strings.TrimSpace(lower[len("domain:"):])
		return domainKey{typ: DomainDomain, value: val}, val != "", nil
	case strings.HasPrefix(lower, "full:"):
		val := strings.TrimSpace(lower[len("full:"):])
		return domainKey{typ: DomainFull, value: val}, val != "", nil
	case strings.HasPrefix(lower, "keyword:"):
		val := strings.TrimSpace(lower[len("keyword:"):])
		return domainKey{typ: DomainSubstr, value: val}, val != "", nil
	case strings.HasPrefix(lower, "regexp:"):
		val := strings.TrimSpace(line[len("regexp:"):])
		if _, err := regexp.Compile(val); err != nil {
			return domainKey{}, false, fmt.Errorf("invalid regex: %w", err)
		}
		return domainKey{typ: DomainRegex, value: val}, val != "", nil
	default:
		return domainKey{typ: DomainDomain, value: lower}, lower != "", nil
	}
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return strings.TrimSpace(s[1 : len(s)-1])
		}
	}
	return s
}

func writeAtomic(path string, data []byte) error {
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

func verifyDat(path, testDomain, testCode string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	list, err := unmarshalGeoSiteList(raw)
	if err != nil {
		return fmt.Errorf("unmarshal GeoSiteList: %w", err)
	}
	fmt.Printf("[VERIFY] %s: %d GeoSite entries (%d bytes)\n", path, len(list.Entry), len(raw))
	for _, e := range list.Entry {
		fmt.Printf("  - %s: %d domains\n", e.Code, len(e.Domain))
	}

	if testDomain != "" {
		target := strings.ToLower(strings.TrimSpace(testDomain))
		wantCode := strings.ToUpper(strings.TrimSpace(testCode))
		matched := false
		for _, e := range list.Entry {
			if wantCode != "" && e.Code != wantCode {
				continue
			}
			for _, d := range e.Domain {
				if matchDomain(d, target) {
					fmt.Printf("[MATCH] %s matched %s (%v: %s)\n", testDomain, e.Code, d.Type, d.Value)
					matched = true
				}
			}
		}
		if !matched {
			return fmt.Errorf("domain %q did not match any rule", testDomain)
		}
	}
	return nil
}

func matchDomain(d Domain, target string) bool {
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

// --- Zero-dependency Proto3 wire encoder/decoder for GeoSiteList ---

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

func appendTag(b []byte, fieldNum uint64, wireType uint64) []byte {
	return binary.AppendUvarint(b, (fieldNum<<3)|wireType)
}

func appendBytesField(b []byte, fieldNum uint64, val []byte) []byte {
	b = appendTag(b, fieldNum, wireBytes)
	b = binary.AppendUvarint(b, uint64(len(val)))
	return append(b, val...)
}

func marshalDomain(d Domain) []byte {
	var b []byte
	if d.Type != 0 {
		b = appendTag(b, 1, wireVarint)
		b = binary.AppendUvarint(b, uint64(d.Type))
	}
	if d.Value != "" {
		b = appendBytesField(b, 2, []byte(d.Value))
	}
	return b
}

func marshalGeoSite(s GeoSite) []byte {
	var b []byte
	if s.Code != "" {
		b = appendBytesField(b, 1, []byte(s.Code))
	}
	for _, d := range s.Domain {
		b = appendBytesField(b, 2, marshalDomain(d))
	}
	return b
}

func marshalGeoSiteList(list *GeoSiteList) []byte {
	var b []byte
	if list == nil {
		return b
	}
	for _, e := range list.Entry {
		b = appendBytesField(b, 1, marshalGeoSite(e))
	}
	return b
}

func consumeVarint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n == 0 {
		return 0, 0, errors.New("truncated varint")
	}
	if n < 0 {
		return 0, 0, errors.New("varint overflow")
	}
	return v, n, nil
}

func consumeBytes(b []byte) ([]byte, int, error) {
	l, n, err := consumeVarint(b)
	if err != nil {
		return nil, 0, err
	}
	if l > uint64(len(b)-n) {
		return nil, 0, errors.New("truncated length-delimited field")
	}
	end := n + int(l)
	return b[n:end], end, nil
}

func skipField(b []byte, wireType uint64) (int, error) {
	switch wireType {
	case wireVarint:
		_, n, err := consumeVarint(b)
		return n, err
	case wireFixed64:
		if len(b) < 8 {
			return 0, errors.New("truncated fixed64")
		}
		return 8, nil
	case wireBytes:
		_, n, err := consumeBytes(b)
		return n, err
	case wireFixed32:
		if len(b) < 4 {
			return 0, errors.New("truncated fixed32")
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported wire type %d", wireType)
	}
}

func unmarshalDomain(b []byte) (Domain, error) {
	var d Domain
	for len(b) > 0 {
		tag, n, err := consumeVarint(b)
		if err != nil {
			return Domain{}, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == wireVarint:
			v, m, err := consumeVarint(b)
			if err != nil {
				return Domain{}, err
			}
			d.Type = DomainType(v)
			b = b[m:]
		case fieldNum == 2 && wireType == wireBytes:
			raw, m, err := consumeBytes(b)
			if err != nil {
				return Domain{}, err
			}
			d.Value = string(raw)
			b = b[m:]
		default:
			m, err := skipField(b, wireType)
			if err != nil {
				return Domain{}, err
			}
			b = b[m:]
		}
	}
	return d, nil
}

func unmarshalGeoSite(b []byte) (GeoSite, error) {
	var s GeoSite
	for len(b) > 0 {
		tag, n, err := consumeVarint(b)
		if err != nil {
			return GeoSite{}, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == wireBytes:
			raw, m, err := consumeBytes(b)
			if err != nil {
				return GeoSite{}, err
			}
			s.Code = string(raw)
			b = b[m:]
		case fieldNum == 2 && wireType == wireBytes:
			raw, m, err := consumeBytes(b)
			if err != nil {
				return GeoSite{}, err
			}
			d, err := unmarshalDomain(raw)
			if err != nil {
				return GeoSite{}, err
			}
			s.Domain = append(s.Domain, d)
			b = b[m:]
		default:
			m, err := skipField(b, wireType)
			if err != nil {
				return GeoSite{}, err
			}
			b = b[m:]
		}
	}
	return s, nil
}

func unmarshalGeoSiteList(b []byte) (*GeoSiteList, error) {
	list := &GeoSiteList{}
	for len(b) > 0 {
		tag, n, err := consumeVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch {
		case fieldNum == 1 && wireType == wireBytes:
			raw, m, err := consumeBytes(b)
			if err != nil {
				return nil, err
			}
			site, err := unmarshalGeoSite(raw)
			if err != nil {
				return nil, err
			}
			list.Entry = append(list.Entry, site)
			b = b[m:]
		default:
			m, err := skipField(b, wireType)
			if err != nil {
				return nil, err
			}
			b = b[m:]
		}
	}
	return list, nil
}
