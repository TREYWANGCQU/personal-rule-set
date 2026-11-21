// tools/personal-dat/main.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/TREYWANGCQU/personal-rule-set/tools/internal/geowire"
)

type DomainType = geowire.DomainType

const (
	DomainSubstr = geowire.DomainSubstr
	DomainRegex  = geowire.DomainRegex
	DomainDomain = geowire.DomainDomain
	DomainFull   = geowire.DomainFull
)

type Domain = geowire.Domain
type GeoSite = geowire.GeoSite
type GeoSiteList = geowire.GeoSiteList

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

	hexSum, err := geowire.WriteWithSHA256(*outFile, data, *writeSHA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] write output failed: %v\n", err)
		os.Exit(1)
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

func marshalGeoSiteList(list *GeoSiteList) []byte {
	return geowire.MarshalGeoSiteList(list)
}

func unmarshalGeoSiteList(b []byte) (*GeoSiteList, error) {
	return geowire.UnmarshalGeoSiteList(b)
}

func matchDomain(d Domain, target string) bool {
	return geowire.MatchDomain(d, target)
}
