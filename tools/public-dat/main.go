// tools/public-dat/main.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TREYWANGCQU/personal-rule-set/tools/internal/geowire"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "slice":
		err = runSlice(os.Args[2:])
	case "anti-ad":
		err = runAntiAD(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %s failed: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: public-dat <slice|anti-ad|verify> [flags]")
}

func parseCodeList(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	var out []string
	for _, p := range parts {
		c := strings.ToUpper(strings.TrimSpace(p))
		if c == "" {
			continue
		}
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// --- Subcommand: slice ---

func runSlice(args []string) error {
	fs := flag.NewFlagSet("slice", flag.ContinueOnError)
	kind := fs.String("kind", "", "Rule file kind: geosite or geoip")
	inPath := fs.String("in", "", "Input upstream .dat file path")
	outPath := fs.String("out", "", "Output slimmed .dat file path")
	codesFlag := fs.String("codes", "CN,PRIVATE", "Comma-separated list of codes to keep")
	writeSHA := fs.Bool("sha256", true, "Write <out>.sha256 alongside output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *kind != "geosite" && *kind != "geoip" {
		return fmt.Errorf("-kind must be 'geosite' or 'geoip', got %q", *kind)
	}
	if *inPath == "" || *outPath == "" {
		return fmt.Errorf("-in and -out are required")
	}

	wantCodes := parseCodeList(*codesFlag)
	if len(wantCodes) == 0 {
		return fmt.Errorf("-codes must contain at least one code")
	}

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		return fmt.Errorf("read %q: %w", *inPath, err)
	}

	sliced, kept, err := sliceDatBytes(raw, wantCodes)
	if err != nil {
		return err
	}

	hexSum, err := geowire.WriteWithSHA256(*outPath, sliced, *writeSHA)
	if err != nil {
		return fmt.Errorf("write %q: %w", *outPath, err)
	}

	fmt.Printf("[OK] sliced %s (%s): %d -> %d bytes (%d codes, sha256=%s)\n",
		*outPath, *kind, len(raw), len(sliced), len(kept), hexSum)
	for _, e := range kept {
		fmt.Printf("  - %s:%s (%d items, %d raw bytes)\n", *kind, strings.ToLower(e.Code), e.PayloadCount, len(e.Raw))
	}
	return nil
}

func sliceDatBytes(raw []byte, wantCodes []string) ([]byte, []geowire.RawEntry, error) {
	entries, err := geowire.ExtractRawEntries(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("extract raw entries: %w", err)
	}

	wantSet := make(map[string]struct{}, len(wantCodes))
	for _, c := range wantCodes {
		wantSet[c] = struct{}{}
	}

	found := make(map[string]geowire.RawEntry, len(wantCodes))
	for _, e := range entries {
		upper := strings.ToUpper(strings.TrimSpace(e.Code))
		if _, ok := wantSet[upper]; !ok {
			continue
		}
		if _, dup := found[upper]; dup {
			return nil, nil, fmt.Errorf("duplicate entry code %q in upstream dat", upper)
		}
		if e.PayloadCount == 0 {
			return nil, nil, fmt.Errorf("entry code %q has 0 payload items", upper)
		}
		e.Code = upper
		found[upper] = e
	}

	var missing []string
	kept := make([]geowire.RawEntry, 0, len(wantCodes))
	for _, c := range wantCodes {
		e, ok := found[c]
		if !ok {
			missing = append(missing, c)
			continue
		}
		kept = append(kept, e)
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("missing required codes in upstream dat: %s", strings.Join(missing, ", "))
	}

	return geowire.MarshalRawEntries(kept), kept, nil
}

// --- Subcommand: anti-ad ---

func runAntiAD(args []string) error {
	fs := flag.NewFlagSet("anti-ad", flag.ContinueOnError)
	inPath := fs.String("in", "", "Input anti-ad-domains.txt path")
	outPath := fs.String("out", "anti-ad.dat", "Output anti-ad.dat path")
	codeFlag := fs.String("code", "ANTI-AD", "GeoSite code name")
	minRules := fs.Int("min-rules", 10000, "Minimum valid domain count required")
	maxInvalidRatio := fs.Float64("max-invalid-ratio", 0.05, "Maximum allowed ratio of invalid lines")
	writeSHA := fs.Bool("sha256", true, "Write <out>.sha256 alongside output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *inPath == "" {
		return fmt.Errorf("-in is required")
	}
	code := strings.ToUpper(strings.TrimSpace(*codeFlag))
	if code == "" {
		return fmt.Errorf("-code must not be empty")
	}

	list, stats, err := buildAntiADGeoSite(*inPath, code, *minRules, *maxInvalidRatio)
	if err != nil {
		return err
	}

	data := geowire.MarshalGeoSiteList(list)
	hexSum, err := geowire.WriteWithSHA256(*outPath, data, *writeSHA)
	if err != nil {
		return fmt.Errorf("write %q: %w", *outPath, err)
	}

	fmt.Printf("[OK] wrote %s (%d bytes, code=%s, %d unique domains, %d invalid skipped, sha256=%s)\n",
		*outPath, len(data), code, stats.UniqueDomains, stats.InvalidLines, hexSum)
	fmt.Printf("  - ext:%s:%s (%d rules)\n", filepath.Base(*outPath), strings.ToLower(code), stats.UniqueDomains)
	return nil
}

type antiADStats struct {
	NonCommentLines int
	InvalidLines    int
	UniqueDomains   int
}

func buildAntiADGeoSite(path, code string, minRules int, maxInvalidRatio float64) (*geowire.GeoSiteList, antiADStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, antiADStats{}, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	domainSet := make(map[string]struct{}, 65536)
	var stats antiADStats

	scanner := bufio.NewScanner(f)
	// Allow long lines safely.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if lineNo == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "!") {
			continue
		}
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		stats.NonCommentLines++
		host := strings.ToLower(strings.TrimSuffix(line, "."))
		if !isValidDomain(host) {
			stats.InvalidLines++
			if stats.InvalidLines <= 10 {
				fmt.Fprintf(os.Stderr, "[WARN] skipping invalid anti-ad domain at line %d: %q\n", lineNo, line)
			}
			continue
		}
		domainSet[host] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("scan %q: %w", path, err)
	}

	if stats.NonCommentLines == 0 {
		return nil, stats, fmt.Errorf("no non-comment lines found in %q", path)
	}

	invalidRatio := float64(stats.InvalidLines) / float64(stats.NonCommentLines)
	if invalidRatio > maxInvalidRatio {
		return nil, stats, fmt.Errorf("invalid line ratio %.2f%% (%d/%d) exceeds threshold %.2f%%",
			invalidRatio*100, stats.InvalidLines, stats.NonCommentLines, maxInvalidRatio*100)
	}

	hosts := make([]string, 0, len(domainSet))
	for h := range domainSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	stats.UniqueDomains = len(hosts)

	if stats.UniqueDomains < minRules {
		return nil, stats, fmt.Errorf("valid domain count %d is below minimum threshold %d", stats.UniqueDomains, minRules)
	}

	domains := make([]geowire.Domain, 0, len(hosts))
	for _, h := range hosts {
		domains = append(domains, geowire.Domain{
			Type:  geowire.DomainDomain,
			Value: h,
		})
	}

	return &geowire.GeoSiteList{
		Entry: []geowire.GeoSite{
			{
				Code:   strings.ToUpper(code),
				Domain: domains,
			},
		},
	}, stats, nil
}

func isValidDomain(s string) bool {
	if len(s) < 3 || len(s) > 253 {
		return false
	}
	if !strings.ContainsRune(s, '.') {
		return false
	}
	if s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// --- Subcommand: verify ---

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	kind := fs.String("kind", "", "Rule file kind: geosite or geoip")
	inPath := fs.String("in", "", "Input .dat file path")
	requireCodes := fs.String("require-codes", "", "Optional comma-separated required codes")
	minRules := fs.Int("min-rules", 1, "Minimum total rule count across all entries")
	testDomain := fs.String("test-domain", "", "Optional domain expected to match (geosite)")
	rejectDomain := fs.String("reject-domain", "", "Optional domain expected NOT to match (geosite)")
	testIP := fs.String("test-ip", "", "Optional IP expected to match (geoip)")
	rejectIP := fs.String("reject-ip", "", "Optional IP expected NOT to match (geoip)")
	testCode := fs.String("test-code", "", "Optional code filter for -test-domain / -test-ip")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *kind != "geosite" && *kind != "geoip" {
		return fmt.Errorf("-kind must be 'geosite' or 'geoip', got %q", *kind)
	}
	if *inPath == "" {
		return fmt.Errorf("-in is required")
	}

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		return err
	}
	reqCodes := parseCodeList(*requireCodes)
	wantCode := strings.ToUpper(strings.TrimSpace(*testCode))

	switch *kind {
	case "geosite":
		return verifyGeoSite(*inPath, raw, reqCodes, *minRules, *testDomain, *rejectDomain, wantCode)
	case "geoip":
		return verifyGeoIP(*inPath, raw, reqCodes, *minRules, *testIP, *rejectIP, wantCode)
	default:
		return fmt.Errorf("unsupported kind %q", *kind)
	}
}

func verifyGeoSite(path string, raw []byte, reqCodes []string, minRules int, testDomain, rejectDomain, wantCode string) error {
	list, err := geowire.UnmarshalGeoSiteList(raw)
	if err != nil {
		return fmt.Errorf("unmarshal GeoSiteList: %w", err)
	}

	counts := make(map[string]int, len(list.Entry))
	total := 0
	fmt.Printf("[VERIFY] %s (geosite): %d entries (%d bytes)\n", path, len(list.Entry), len(raw))
	for _, e := range list.Entry {
		upper := strings.ToUpper(e.Code)
		counts[upper] = len(e.Domain)
		total += len(e.Domain)
		fmt.Printf("  - %s: %d domains\n", upper, len(e.Domain))
	}

	for _, c := range reqCodes {
		if counts[c] == 0 {
			return fmt.Errorf("required code %q missing or empty in %s", c, path)
		}
	}
	if total < minRules {
		return fmt.Errorf("total domain count %d < min-rules %d", total, minRules)
	}

	if testDomain != "" {
		target := strings.ToLower(strings.TrimSpace(testDomain))
		matched := false
		for _, e := range list.Entry {
			if wantCode != "" && strings.ToUpper(e.Code) != wantCode {
				continue
			}
			for _, d := range e.Domain {
				if geowire.MatchDomain(d, target) {
					fmt.Printf("[MATCH] %s matched %s (%v: %s)\n", testDomain, e.Code, d.Type, d.Value)
					matched = true
					break
				}
			}
		}
		if !matched {
			return fmt.Errorf("domain %q did not match any rule", testDomain)
		}
	}

	if rejectDomain != "" {
		target := strings.ToLower(strings.TrimSpace(rejectDomain))
		for _, e := range list.Entry {
			if wantCode != "" && strings.ToUpper(e.Code) != wantCode {
				continue
			}
			for _, d := range e.Domain {
				if geowire.MatchDomain(d, target) {
					return fmt.Errorf("reject-domain %q unexpectedly matched %s (%v: %s)", rejectDomain, e.Code, d.Type, d.Value)
				}
			}
		}
		fmt.Printf("[REJECT-OK] %s did not match\n", rejectDomain)
	}

	return nil
}

func verifyGeoIP(path string, raw []byte, reqCodes []string, minRules int, testIP, rejectIP, wantCode string) error {
	list, err := geowire.UnmarshalGeoIPList(raw)
	if err != nil {
		return fmt.Errorf("unmarshal GeoIPList: %w", err)
	}

	counts := make(map[string]int, len(list.Entry))
	total := 0
	fmt.Printf("[VERIFY] %s (geoip): %d entries (%d bytes)\n", path, len(list.Entry), len(raw))
	for _, e := range list.Entry {
		upper := strings.ToUpper(e.Code)
		counts[upper] = len(e.CIDR)
		total += len(e.CIDR)
		fmt.Printf("  - %s: %d CIDRs\n", upper, len(e.CIDR))
	}

	for _, c := range reqCodes {
		if counts[c] == 0 {
			return fmt.Errorf("required code %q missing or empty in %s", c, path)
		}
	}
	if total < minRules {
		return fmt.Errorf("total CIDR count %d < min-rules %d", total, minRules)
	}

	if testIP != "" {
		ip := net.ParseIP(strings.TrimSpace(testIP))
		if ip == nil {
			return fmt.Errorf("invalid -test-ip %q", testIP)
		}
		matched := false
		for _, e := range list.Entry {
			if wantCode != "" && strings.ToUpper(e.Code) != wantCode {
				continue
			}
			for _, c := range e.CIDR {
				if geowire.MatchCIDR(c, ip) {
					fmt.Printf("[MATCH] %s matched %s (%s/%d)\n", testIP, e.Code, net.IP(c.IP).String(), c.Prefix)
					matched = true
					break
				}
			}
		}
		if !matched {
			return fmt.Errorf("IP %q did not match any rule", testIP)
		}
	}

	if rejectIP != "" {
		ip := net.ParseIP(strings.TrimSpace(rejectIP))
		if ip == nil {
			return fmt.Errorf("invalid -reject-ip %q", rejectIP)
		}
		for _, e := range list.Entry {
			if wantCode != "" && strings.ToUpper(e.Code) != wantCode {
				continue
			}
			for _, c := range e.CIDR {
				if geowire.MatchCIDR(c, ip) {
					return fmt.Errorf("reject-ip %q unexpectedly matched %s (%s/%d)", rejectIP, e.Code, net.IP(c.IP).String(), c.Prefix)
				}
			}
		}
		fmt.Printf("[REJECT-OK] %s did not match\n", rejectIP)
	}

	return nil
}
