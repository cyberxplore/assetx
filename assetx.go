package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	trimChars = ".,;:!?\"'()[]{}<>"
	tldURL    = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
)

// knownTLDs holds the IANA TLDs in lowercase.
var knownTLDs = make(map[string]struct{})

// Global regexes.
var (
	validDomainRegex = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)$`)
	cidrRegex        = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
	urlSubRegex      = regexp.MustCompile(`https?://[^\s"']+`)
	domainSubRegex   = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b`)
	quotedRegex      = regexp.MustCompile(`["']([^"']+\.[^"']+)["']`)
)

// helpMsg is the help message with examples.
var helpMsg = `
AssetX - Extract, Organize, Scan!

Usage:
  assetx -f <input_file> [options]

Description:
  AssetX extracts and categorizes unique IPv4 addresses, CIDR subnets,
  HTTP/HTTPS URLs, domains, and subdomains from an input file.

  Scan Modes:
    normal  (default) - tokenizes each line by whitespace.
    deep    - scans only within quoted literals.

  Domain Check:
    By default, domains/subdomains are validated using the publicsuffix
    library and the official IANA TLD list. Use -k false to disable this check.
    Note: "localhost" is always accepted.

Options:
  -f, --file <file>    Input file to scan.
  -s, --split <num>    Maximum items per output file (default: 1000).
  -m, --mode <mode>    Scan mode: "normal" (default) or "deep".
  -k, --check <bool>   Check domains against IANA TLD list (default: true).
  -h, --help           Show this help message and exit.

Example:
  assetx -s 500 -m normal -k false -f bundle.js
`

func init() {
	flag.Usage = func() {
		fmt.Println(helpMsg)
	}
}

// loadKnownTLDs fetches the official IANA TLD list and loads it into knownTLDs.
// If the fetch fails, it falls back to a minimal default list.
func loadKnownTLDs() {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(tldURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching TLD list: %v. Using default list.\n", err)
		for _, tld := range []string{"com", "net", "org", "edu", "gov", "mil"} {
			knownTLDs[strings.ToLower(tld)] = struct{}{}
		}
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine { // skip header
			firstLine = false
			continue
		}
		tld := strings.ToLower(strings.TrimSpace(line))
		if tld != "" {
			knownTLDs[tld] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading TLD list: %v\n", err)
	}
}

// incIP returns a new net.IP incremented by 1.
func incIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	for j := len(newIP) - 1; j >= 0; j-- {
		newIP[j]++
		if newIP[j] != 0 {
			break
		}
	}
	return newIP
}

// CategoryOutput and JSONOutput define our output structure.
type CategoryOutput struct {
	Count      int      `json:"count"`
	IsSplitted bool     `json:"isSplitted"`
	Filenames  []string `json:"filenames"`
	RootFile   string   `json:"rootFile"`
}
type JSONOutput struct {
	Ips        CategoryOutput `json:"ips"`
	Urls       CategoryOutput `json:"urls"`
	Domains    CategoryOutput `json:"domains"`
	Subdomains CategoryOutput `json:"subdomains"`
}

// WorkerResult holds per-worker maps.
type WorkerResult struct {
	ipsMap        map[string]struct{}
	urlsMap       map[string]struct{}
	domainsMap    map[string]struct{}
	subdomainsMap map[string]struct{}
}

// globalEffectiveCache caches EffectiveTLDPlusOne results.
var globalEffectiveCache sync.Map

// isLikelyJSReference returns true if s contains common JS property/method patterns.
func isLikelyJSReference(s string) bool {
	sLower := strings.ToLower(s)
	blacklist := []string{"this.", "prototype.", "array.", "object.", "relativeparent.", "state."}
	for _, b := range blacklist {
		if strings.Contains(sLower, b) {
			return true
		}
	}
	return false
}

// Custom boolean flag type to allow "-k false" or "-k=false"
type boolFlag bool

func (b *boolFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*b = boolFlag(v)
	return nil
}
func (b *boolFlag) String() string {
	if *b {
		return "true"
	}
	return "false"
}

var _ flag.Value = (*boolFlag)(nil)

// Global flag variable for domain check.
var checkTLDFlag boolFlag = true

// processDomain validates a candidate domain using publicsuffix and knownTLDs.
// It ignores tokens that look like JS property chains. "localhost" is always accepted.
func processDomain(domain string, res *WorkerResult) {
	if strings.ToLower(domain) == "localhost" {
		res.domainsMap[domain] = struct{}{}
		return
	}
	if isLikelyJSReference(domain) {
		return
	}
	labels := strings.Split(domain, ".")
	if len(labels) >= 3 && len(labels[0]) == 1 {
		return
	}
	if !validDomainRegex.MatchString(domain) {
		return
	}
	effDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return
	}
	suffix, _ := publicsuffix.PublicSuffix(effDomain)
	if suffix == "" {
		return
	}
	if bool(checkTLDFlag) {
		if _, ok := knownTLDs[strings.ToLower(suffix)]; !ok {
			return
		}
	}
	if domain == effDomain {
		res.domainsMap[domain] = struct{}{}
	} else {
		res.subdomainsMap[domain] = struct{}{}
		res.domainsMap[effDomain] = struct{}{}
	}
}

// processCandidate handles a URL candidate string: trims, parses, records, and processes its host.
func processCandidate(urlCandidate string, res *WorkerResult) {
	urlCandidate = strings.Trim(urlCandidate, " \t\n\r"+trimChars)
	parsed, err := url.Parse(urlCandidate)
	if err != nil || parsed.Host == "" {
		return
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return
	}
	res.urlsMap[urlCandidate] = struct{}{}
	host := parsed.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if net.ParseIP(host) != nil {
		return
	}
	processDomain(host, res)
}

// processLine tokenizes candidate string by whitespace and processes each token.
func processLine(candidate string, res *WorkerResult) {
	tokens := strings.Fields(candidate)
	for _, token := range tokens {
		token = strings.Trim(token, trimChars)
		if token == "" {
			continue
		}
		tokenLower := strings.ToLower(token)
		if strings.Contains(tokenLower, "/") {
			if cidrRegex.MatchString(tokenLower) {
				if ip, ipnet, err := net.ParseCIDR(tokenLower); err == nil && ip.To4() != nil {
					for curIP := ip.Mask(ipnet.Mask); ipnet.Contains(curIP); curIP = incIP(curIP) {
						res.ipsMap[curIP.String()] = struct{}{}
					}
				}
				continue
			}
			if strings.Contains(tokenLower, "://") ||
				(strings.Contains(tokenLower, "/") && validDomainRegex.MatchString(strings.SplitN(tokenLower, "/", 2)[0])) {
				urlStr := token
				if !strings.Contains(urlStr, "://") {
					urlStr = "http://" + urlStr
				}
				parsed, err := url.Parse(urlStr)
				if err != nil || parsed.Host == "" {
					matches := urlSubRegex.FindAllString(token, -1)
					for _, m := range matches {
						processCandidate(m, res)
					}
					continue
				}
				processCandidate(urlStr, res)
				continue
			}
		}
		if ip := net.ParseIP(tokenLower); ip != nil && ip.To4() != nil {
			res.ipsMap[tokenLower] = struct{}{}
			continue
		}
		if validDomainRegex.MatchString(tokenLower) {
			processDomain(tokenLower, res)
			continue
		}
		matches := domainSubRegex.FindAllString(token, -1)
		for _, d := range matches {
			processDomain(strings.ToLower(d), res)
		}
	}
}

// processLineDeep extracts tokens only from within quoted literals.
func processLineDeep(line string, res *WorkerResult) {
	quotedMatches := quotedRegex.FindAllStringSubmatch(line, -1)
	for _, m := range quotedMatches {
		if len(m) >= 2 && !isLikelyJSReference(m[1]) {
			processLine(m[1], res)
		}
	}
}

// writeKeysToFile writes sorted keys to a file.
func writeKeysToFile(filename string, keys []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	writer := bufio.NewWriter(f)
	for _, key := range keys {
		if _, err := writer.WriteString(key + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// writeSetWithSplit writes a "root" file and splits output if needed.
func writeSetWithSplit(filePrefix, baseFolder, categoryName string, set map[string]struct{}, threshold int) CategoryOutput {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	count := len(keys)
	output := CategoryOutput{
		Count:      count,
		IsSplitted: false,
		Filenames:  []string{},
		RootFile:   "",
	}
	if count == 0 {
		return output
	}
	rootFilename := filepath.Join(baseFolder, fmt.Sprintf("%s_%s.txt", filePrefix, categoryName))
	if err := writeKeysToFile(rootFilename, keys); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file '%s': %v\n", rootFilename, err)
	}
	output.RootFile = rootFilename
	if count <= threshold {
		output.Filenames = append(output.Filenames, rootFilename)
		return output
	}
	output.IsSplitted = true
	subfolder := filepath.Join(baseFolder, categoryName)
	if err := os.MkdirAll(subfolder, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating subfolder '%s': %v\n", subfolder, err)
		output.Filenames = append(output.Filenames, rootFilename)
		return output
	}
	totalFiles := (count + threshold - 1) / threshold
	var splitFiles []string
	for i := 0; i < totalFiles; i++ {
		start := i * threshold
		end := start + threshold
		if end > count {
			end = count
		}
		filename := filepath.Join(subfolder, fmt.Sprintf("%s_%s_%d.txt", filePrefix, categoryName, i+1))
		if err := writeKeysToFile(filename, keys[start:end]); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file '%s': %v\n", filename, err)
			continue
		}
		splitFiles = append(splitFiles, filename)
	}
	output.Filenames = splitFiles
	return output
}

func main() {
	splitPtr := flag.Int("split", 1000, "Max items per output file")
	flag.IntVar(splitPtr, "s", 1000, "Max items per output file (short)")
	modePtr := flag.String("mode", "normal", `Scan mode: "normal" (default) or "deep"`)
	flag.StringVar(modePtr, "m", "normal", `Scan mode: "normal" or "deep" (short)`)
	checkPtr := new(boolFlag)
	*checkPtr = true
	flag.Var(checkPtr, "check", "Check domains against IANA TLD list")
	flag.Var(checkPtr, "k", "Check domains against IANA TLD list (short)")
	filePtr := flag.String("file", "", "Input file to scan")
	flag.StringVar(filePtr, "f", "", "Input file (short)")
	helpPtr := flag.Bool("help", false, "Show help message")
	flag.BoolVar(helpPtr, "h", false, "Show help message (short)")
	flag.Parse()

	if *helpPtr {
		flag.Usage()
		os.Exit(0)
	}
	if *filePtr == "" {
		flag.Usage()
		os.Exit(1)
	}
	checkTLDFlag = *checkPtr
	inputFile := *filePtr

	loadKnownTLDs()

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file '%s': %v\n", inputFile, err)
		os.Exit(1)
	}
	defer file.Close()

	base := inputFile
	if ext := filepath.Ext(inputFile); ext != "" {
		base = strings.TrimSuffix(inputFile, ext)
	}
	if err = os.MkdirAll(base, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating folder '%s': %v\n", base, err)
		os.Exit(1)
	}
	filePrefix := filepath.Base(base)

	numWorkers := runtime.NumCPU()
	linesChan := make(chan string, 1024)
	resultsChan := make(chan WorkerResult, numWorkers)
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			res := WorkerResult{
				ipsMap:        make(map[string]struct{}, 256),
				urlsMap:       make(map[string]struct{}, 256),
				domainsMap:    make(map[string]struct{}, 256),
				subdomainsMap: make(map[string]struct{}, 256),
			}
			for line := range linesChan {
				if *modePtr == "deep" {
					processLineDeep(line, &res)
				} else {
					processLine(line, &res)
				}
			}
			resultsChan <- res
			wg.Done()
		}()
	}
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			linesChan <- line
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
	}
	close(linesChan)
	wg.Wait()
	close(resultsChan)

	globalIps := make(map[string]struct{})
	globalUrls := make(map[string]struct{})
	globalDomains := make(map[string]struct{})
	globalSubdomains := make(map[string]struct{})
	for res := range resultsChan {
		for k := range res.ipsMap {
			globalIps[k] = struct{}{}
		}
		for k := range res.urlsMap {
			globalUrls[k] = struct{}{}
		}
		for k := range res.domainsMap {
			globalDomains[k] = struct{}{}
		}
		for k := range res.subdomainsMap {
			globalSubdomains[k] = struct{}{}
		}
	}

	ipsOutput := writeSetWithSplit(filePrefix, base, "ips", globalIps, *splitPtr)
	urlsOutput := writeSetWithSplit(filePrefix, base, "urls", globalUrls, *splitPtr)
	domainsOutput := writeSetWithSplit(filePrefix, base, "domains", globalDomains, *splitPtr)
	subdomainsOutput := writeSetWithSplit(filePrefix, base, "subdomains", globalSubdomains, *splitPtr)
	jsonOut := JSONOutput{
		Ips:        ipsOutput,
		Urls:       urlsOutput,
		Domains:    domainsOutput,
		Subdomains: subdomainsOutput,
	}
	outBytes, err := json.MarshalIndent(jsonOut, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(outBytes))
}
