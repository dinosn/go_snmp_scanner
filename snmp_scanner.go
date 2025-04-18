package main

import (
	"bufio"
	"flag"
	"fmt"
	"io" // Import io for io.Discard
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	// No external CIDR package needed
)

var (
	// Flag pointers (declared globally for access in functions)
	communityFile  = flag.String("c", "", "File containing community strings (one per line)")
	targetFile     = flag.String("i", "", "File containing target hosts/CIDRs (one per line)")
	outputFile     = flag.String("o", "", "Output log file for results")
	port           = flag.Int("p", 161, "Destination SNMP port")
	timeoutSeconds = flag.Float64("w", 0.5, "Response timeout in seconds")
	retries        = flag.Int("r", 0, "Number of SNMP retries")
	concurrency    = flag.Int("C", 1000, "Max concurrent scan tasks")
	shortMode      = flag.Bool("s", false, "Short mode, print only IP addresses that respond")
	quietMode      = flag.Bool("q", false, "Quiet mode, suppress informational messages on console")
	debugMode      = flag.Bool("d", false, "Enable debug logging (prints errors/timeouts)")

	// Global variables
	communities = []string{"public", "private"} // Default communities
	targets     = []string{}
	outputFH    *os.File
	wg          sync.WaitGroup
	resultsChan chan string      // Channel to send successful results for printing/logging
	targetChan  chan scanTarget // Channel to feed targets to workers
	sysDescrOID = ".1.3.6.1.2.1.1.1.0" // sysDescr.0 OID
)

type scanTarget struct {
	IP        string
	Community string
}

// Configure logger AFTER flags are parsed
func configureLogger() {
	log.SetFlags(log.Ltime) // Only show time
	if *quietMode {
		log.SetOutput(io.Discard) // Discard informational logs if quiet
	} else {
		log.SetOutput(os.Stderr) // Print informational logs to stderr by default
	}
	// Note: Errors printed directly (like file not found) might still appear on stderr
}

func setupOutputFile(filename string) {
	var err error
	outputFH, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Use fmt.Fprintf for critical errors before logger might be fully set up
		fmt.Fprintf(os.Stderr, "[!] Error opening output file %s: %v\n", filename, err)
		outputFH = nil
	} else {
		log.Printf("[i] Logging results to: %s\n", filename) // Log info goes to stderr if not quiet
	}
}

func logResult(message string) {
	// Print result to stdout only if NOT quiet
	if !*quietMode {
		fmt.Println(message)
	}
	// Always write to file if open
	if outputFH != nil {
		if _, err := fmt.Fprintln(outputFH, message); err != nil {
			log.Printf("[!] Error writing to output file: %v\n", err) // Log actual error
		}
	}
}

func loadCommunities(filename string) []string {
	// (Function unchanged)
	file, err := os.Open(filename)
	if err != nil { log.Printf("[!] Error opening community file %s: %v. Using defaults.\n", filename, err); return communities }
	defer file.Close()
	loadedCommunities := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != "" && !strings.HasPrefix(line, "#") { loadedCommunities = append(loadedCommunities, line) } }
	if err := scanner.Err(); err != nil { log.Printf("[!] Error reading community file %s: %v. Using defaults.\n", filename, err); return communities }
	if len(loadedCommunities) > 0 { log.Printf("[i] Loaded %d communities from %s\n", len(loadedCommunities), filename); return loadedCommunities }
	log.Printf("[!] Warning: Community file %s was empty. Using defaults.\n", filename); return communities
}

func incIP(ip net.IP) {
	// (Function unchanged)
	for j := len(ip) - 1; j >= 0; j-- { ip[j]++; if ip[j] > 0 { break } }
}

func expandTargets(targetSpecs []string, filename string) []string {
	// (Function unchanged)
	targetSet := make(map[string]struct{})
	if filename != "" {
		log.Printf("[i] Reading targets from file: %s\n", filename)
		file, err := os.Open(filename)
		if err != nil { log.Printf("[!] Error opening target file %s: %v\n", filename, err) } else {
			scanner := bufio.NewScanner(file); for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != "" && !strings.HasPrefix(line, "#") { targetSpecs = append(targetSpecs, line) } }; file.Close()
			if err := scanner.Err(); err != nil { log.Printf("[!] Error reading target file %s: %v\n", filename, err) }
		}
	}
	for _, spec := range targetSpecs {
		_, ipNet, err := net.ParseCIDR(spec)
		if err == nil {
			log.Printf("[i] Expanding CIDR: %s\n", spec); count := 0; limit := 10 * 65536
			currentIP := ipNet.IP.To4(); if currentIP == nil { log.Printf("[!] Warning: Skipping non-IPv4 CIDR %s\n", spec); continue }
			mask := ipNet.Mask; networkIP := make(net.IP, len(currentIP)); copy(networkIP, currentIP); networkIP = networkIP.Mask(mask)
			broadcastIP := make(net.IP, len(currentIP)); for i := range currentIP { broadcastIP[i] = currentIP[i] | ^mask[i] }
			currentIP = make(net.IP, len(networkIP)); copy(currentIP, networkIP); incIP(currentIP)
			for ; ipNet.Contains(currentIP); incIP(currentIP) {
				ipStr := currentIP.String()
				if ipStr == broadcastIP.String() { ones, _ := ipNet.Mask.Size(); if ones < 31 { break } }
				targetSet[ipStr] = struct{}{}; count++
				if count >= limit { log.Printf("[!] Warning: Stopping expansion of %s at %d hosts.\n", spec, count); break }
			}
			log.Printf("[i] Added %d hosts from %s\n", count, spec)
		} else {
			ip := net.ParseIP(spec); if ip != nil { if ip.To4() != nil { targetSet[ip.String()] = struct{}{} } else { log.Printf("[!] Warning: Skipping non-IPv4 address: %s\n", spec) }
			} else { log.Printf("[!] Warning: Skipping invalid target specifier: %s\n", spec) }
		}
	}
	finalTargets := make([]string, 0, len(targetSet)); for ip := range targetSet { finalTargets = append(finalTargets, ip) }
	log.Printf("[i] Total unique target IPs generated: %d\n", len(finalTargets))
	return finalTargets
}


func worker(id int) {
	// (Worker function unchanged - sends results to channel)
	defer wg.Done()
	for target := range targetChan {
		if *debugMode { log.Printf("[d] Worker %d processing %s [%s]\n", id, target.IP, target.Community) }
		params := &gosnmp.GoSNMP{
			Target:    target.IP, Port:      uint16(*port), Community: target.Community,
			Version:   gosnmp.Version1, Timeout:   time.Duration(*timeoutSeconds * float64(time.Second)),
			Retries:   *retries, MaxOids:   gosnmp.MaxOids,
		}
		err := params.Connect()
		if err != nil { if *debugMode { log.Printf("[d] Failed connect %s [%s]: %v\n", target.IP, target.Community, err) }; continue }
		defer params.Conn.Close()
		oids := []string{sysDescrOID}
		result, err := params.Get(oids)
		if err != nil { if *debugMode { log.Printf("[d] Failed GET %s [%s]: %v\n", target.IP, target.Community, err) }
		} else if result == nil { if *debugMode { log.Printf("[d] Nil result for %s [%s]\n", target.IP, target.Community) }
		} else if len(result.Variables) > 0 {
			variable := result.Variables[0]
			if variable.Type != gosnmp.NoSuchObject && variable.Type != gosnmp.NoSuchInstance {
				var valueStr string
				switch variable.Type {
				case gosnmp.OctetString:
					cleanedBytes := []byte{}; for _, b := range variable.Value.([]byte) { if b >= 32 && b <= 126 { cleanedBytes = append(cleanedBytes, b) } else { cleanedBytes = append(cleanedBytes, '.') } }; valueStr = string(cleanedBytes)
				default: valueStr = fmt.Sprintf("%v", variable.Value)
				}
				resultLine := fmt.Sprintf("%s [%s] %s", target.IP, target.Community, valueStr)
				resultsChan <- resultLine
				if *shortMode { resultsChan <- target.IP }
			} else { if *debugMode { log.Printf("[d] SNMP Error for %s [%s]: %s\n", target.IP, target.Community, variable.Type.String()) } }
		} else { if *debugMode { log.Printf("[d] No variables received for %s [%s]\n", target.IP, target.Community) } }
	}
}

func resultProcessor() {
	// (resultProcessor function unchanged - uses logResult which now checks quiet mode)
	shortModeIPs := make(map[string]struct{})
	for result := range resultsChan {
		if *shortMode {
			if strings.Contains(result, ".") { // Crude check for IP vs full line
				if _, exists := shortModeIPs[result]; !exists {
					// Print unique IP to stdout even if quiet, unless file output is specified?
					// Original onesixtyone -s -q -o file outputs nothing to stdout.
					// Let's match that: only print if not quiet.
					if !*quietMode {
					    fmt.Println(result)
					}
					// Always log unique IP to file if open
					if outputFH != nil { fmt.Fprintln(outputFH, result) }
					shortModeIPs[result] = struct{}{}
				}
			}
		} else {
			logResult(result) // logResult handles quiet mode check for console output
		}
	}
}

// --- Main Execution ---
func main() {
	flag.Parse() // Parse flags first
	configureLogger() // Configure logging based on flags (like -q)

	if *outputFile != "" { setupOutputFile(*outputFile); if outputFH != nil { defer outputFH.Close() } }

	if *communityFile != "" { communities = loadCommunities(*communityFile)
	} else if flag.NArg() > 1 { communities = []string{flag.Arg(1)}; log.Printf("[i] Using community from command line: %s\n", communities[0])
	} else if len(communities) > 0 && *communityFile == "" { log.Printf("[i] No community file/argument. Using defaults: %v\n", communities) }
	if len(communities) == 0 { log.Fatal("[!] No community strings specified or loaded. Exiting.") } // Use log.Fatal

	targetSpecs := []string{}
	if flag.NArg() > 0 && *targetFile == "" { targetSpecs = []string{flag.Arg(0)} }
	targets = expandTargets(targetSpecs, *targetFile)
	if len(targets) == 0 { log.Fatal("[!] No valid targets specified or loaded. Exiting.") } // Use log.Fatal

	log.Printf("[i] Starting scan: %d hosts, %d communities.\n", len(targets), len(communities))
	log.Printf("[i] Concurrency=%d, Timeout=%.2fs, Retries=%d, Port=%d\n", *concurrency, *timeoutSeconds, *retries, *port)

	targetChan = make(chan scanTarget, *concurrency); resultsChan = make(chan string, *concurrency)
	wg.Add(*concurrency); for i := 1; i <= *concurrency; i++ { go worker(i) }
	go resultProcessor()

	go func() {
		for _, ip := range targets { for _, comm := range communities { targetChan <- scanTarget{IP: ip, Community: comm} } }
		close(targetChan)
	}()

	wg.Wait(); close(resultsChan)
	time.Sleep(100 * time.Millisecond)
	log.Printf("[i] Scan finished.") // This will only print to file or stderr if -q used
}
