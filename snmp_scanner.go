package main

import (
	"bufio"
	"flag"
	"fmt"
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
	communityFile  = flag.String("c", "", "File containing community strings (one per line)")
	targetFile     = flag.String("i", "", "File containing target hosts/CIDRs (one per line)")
	outputFile     = flag.String("o", "", "Output log file for results")
	port           = flag.Int("p", 161, "Destination SNMP port")
	timeoutSeconds = flag.Float64("w", 0.5, "Response timeout in seconds")
	retries        = flag.Int("r", 0, "Number of SNMP retries")
	concurrency    = flag.Int("C", 1000, "Max concurrent scan tasks")
	shortMode      = flag.Bool("s", false, "Short mode, print only IP addresses that respond")
	quietMode      = flag.Bool("q", false, "Quiet mode, do not print results to stdout (use with -o)")
	debugMode      = flag.Bool("d", false, "Enable debug logging (prints errors/timeouts)")

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

func initLogger() {
	log.SetFlags(log.Ltime) // Only show time in logs
}

func setupOutputFile(filename string) {
	var err error
	// Use append mode, create if not exists
	outputFH, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[!] Error opening output file %s: %v\n", filename, err)
		outputFH = nil // Ensure it's nil if open failed
	} else {
		log.Printf("[i] Logging results also to: %s\n", filename)
	}
}

func logResult(message string) {
	if !*quietMode {
		fmt.Println(message) // Print directly to stdout if not quiet
	}
	if outputFH != nil {
		// Add timestamp manually for file consistency if needed, logger does it too
		// timestamp := time.Now().Format("15:04:05")
		if _, err := fmt.Fprintln(outputFH, message); err != nil {
			log.Printf("[!] Error writing to output file: %v\n", err)
		}
	}
}

func loadCommunities(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("[!] Error opening community file %s: %v. Using defaults.\n", filename, err)
		return communities // Return default on error
	}
	defer file.Close()

	loadedCommunities := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Ignore comments and empty lines
		if line != "" && !strings.HasPrefix(line, "#") {
			loadedCommunities = append(loadedCommunities, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[!] Error reading community file %s: %v. Using defaults.\n", filename, err)
		return communities
	}

	if len(loadedCommunities) > 0 {
		log.Printf("[i] Loaded %d communities from %s\n", len(loadedCommunities), filename)
		return loadedCommunities
	}

	log.Printf("[!] Warning: Community file %s was empty. Using defaults.\n", filename)
	return communities
}

// --- Function to increment an IPv4 address ---
func incIP(ip net.IP) {
	// Operate on a copy if original needed later, but here we modify in place
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// --- UPDATED expandTargets function (No external dependencies) ---
func expandTargets(targetSpecs []string, filename string) []string {
	targetSet := make(map[string]struct{}) // Use map as a set for uniqueness

	// Add targets from file if specified
	if filename != "" {
		log.Printf("[i] Reading targets from file: %s\n", filename)
		file, err := os.Open(filename)
		if err != nil { log.Printf("[!] Error opening target file %s: %v\n", filename, err) } else {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != "" && !strings.HasPrefix(line, "#") { targetSpecs = append(targetSpecs, line) } }
			file.Close()
			if err := scanner.Err(); err != nil { log.Printf("[!] Error reading target file %s: %v\n", filename, err) }
		}
	}

	// Process all specs (from args and file)
	for _, spec := range targetSpecs {
		// Use blank identifier '_' for unused ipAddr from ParseCIDR
		_, ipNet, err := net.ParseCIDR(spec)
		if err == nil {
			// It's a CIDR range
			log.Printf("[i] Expanding CIDR: %s\n", spec)
			count := 0
			// Limit processing extremely large ranges to prevent excessive memory/time usage
			ones, bits := ipNet.Mask.Size()
			if bits-ones > 24 { // Limit larger than /8 (~16M) ? Adjust as needed. Check /24 first.
			    if bits-ones > 16 { // Limit /16 (~65k)
			        log.Printf("[!] Warning: CIDR range /%d (%s) is large. Expansion might be slow/memory intensive.\n", ones, spec)
			        // Add more aggressive limits if needed
			    }
			}


			currentIP := ipNet.IP.To4() // Ensure we start with IPv4
			if currentIP == nil { log.Printf("[!] Warning: Skipping non-IPv4 CIDR %s\n", spec); continue }

			mask := ipNet.Mask
			networkIP := make(net.IP, len(currentIP))
			copy(networkIP, currentIP) // Make copy before masking
			networkIP = networkIP.Mask(mask)

			broadcastIP := make(net.IP, len(currentIP))
			for i := range currentIP { broadcastIP[i] = currentIP[i] | ^mask[i] }

			// Iterate through the range, starting from the IP after network addr
            currentIP = make(net.IP, len(networkIP))
            copy(currentIP, networkIP)
			incIP(currentIP) // Start from first usable IP

			// Iterate until currentIP > broadcastIP or leaves the network
			for ; ipNet.Contains(currentIP); incIP(currentIP) {
				ipStr := currentIP.String()

                // Stop if we reach broadcast (unless /31 or /32)
				if ipStr == broadcastIP.String() {
				    if ones < 31 { // For /30 and smaller, don't include broadcast
				         break
				    }
                    // Include last IP for /31, /32
                }


				targetSet[ipStr] = struct{}{}
				count++

				// Safety break for extremely large ranges not caught by initial size check
				if count > 2 * 65536 { // Stop after ~130k hosts from one CIDR anyway
					log.Printf("[!] Warning: Stopping expansion of %s at %d hosts (Safety limit).\n", spec, count)
					break
				}
			}
			log.Printf("[i] Added %d hosts from %s\n", count, spec)

		} else {
			// Treat as single IP if not CIDR
			ip := net.ParseIP(spec)
			if ip != nil {
				if ip.To4() != nil { targetSet[ip.String()] = struct{}{} } else { log.Printf("[!] Warning: Skipping non-IPv4 address: %s\n", spec) }
			} else { log.Printf("[!] Warning: Skipping invalid target specifier: %s\n", spec) }
		}
	}

	finalTargets := make([]string, 0, len(targetSet))
	for ip := range targetSet { finalTargets = append(finalTargets, ip) }
	log.Printf("[i] Total unique target IPs generated: %d\n", len(finalTargets))
	return finalTargets
}
// --- END UPDATED expandTargets ---


func worker(id int) {
	// (Worker function remains the same as response #59)
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
	// (resultProcessor function remains the same)
	shortModeIPs := make(map[string]struct{})
	for result := range resultsChan {
		if *shortMode {
			if strings.Contains(result, ".") { // Crude check for IP vs full line
				if _, exists := shortModeIPs[result]; !exists {
					fmt.Println(result)
					if outputFH != nil { fmt.Fprintln(outputFH, result) }
					shortModeIPs[result] = struct{}{}
				}
			}
		} else { logResult(result) }
	}
}

// --- Main Execution ---
func main() {
	initLogger()
	flag.Parse()

	if *outputFile != "" { setupOutputFile(*outputFile); if outputFH != nil { defer outputFH.Close() } }

	// Determine community list
	if *communityFile != "" { communities = loadCommunities(*communityFile)
	} else if flag.NArg() > 1 { // Community is the second positional arg if present
		communities = []string{flag.Arg(1)}
		log.Printf("[i] Using community from command line: %s\n", communities[0])
	} else if len(communities) > 0 && *communityFile == "" { // Use defaults only if nothing else provided
	    log.Printf("[i] No community file/argument. Using defaults: %v\n", communities)
	}
	// Final check if we ended up with no communities
	if len(communities) == 0 { log.Fatal("[!] No community strings specified or loaded. Exiting.") }


	// Determine target specifications
	targetSpecs := []string{}
	// If -i file is given, it overrides positional target
	if *targetFile == "" {
	    // No -i file, check for positional target (must be first arg)
	    if flag.NArg() > 0 {
	        targetSpecs = []string{flag.Arg(0)}
	    }
	} // If -i file is given, targetSpecs remains empty, expandTargets handles the file

	if len(targetSpecs) == 0 && *targetFile == "" {
	    log.Fatal("[!] No targets specified via argument or -i file. Exiting.")
	}

	targets = expandTargets(targetSpecs, *targetFile)
	if len(targets) == 0 { log.Fatal("[!] No valid targets specified or loaded. Exiting.") }

	log.Printf("[i] Starting scan: %d hosts, %d communities.\n", len(targets), len(communities))
	log.Printf("[i] Concurrency=%d, Timeout=%.2fs, Retries=%d, Port=%d\n", *concurrency, *timeoutSeconds, *retries, *port)

	targetChan = make(chan scanTarget, *concurrency); resultsChan = make(chan string, *concurrency)
	wg.Add(*concurrency); for i := 1; i <= *concurrency; i++ { go worker(i) }
	go resultProcessor() // Start processor to consume results

	// Feed targets in a separate goroutine to avoid blocking main
	go func() {
		for _, ip := range targets { for _, comm := range communities { targetChan <- scanTarget{IP: ip, Community: comm} } }
		close(targetChan) // Close channel when all targets are sent
	}()

	wg.Wait(); // Wait for all worker goroutines to finish
	close(resultsChan); // Close results channel after workers are done

	// Wait briefly for result processor to finish printing last items
	time.Sleep(200 * time.Millisecond)
	log.Printf("[i] Scan finished.")
}
