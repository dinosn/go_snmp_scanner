```markdown
# go_snmp_scanner

Ultra‑fast SNMP scanner written in Go, based on the original `onesixtyone` scanner.

---

## 📈 Timing Comparison

| Scanner                       | Real Time | User CPU | System CPU |
|-------------------------------|-----------|----------|------------|
| **go_snmp_scanner**           | 0m5.286s  | 0m0.680s | 0m0.478s   |
| **onesixtyone (original)**    | 1m47.749s | 0m0.064s | 0m0.673s   |


```
# go_snmp_scanner

Ultra‑fast SNMP scanner written in Go, based on the original `onesixtyone` scanner.

## Timing Comparison

| Scanner                    | Real Time | User CPU | Sys CPU |
|----------------------------|-----------|----------|---------|
| **go_snmp_scanner**        | 0m5.286s  | 0m0.680s | 0m0.478s|
| **onesixtyone (original)** | 1m47.749s | 0m0.064s | 0m0.673s|

### go_snmp_scanner output

```bash
time /root/tools/gosnmp/go_snmp_scanner \
  -c ~/tools/onesixtyone/dict.txt \
  -i ip.txt

14:58:28 [i] Loaded 50 communities from /root/tools/onesixtyone/dict.txt
14:58:28 [i] Reading targets from file: ip.txt
14:58:28 [i] Total unique target IPs generated: 200
14:58:28 [i] Starting scan: 200 hosts, 50 communities.
14:58:28 [i] Concurrency=1000, Timeout=0.50s, Retries=0, Port=161
x.x.x.x [public] HP 
x.x.x.x [public] 
14:58:48 [i] Scan finished.

real    0m5.286s
user    0m0.680s
sys     0m0.478s
```

### onesixtyone output

```bash
time ~/tools/onesixtyone/onesixtyone \
  -i ip.txt \
  -c /root/tools/onesixtyone/dict.txt

Scanning 200 hosts, 50 communities
x.x.x.x [public] HP 
x.x.x.x [public] 

real    1m47.749s
user    0m0.064s
sys     0m0.673s
```

## Installation

### Via `go install`

```bash
go install github.com/dinosn/go_snmp_scanner@latest
```

### From source

1. **Clone the repo**  
   ```bash
   git clone https://github.com/dinosn/go_snmp_scanner.git
   ```
2. **Enter the directory**  
   ```bash
   cd go_snmp_scanner
   ```
3. **Build the binary**  
   ```bash
   go build -o go_snmp_scanner .
   ```

## Usage

```bash
go_snmp_scanner \
  -c /path/to/communities.txt \
  -i /path/to/targets.txt \
  -t 161 \
  --timeout 0.5 \
  --retries 0 \
  --workers 1000
```

- `-c`, `--communities`  
  File with one SNMP community string per line.  
- `-i`, `--input`  
  File with IPs, CIDRs, or ranges (one per line).  
- `-t`, `--port`  
  SNMP port (default: `161`).  
- `--timeout`  
  Per‑request timeout in seconds (default: `0.50`).  
- `--retries`  
  Number of retry attempts per request (default: `0`).  
- `--workers`  
  Maximum concurrent workers (default: `1000`).

## Notes

- Created because `onesixtyone` sometimes fails on certain CIDR/range formats.  
- Supports single IPs, CIDR notation (e.g. `10.0.0.0/24`), and dash‑separated ranges (e.g. `10.0.0.1-10.0.0.254`).  
- Contributions and optimizations welcome: https://github.com/dinosn/go_snmp_scanner.
