# go_snmp_scanner
Ultra fast snmp scanner on go

# This is based on the onesixtyone snmp scanner written in go.  

Timing results:
```
time /root/tools/gosnmp/go_snmp_scanner  -c ~/tools/onesixtyone/dict.txt -i ip.txt 
14:58:28 [i] Loaded 50 communities from /root/tools/onesixtyone/dict.txt
14:58:28 [i] Reading targets from file: ip.txt
14:58:28 [i] Total unique target IPs generated: 200
14:58:28 [i] Starting scan: 200 hosts, 50 communities.
14:58:28 [i] Concurrency=1000, Timeout=0.50s, Retries=0, Port=161
x.x.x.x [public] HP 
x.x.x.x [public] 
14:58:48 [i] Scan finished.

real	0m5.286s
user	0m0.680s
sys	0m0.478s
```

```
time ~/tools/onesixtyone/onesixtyone   -i ip.txt -c /root/tools/onesixtyone/dict.txt 
Scanning 200 hosts, 50 communities
x.x.x.x [public] HP 
x.x.x.x [public] 

real	1m47.749s
user	0m0.064s
sys	0m0.673s
```

## Notes.  Main reason that I created another scanner is because onesixtyone is failing in CIDR parsing in some networks. 
