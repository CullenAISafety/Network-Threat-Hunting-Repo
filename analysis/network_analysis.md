# Network Traffic Analysis Report

**File:** `sample_network.pcap`  
**Analyst:** Cullen E. Mathews  
**Date:** 2026-03-22  
**Purpose:** Threat hunting and network traffic analysis lab  

---

## 1. Overview

This analysis reviews the `sample_network.pcap` file containing simulated network traffic. The goal is to identify normal behavior patterns, detect anomalies, and highlight potential threats. The traffic includes:

- ICMP (ping) requests
- TCP traffic (HTTP, SSH)
- UDP traffic (DNS queries)
- Suspicious patterns such as port scans

The simulated environment consists of **internal hosts** (`192.168.1.10`, `192.168.1.20`) and **external hosts** (`8.8.8.8`, `1.1.1.1`), with some malicious activity simulated from `192.168.1.99`.

---

## 2. Traffic Summary

| Protocol | Packet Count | Observations |
|----------|--------------|--------------|
| ICMP     | 2            | Normal ping requests to external hosts. |
| TCP      | 6            | HTTP and SSH connections. Some SYN flags indicate potential scans. |
| UDP      | 2            | DNS queries to public DNS servers (8.8.8.8, 1.1.1.1). |
| TCP SYN (Port Scan) | 5 | Multiple sequential ports targeted on host 192.168.1.30, suspicious behavior. |

> **Note:** Counts are based on this sample capture. In real-world analysis, traffic volumes would be larger and time-stamped.

---

## 3. Suspicious Activity

### 3.1 Port Scan Detection

- **Source IP:** `192.168.1.99`  
- **Target IP:** `192.168.1.30`  
- **Ports:** 20–24  
- **Pattern:** Multiple TCP SYN packets sent to sequential ports

This activity is indicative of **reconnaissance** or **preliminary scanning**. It should be investigated further.

### 3.2 Abnormal SSH Connection Attempts

- Some TCP SYN packets to port 22 from internal hosts appear unusual.  
- In a real environment, repeated or unexpected SSH connections could indicate **lateral movement** or **unauthorized access attempts**.

---

## 4. Traffic Visualization

> You can use **Wireshark**, **Zeek**, or Python plotting libraries to visualize traffic patterns. Examples:

```python
from scapy.all import rdpcap
import matplotlib.pyplot as plt

packets = rdpcap("sample_network.pcap")
protocols = [pkt.sprintf("%IP.proto%") for pkt in packets]

plt.hist(protocols, bins=len(set(protocols)))
plt.title("Protocol Distribution")
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.show()

Recommendations
Monitor for repeated port scans: Configure IDS/IPS alerts for multiple TCP SYN packets across sequential ports.
Validate SSH connections: Ensure only authorized hosts initiate SSH sessions.
Log DNS queries: Look for unusual or repeated external queries, which may indicate exfiltration.
Expand capture timeframe: Longer captures provide better insight into baseline traffic and anomalies.

Conclusion

The sample_network.pcap file provides a realistic environment for threat hunting exercises. Key findings:

Normal activity: ICMP, HTTP, DNS traffic
Suspicious activity: TCP SYN port scan, unexpected SSH connections
Visualizations and protocol distribution can help quickly identify anomalies

This lab serves as a foundation for SOC/IR training and further network threat hunting scenarios.
