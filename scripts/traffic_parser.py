#!/usr/bin/env python3
"""
traffic_parser.py

Realistic network traffic parser for SOC/Threat Hunting labs:
- Parses a PCAP file
- Detects port scans and suspicious SSH attempts
- Generates protocol summary
- Exports analysis to network_analysis.md

Author: Cullen E. Mathews
Date: 2026-03-22
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter, defaultdict
from datetime import datetime

PCAP_FILE = "sample_network.pcap"
REPORT_FILE = "network_analysis.md"

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    summary = {
        "total_packets": len(packets),
        "protocol_count": Counter(),
        "suspicious_events": []
    }

    # Track potential port scans (source IP -> target IP -> ports)
    port_scan_tracker = defaultdict(lambda: defaultdict(set))
    ssh_attempts = []

    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            src = pkt[IP].src
            dst = pkt[IP].dst
            ts = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S")

            if proto == 1 and ICMP in pkt:
                summary["protocol_count"]["ICMP"] += 1

            elif proto == 6 and TCP in pkt:
                summary["protocol_count"]["TCP"] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags

                # Detect TCP SYNs (possible port scan)
                if flags == "S":
                    port_scan_tracker[src][dst].add(dport)
                    summary["suspicious_events"].append({
                        "type": "TCP SYN",
                        "src": src,
                        "dst": dst,
                        "dport": dport,
                        "time": ts
                    })

                # Detect unusual SSH attempts (port 22)
                if dport == 22 and flags == "S":
                    ssh_attempts.append({
                        "src": src,
                        "dst": dst,
                        "time": ts
                    })

            elif proto == 17 and UDP in pkt:
                summary["protocol_count"]["UDP"] += 1
            else:
                summary["protocol_count"]["Other"] += 1

        else:
            summary["protocol_count"]["Non-IP"] += 1

    # Identify potential port scans (>3 ports in short capture)
    for src, targets in port_scan_tracker.items():
        for dst, ports in targets.items():
            if len(ports) >= 3:
                summary["suspicious_events"].append({
                    "type": "Port Scan",
                    "src": src,
                    "dst": dst,
                    "ports": sorted(list(ports)),
                    "time": ts
                })

    # Include SSH attempts as suspicious
    for attempt in ssh_attempts:
        summary["suspicious_events"].append({
            "type": "Suspicious SSH",
            "src": attempt["src"],
            "dst": attempt["dst"],
            "time": attempt["time"]
        })

    return summary

def generate_markdown_report(summary, report_file):
    with open(report_file, "w") as f:
        f.write(f"# Network Traffic Analysis Report\n\n")
        f.write(f"**File:** `{PCAP_FILE}`  \n")
        f.write(f"**Analyst:** Cullen E. Mathews  \n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}  \n\n")

        f.write("## 1. Traffic Summary\n\n")
        f.write(f"- Total packets: {summary['total_packets']}\n")
        f.write("- Protocol breakdown:\n")
        for proto, count in summary["protocol_count"].items():
            f.write(f"  - {proto}: {count}\n")

        f.write(f"\n## 2. Suspicious Activity\n\n")
        if summary['suspicious_events']:
            for event in summary['suspicious_events']:
                if event["type"] == "Port Scan":
                    f.write(f"- [Port Scan] {event['src']} -> {event['dst']} Ports: {event['ports']} Time: {event['time']}\n")
                elif event["type"] == "TCP SYN":
                    f.write(f"- [TCP SYN] {event['src']} -> {event['dst']}:{event['dport']} Time: {event['time']}\n")
                elif event["type"] == "Suspicious SSH":
                    f.write(f"- [Suspicious SSH] {event['src']} -> {event['dst']} Time: {event['time']}\n")
        else:
            f.write("No suspicious events detected.\n")

        f.write("\n## 3. Recommendations\n\n")
        f.write("1. Monitor repeated TCP SYN packets for reconnaissance attempts.\n")
        f.write("2. Verify all SSH access and block unauthorized attempts.\n")
        f.write("3. Inspect unusual UDP or ICMP traffic for abnormal behavior.\n")
        f.write("4. Expand capture window for baseline analysis.\n")

    print(f"Report generated: {report_file}")

def main():
    summary = parse_pcap(PCAP_FILE)
    generate_markdown_report(summary, REPORT_FILE)

if __name__ == "__main__":
    main()

    How to run:
    pip install scapy
python traffic_parser.py
After running, you will have:

network_analysis.md with a ready-to-read SOC report
Detailed suspicious activity logs for threat hunting exercises

