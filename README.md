# Network Traffic Threat Hunting

## Overview
This project is a hands-on SOC/Threat Hunting mini-project focused on analyzing network traffic to detect anomalies, extract Indicators of Compromise (IOCs), and simulate incident response workflows. It's designed to demonstrate practical cybersecurity skills for a Security Analyst or SOC engineer portfolio.

## Demo
![Network Traffic Demo](assets/network_demo.gif)

## Project Structure

```
Network-Traffic-Threat-Hunting/
├── README.md                  # Project overview and instructions
├── assets/                    # Demo GIFs and visualization assets
│   └── network_demo.gif
├── logs/                      # Sample network PCAP files for analysis
│   └── sample_network.pcap
├── analysis/                  # Markdown analysis write-ups
│   └── network_analysis.md
├── scripts/                   # Python scripts for network traffic parsing and IOC extraction
│   └── traffic_parser.py
├── iocs/                      # Extracted indicators of compromise
│   └── network_iocs.json
└── reports/                   # Final incident report summarizing findings
    └── final_network_incident_report.pdf
```

## Skills Demonstrated
- Network traffic analysis using PCAPs
- Detection of anomalies and suspicious connections
- Extraction and reporting of IOCs
- Threat hunting workflow simulation
- SOC-style investigation reporting

## Getting Started
1. Clone the repository:
```bash
git clone <repo_url>
cd Network-Traffic-Threat-Hunting
```
2. Install required Python packages:
```bash
pip install dpkt
```
3. Run the network traffic parser:
```bash
python3 scripts/traffic_parser.py logs/sample_network.pcap
```
4. Review extracted IOCs:
```bash
cat iocs/network_iocs.json
```

## Reports
- `reports/final_network_incident_report.pdf` contains a detailed summary of the investigation, findings, extracted IOCs, and recommended mitigation actions.

## Contribution
This project is designed as a showcase for cybersecurity portfolios. Contributions for improved detection scripts or more detailed analysis are welcome.
