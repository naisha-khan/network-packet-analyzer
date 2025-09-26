# Network Packet Analyzer

A Python-based **Network Packet Analyzer** that simulates network traffic capture, analyzes packets, detects anomalies, and generates comprehensive reports with visualizations.

---

##  Features
- **Packet Capture Simulation:** Generate normal, anomalous, and broadcast packets  
- **Protocol Analysis:** TCP, UDP, ICMP, HTTP, HTTPS, SSH, FTP  
- **Traffic Statistics:** Total packets, bytes, bandwidth utilization  
- **Anomaly Detection:** Port scans, unusual packet sizes, high-frequency traffic, privileged port access  
- **Top Talkers:** Identify most active IP addresses  
- **Packet Loss Analysis:** Detect missing packets in the stream  
- **Visualization:** Protocol distribution, bandwidth over time, packet size distribution, anomalies by type  
- **Report Generation:** Export JSON analysis summaries  

---

##  Project Structure
```text
network-packet-analyzer/
├── network_packet_analyzer.py   # Main analyzer script
├── packet_analysis.json         # Generated analysis report (after run)
├── README.md                    # Project documentation
└── requirements.txt             # Optional: Python dependencies
