# ARP Watchdog 🐕

A lightweight Network Intrusion Detection System (NIDS) written in Python using Scapy. It monitors the network for ARP Spoofing attacks (Man-in-the-Middle attempts).

## 🛡️ Educational Purpose
Understanding how to defend against attacks is the core of Cybersecurity. This tool demonstrates:
- **Protocol Analysis:** How the ARP protocol maps IP addresses to MAC addresses.
- **Anomaly Detection:** Identifying malicious traffic patterns (IP addresses changing physical locations rapidly).
- **Passive Monitoring:** Listening to network traffic without disrupting it.

## ⚠️ Requirements
- **Python 3**
- **Scapy:** `pip install scapy`
- **Privileges:** Must be run as Administrator/Root to access the network interface.

## 🚀 How to Run
1. Install Scapy:
   ```bash
   pip install scapy
