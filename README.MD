# 🕵️ Packet Sniffer – Real-Time Network Traffic Analyzer

A custom packet sniffer built with **Python** and **Scapy** to capture and analyze live network traffic.  
It provides deep insights into packet-level data such as Ethernet, IP, TCP, UDP, and DNS.

---

## 🔧 Technologies Used

- Python
- Scapy

---

## 🚀 Features

- Captures live packets using `scapy.sniff`
- Parses:
  - Ethernet frames
  - IP packets
  - TCP/UDP segments
  - DNS queries & responses
- Displays real-time output in the console

---

## 📸 Sample Output:
        Ethernet Frame: 08:00:27:xx:xx:xx -> ff:ff:ff:ff:ff:ff, Type: 2048
        IP Packet: 192.168.1.2 -> 8.8.8.8, Protocol: 17
        UDP Datagram: 192.168.1.2:54500 -> 8.8.8.8:53
        DNS Query: example.com.
