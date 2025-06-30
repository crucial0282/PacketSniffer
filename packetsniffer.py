from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Ether
from datetime import datetime

def packet_callback(packet):
    print("="*80)
    print(f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Ethernet Layer
    if Ether in packet:
        ether = packet[Ether]
        print(f"🔌 Ethernet: {ether.src} ➜ {ether.dst} | Type: {ether.type}")

    # IP Layer
    if IP in packet:
        ip = packet[IP]
        print(f"🌐 IP: {ip.src} ➜ {ip.dst} | Protocol: {ip.proto}")

        # TCP Layer
        if TCP in packet:
            tcp = packet[TCP]
            print(f"📦 TCP: {ip.src}:{tcp.sport} ➜ {ip.dst}:{tcp.dport}")

        # UDP Layer
        elif UDP in packet:
            udp = packet[UDP]
            print(f"📦 UDP: {ip.src}:{udp.sport} ➜ {ip.dst}:{udp.dport}")

            # DNS Layer (inside UDP)
            if DNS in packet:
                dns = packet[DNS]
                if dns.qr == 0 and DNSQR in dns:
                    print(f"🔎 DNS Query: {dns[DNSQR].qname.decode(errors='ignore')}")
                elif dns.qr == 1 and DNSRR in dns:
                    print(f"📥 DNS Response: {dns[DNSRR].rrname.decode(errors='ignore')} ➜ {dns[DNSRR].rdata}")

print("🚨 Packet Sniffer Started... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False)
