#!/usr/bin/env python3
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap
from datetime import datetime
import random
from pathlib import Path
import base64

STUDENT_NAME = "Gravalos-Kerimi"
STUDENT_ID   = "2021030001-2021030007"
DNS_SERVER_IP = "192.168.1.1"

def random_public_ipv4() -> str:
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)

        if a in (10, 127):
            continue
        if a == 169 and b == 254:
            continue
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue

        return f"{a}.{b}.{c}.{d}"

def payload_string():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{STUDENT_NAME}-{STUDENT_ID} {ts}"

def studId_packets():
    return (
        IP(src=random_public_ipv4(), dst="192.168.1.1") /
        TCP(sport=random.randint(1024, 65535), dport=54321, flags="PA") /
        Raw(load=payload_string())
    )

def portscan_packets():
    dst_ip = "192.168.1.2"
    services = [
        ("HTTP",   "TCP", 80),
        ("HTTPS",  "TCP", 443),
        ("SSH",    "TCP", 22),
        ("TELNET", "TCP", 23),
        ("FTP",    "TCP", 21),
        ("DNS",    "UDP", 53),
        ("RTSP",   "TCP", 554),
        ("SQL",    "TCP", 1433),
        ("RDP",    "TCP", 3389),
        ("MQTT",   "TCP", 1883),
    ]

    packets = []
    for service, protocol, port in services:
        if protocol == "TCP":
            pkt = (
                IP(src=random_public_ipv4(), dst=dst_ip) /
                TCP(sport=random.randint(1024, 65535), dport=port, flags="S") /
                Raw(load=payload_string())
            )
        else:
            pkt = (
                IP(src=random_public_ipv4(), dst=dst_ip) /
                UDP(sport=random.randint(1024, 65535), dport=port) /
                Raw(load=payload_string())
            )
        packets.append(pkt)

    return packets

def base64_packets(count=5):
    dst_ip = "192.168.1.3"
    dst_port = 8080
    b64_payload = base64.b64encode(STUDENT_ID.encode()).decode()

    packets = []
    for _ in range(count):
        pkt = (
            IP(src=random_public_ipv4(), dst=dst_ip) /
            TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="PA") /
            Raw(load=b64_payload)
        )
        packets.append(pkt)

    return packets

def dns_packet():
    return (
        IP(src=random_public_ipv4(), dst=DNS_SERVER_IP) /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        DNS(rd=1, qd=DNSQR(qname="ergasiaMesa.StisGiortes.com"))
    )

def icmp_packet():
    return (
        IP(src=random_public_ipv4(), dst="192.168.1.4") /
        ICMP(type=8, code=0) /
        Raw(load="thelwNaFygw!!!!!")
    )

def main():
    packets = []

    packets.append(studId_packets())
    packets.extend(portscan_packets())
    packets.extend(base64_packets(5))
    packets.append(dns_packet())
    packets.append(icmp_packet())

    out_dir = Path.home() / "Desktop/assignment7/snort/lab"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_pcap = out_dir / "custom_pt2.pcap"

    wrpcap(str(out_pcap), packets)

    print(f"Wrote {len(packets)}/18 packets to {out_pcap}")

if __name__ == "__main__":
    main()

