# modules/packet_sniffer.py

from scapy.all import sniff,wrpcap, IP, TCP, UDP, ICMP
from datetime import datetime

packet_logs = []
packet_list = []
protocol_counts = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}

def packet_callback(packet):

    packet_list.append(packet)
    protocol_counts[proto] += 1
    timestamp = datetime.now().strftime("%H:%M:%S")
    if IP in packet:
        proto = "Other"
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "Other"
        src = packet[IP].src
        dst = packet[IP].dst
        log = f"[{timestamp}] {proto} Packet: {src} -> {dst}"
        packet_logs.append(log)

        # Keep only last 100 logs to avoid overflow
        if len(packet_logs) > 100:
            packet_logs.pop(0)

def start_sniffing():
    sniff(prn=packet_callback, store=True, timeout=60, filter="ip", out="captured.pcap")

def export_pcap():
    wrpcap("static/pcap/captured.pcap", packet_list)