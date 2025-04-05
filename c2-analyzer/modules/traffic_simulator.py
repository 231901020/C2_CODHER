from scapy.all import send, IP, TCP
import time

def simulate_c2_traffic():
    while True:
        packet = IP(dst="127.0.0.1")/TCP(dport=4444, flags="S")
        send(packet, verbose=False)
        time.sleep(2)