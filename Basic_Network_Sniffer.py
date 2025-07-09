# Basic Network Sniffer using Scapy
# Author: Md. Shefayer Ahmed
# Description: This script captures and analyzes network packets (IP, TCP, UDP, ICMP)

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Function to process each captured packet
def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Mapping protocol numbers to names
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_name = proto_map.get(protocol, "Other")

        print("\nPacket Captured:")
        print(f"Protocol        : {proto_name}")
        print(f"Source IP       : {src_ip}")
        print(f"Destination IP  : {dst_ip}")

        # For TCP/UDP packets, show port info
        if proto_name == "TCP" and TCP in packet:
            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif proto_name == "UDP" and UDP in packet:
            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif proto_name == "ICMP":
            print(f"ICMP Type       : {packet[ICMP].type}")

        # Display raw payload data (if any)
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload         : {payload[:50]}")  # Show first 50 bytes

# Start sniffing packets on default interface
print("Sniffing network traffic... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, store=False)