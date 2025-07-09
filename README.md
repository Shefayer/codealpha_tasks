Basic Network Sniffer using Scapy:


Author: Md. Shefayer Ahmed  
Description: This Python script captures and analyzes network packets in real-time using the Scapy library. It identifies key packet information such as protocol type, source and destination IP addresses, ports (for TCP/UDP), and displays a portion of the raw payload.

-------------------------------
📁 File: network_sniffer.py
-------------------------------

🔧 Requirements:
---------------
- Python 3.x
- Scapy library

To install Scapy:
> pip install scapy

-------------------------------
▶️ How to Run:
---------------
1. Make sure you have administrative/root privileges (required for packet sniffing).
2. Open a terminal or command prompt.
3. Run the script using:
> sudo python network_sniffer.py   (Linux/macOS)  
> python network_sniffer.py       (Windows with admin rights)

The script will start sniffing live traffic on your default network interface.

-------------------------------
🔍 What It Does:
---------------
- Captures packets in real-time.
- Detects and prints:
  - Protocol (TCP, UDP, ICMP)
  - Source and Destination IP addresses
  - Port numbers (if applicable)
  - ICMP type (for ICMP packets)
  - First 50 bytes of the payload (if present)

-------------------------------
❗ Notes:
---------------
- Use responsibly and only on networks you own or have permission to monitor.
- May require firewall or antivirus permissions to function properly.

-------------------------------
📌 Example Output:
---------------
Sniffing network traffic... Press Ctrl+C to stop.

Packet Captured:
Protocol        : TCP
Source IP       : 192.168.1.10
Destination IP  : 172.217.11.142
Source Port     : 54321
Destination Port: 80
Payload         : b'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent:'

-------------------------------
📬 Contact:
---------------
For questions or improvements, feel free to contact the author.
