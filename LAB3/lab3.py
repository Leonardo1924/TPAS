from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP

# Script to Parse Wireshark .pcapng File and Extract IP Addresses

packet = rdpcap('capture.pcapng')

ip_addresses = set()

for pkt in packet:
    if IP in pkt:
        ip_addresses.add(pkt[IP].src)
        ip_addresses.add(pkt[IP].dst)

for ip in ip_addresses:
    print(ip)

# End of File

#  Script to Perform a SYN Port Scan

def syn_scan(target_ip, ports):
    for port in ports:
        syn_packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print(f'Port {port} is open')
                sr(IP(dst=target_ip)/TCP(dport=port, flags='R'), timeout=1, verbose=0)
            else:
                print(f'Port {port} is closed')
        else:
            print(f'Port {port} is filtered')

target = "192.168.1.1"
ports = [22, 23, 80, 443, 3389]
syn_scan(target, ports)

# End of File