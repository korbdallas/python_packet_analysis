####################################################################################
## This is an application to help find connections where SYN has been retransmitted. 
##
##       python failed_connections.py <pcap_file>
##
## Author: Michael Colombo
## Date: 5/26/2023 
##
####################################################################################

#!/bin/env/python

from scapy.all import *
import sys

pcap_file = sys.argv[1]

def detect_failed_connections(packet_capture):
    connections = {}
    failed_connections = []

    for packet in packet_capture:
        if TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if packet[TCP].flags == "S":  # SYN packet
                if (src_ip, src_port, dst_ip, dst_port) not in connections:
                    connections[(src_ip, src_port, dst_ip, dst_port)] = False

            elif packet[TCP].flags == "SA":  # SYN-ACK packet
                if (dst_ip, dst_port, src_ip, src_port) in connections:
                    connections[(dst_ip, dst_port, src_ip, src_port)] = True

            elif packet[TCP].flags == "R":  # RST packet
                if (dst_ip, dst_port, src_ip, src_port) in connections:
                    connections[(dst_ip, dst_port, src_ip, src_port)] = False

    for key, value in connections.items():
        if not value:
            failed_connections.append(key)

    return failed_connections


# Load the packet capture file
packet_capture = rdpcap(pcap_file)

# Detect failed connections
failed_connections = detect_failed_connections(packet_capture)

# Print the failed connections
if failed_connections:
    print("Failed connections:")
    for connection in failed_connections:
        src_ip, src_port, dst_ip, dst_port = connection
        print(f"Source: {src_ip}:{src_port}  Destination: {dst_ip}:{dst_port}")
else:
    print("No failed connections found.")
