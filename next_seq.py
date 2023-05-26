####################################################################################
## This is an application to calculate the next expected seq number. 
##
##       python next_seq.py <pcap_file>
##
## Author: Michael Colombo
## Date: 5/26/2023 
##
####################################################################################

from scapy.all import *
import sys

pcap_file = sys.argv[1]

def packet_handler(packet):
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    current_seq = packet[TCP].seq
    flags = packet[TCP].flags
    payload = packet[TCP].payload

    next_seq = current_seq + len(payload)
    print(f"{flags} Source: {src_ip}:{src_port}  Destination: {dst_ip}:{dst_port}")
    print(f"Current Seq: {current_seq} -> Next Seq:, {next_seq}\n")


# Start sniffing packets
sniff(offline=pcap_file, filter="tcp", prn=packet_handler)
