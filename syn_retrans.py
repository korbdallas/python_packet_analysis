####################################################################################
## This is an application to help find connections where SYN has been retransmitted. 
##
##       python syn_retrans.py <pcap_file>
##
## Author: Michael Colombo
## Date: 5/25/2023 
##
####################################################################################

from scapy.all import *
import sys

pcap_file = sys.argv[1]

def find_retransmitted_syn_packets(pcap_file):
    syn_packets = {}

    def process_packet(packet):
        if TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            if flags & 'S' and not flags & 'A':
                # SYN packet without ACK flag (Initial SYN)
                key = (src_ip, dst_ip, src_port, dst_port)

                if key in syn_packets:
                    # Retransmitted SYN packet
                    print(f"Retransmitted SYN packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print()
                else:
                    syn_packets[key] = True

    # Process the packet capture file
    sniff(offline=pcap_file, prn=process_packet)


find_retransmitted_syn_packets(pcap_file)
