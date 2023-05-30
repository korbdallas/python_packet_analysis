########################################################
##
## This is an application that is designed to detect missing
## packets (sequence) numbers on reciever packet captures. 
##
##   USAGE: python missing_seq_numbers.py
##
## Author: Michael Colombo
## Date: 5/30/2023
##
########################################################
import sys
import logging

# This is needed to suppress a really irrating warning message when scapy
# is imported
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import*
except ImportError:
    print ("scapy is not installed.")
    exit ()


# Assign arguments to variables
try:
    pcap_file = sys.argv[1]
except IndexError:
    print(" Usage: python missing_seq_numbers.py dest.pcap")
    exit()
except NameError:
    print(" Usage: python missing_seq_numbers.py dest.pcap")
    exit()

def spot_missing_tcp_packets(pcap_file):
    packets = sniff(offline=pcap_file, filter="tcp")

    # Track the sequence numbers of TCP packets
    seq_nums = set()

    # Find missing TCP packets
    missing_packets = []
    for packet in packets:
        tcp_packet = packet[TCP]
        seq_num = tcp_packet.seq

        if seq_num in seq_nums:
           # Duplicate packet found
            continue

            seq_nums.add(seq_num)

            if len(seq_nums) != seq_num:
                # Missing packet found
                missing_packets.append(seq_num)

    return missing_packets

# Usage example
missing_packets = spot_missing_tcp_packets(pcap_file)

print(f"Missing TCP packets: {len(missing_packets)}")
print("Sequence numbers of missing packets:")
print(missing_packets)
