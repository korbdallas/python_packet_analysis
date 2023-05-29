########################################################################################
##  This is an application used to compare 2 packet captures and determine if
##  There are any packets missing from the second capture that are present in the first.
##
##  important note: This application requires the scapy module to be install
##
##          # pip3 install scapy
##
##   Usage: python missing_packets.py source.pcap dest.pcap
##
##   Author: Michael Colombo
##   Date: 5/29/2023
##########################################################################################

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
    pcap_file1 = sys.argv[1]
except IndexError:
    print(" Usage: python missing_packets.py source.pcap dest.pcap")
    exit()
except NameError:
    print(" Usage: python missing_packets.py source.pcap dest.pcap")
    exit()

try:
    pcap_file2 = sys.argv[2]
except IndexError:
    print(" Usage: python missing_packets.py source.pcap dest.pcap")
    exit()
except NameError:
    print(" Usage: python missing_packets.py source.pcap dest.pcap")
    exit()
# Step 1: Read the packet captures
try:
    packets1 = rdpcap(pcap_file1)
except IOError:
   print ("It doesn't look like " + pcap_file1 + " exists")
   exit()
except NameError:
   print ("It doesn't look like " + pcap_file1 + " is a file that can be processed."   )
   exit ()

try:
    packets2 = rdpcap(pcap_file2)
except IOError:
   print ("It doesn't look like " + pcap_file2 + " exists")
   exit()
except NameError:
   print ("It doesn't look like " + pcap_file2 + " is a file that can be processed.")
   exit ()

# Step 2: Create a list for missing packets
missing_packets = []

# Step 3: Define the callback function
def compare_packets(packet):

    global missing_packets
    if packet not in packets2:
        missing_packets.append(packet)

# Step 4: Sniff packets from the first capture
sniff(offline=pcap_file1, prn=compare_packets)

# Step 6: Access the missing packets
print(f"Number of missing packets: {len(missing_packets)}")
print("Missing Packets:")
for pkt in missing_packets:

    if TCP in pkt:
        seq = pkt[TCP].seq    
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport    
        flags = pkt[TCP].flags
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        print(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} SEQ:{seq} FLAG:{flags}")
