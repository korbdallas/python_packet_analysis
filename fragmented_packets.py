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


#assign argument to variable
try:
    pcap_file = sys.argv[1]
except IndexError:
    print(" Usage: fragmented_packets <file>.pcap")
    exit()
except NameError:
    print(" Usage: fragmented_packets <file>.pcap")
    exit()


def identify_fragmented_packets(pcap_file):
    # Read the packet capture file
    try:
        packets = rdpcap(pcap_file)
    except IOError:
        print ("It doesn't look like " + pcap_file + " exists")
        exit()
    except NameError:
        print ("It doesn't look like " + pcap_file + " is a file that can be processed."   )
        exit ()

    fragmented_packets = []

    for packet in packets:
        if IP in packet:
            ip = packet[IP]

            if ip.flags & 0x1:  # Check if the "More Fragments" flag is set
                if TCP in packet:
                    tcp = packet[TCP]
                    fragmented_packets.append({
                        'type': 'TCP',
                        'src_ip': ip.src,
                        'src_port': tcp.sport,
                        'dst_ip': ip.dst,
                        'dst_port': tcp.dport,
                        'seq_num': tcp.seq
                    })
                elif UDP in packet:
                    udp = packet[UDP]
                    fragmented_packets.append({
                        'type': 'UDP',
                        'src_ip': ip.src,
                        'src_port': udp.sport,
                        'dst_ip': ip.dst,
                        'dst_port': udp.dport,
                        #'seq_num': None
                    })

    if fragmented_packets:
        for packet in fragmented_packets:
            print(f"Fragmented {packet['type']} packet found!")
            print(f"Source IP: {packet['src_ip']}, Source Port: {packet['src_port']}")
            print(f"Destination IP: {packet['dst_ip']}, Destination Port: {packet['dst_port']}")
            if packet['type'] == 'TCP':
                print(f"Sequence Number: {packet['seq_num']}")
            print("")
    else:
        print("No fragmented packets found.")

identify_fragmented_packets(pcap_file)
