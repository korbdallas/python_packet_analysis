# python_packet_analysis
Tools written in python to analyze packet captures


syn_retrans.py usage and example

```
python syn_retrans_2.py retrans.pcap 

Retransmitted SYN packet: 127.0.0.1:55616 -> 127.0.0.1:8080

Retransmitted SYN packet: 127.0.0.1:55616 -> 127.0.0.1:8080

Retransmitted SYN packet: 127.0.0.1:55616 -> 127.0.0.1:8080
```

fail_connections.py usage and example

```
# python failed_connection_2.py test.pcap 
Failed connections:
Source: 127.0.0.1:53840  Destination: 127.0.0.1:443
Source: 127.0.0.1:60548  Destination: 127.0.0.1:443
```
nex_seq.py usage and example

```# python next_seq.py ~/Downloads/steam4.pcap 
reading from file /home/mcolombo/Downloads/steam4.pcap, link-type EN10MB (Ethernet), snapshot length 512
S Source: 11.16.32.163:52694  Destination: 10.161.80.14:82
Current Seq: 3153100397 -> Next Seq:, 3153100397

SA Source: 10.161.80.14:82  Destination: 11.16.32.163:52694
Current Seq: 3298843518 -> Next Seq:, 3298843518

A Source: 11.16.32.163:52694  Destination: 10.161.80.14:82
Current Seq: 3153100398 -> Next Seq:, 3153100398

PA Source: 11.16.32.163:52694  Destination: 10.161.80.14:82
Current Seq: 3153100398 -> Next Seq:, 3153100844

A Source: 10.161.80.14:82  Destination: 11.16.32.163:52694
Current Seq: 3298843519 -> Next Seq:, 3298843519

PA Source: 10.161.80.14:82  Destination: 11.16.32.163:52694
Current Seq: 3298843519 -> Next Seq:, 3298843965

FA Source: 10.161.80.14:82  Destination: 11.16.32.163:52694
Current Seq: 3298845193 -> Next Seq:, 3298845193

A Source: 11.16.32.163:52694  Destination: 10.161.80.14:82
Current Seq: 3153106811 -> Next Seq:, 3153106811

A Source: 11.16.32.163:52694  Destination: 10.161.80.14:82
Current Seq: 3153106811 -> Next Seq:, 3153106811

FA Source: 11.16.32.163:52694  Destination: 10.161.80.14:82
Current Seq: 3153106811 -> Next Seq:, 3153106811

A Source: 10.161.80.14:82  Destination: 11.16.32.163:52694
Current Seq: 3298845194 -> Next Seq:, 3298845194
```
