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
