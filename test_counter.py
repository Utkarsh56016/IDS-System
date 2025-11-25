# test_counter.py
import flow_manager
from sniffer import packet_handler

print("initial counter:", flow_manager.global_packet_counter)
# call handler with a fake object that flow_manager will ignore because not IP,
# but we can call add_packet directly to test increment as well
from scapy.layers.inet import IP
from scapy.all import Ether
# craft a tiny IP packet for test
pkt = Ether()/IP(dst="8.8.8.8", src="192.168.0.10")
packet_handler(pkt)
packet_handler(pkt)
print("after handler calls:", flow_manager.global_packet_counter)

# also test direct add_packet
flow_manager.add_packet(pkt)
print("after direct add_packet:", flow_manager.global_packet_counter)
