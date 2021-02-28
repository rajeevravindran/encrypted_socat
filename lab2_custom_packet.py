from scapy.all import *
from scapy.layers.inet import IP, ICMP

A = '10.0.0.9' # spoofed source IP address
B = '10.0.0.7' # destination IP address

spoofed_packet = IP(src=A, dst=B) / ICMP()
send(spoofed_packet)