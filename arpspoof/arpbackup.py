
import keyword
import scapy.all as scapy
from scapy.layers import http
 

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            print(load)


sniff("wlan0")