#!/usr/bin/env python3

from tabnanny import verbose
from async_timeout import timeout
import scapy.all as scapy

def scan(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print("\n\t\t\t\t@JACK NETWORK SCANNER\n\t\t\t\t\t@Jack")
    print("\t\t\tTHE PHANTOM JACK PROJECT (PH4N70M)\n")
    print("IP\t\t\tMAC Address\n----------------------------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
       

    
   
scan("192.168.43.1/24")