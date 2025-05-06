#!/usr/bin/env python3

import scapy.all as netscan
import argparse

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_check = netscan.ARP(pdst=ip)
    broadcast = netscan.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_cb = broadcast/arp_check
    answered = netscan.srp(arp_cb, timeout=1, verbose=False)[0]
    clients_list=[]
    for i in answered:
        clients_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        clients_list.append(clients_dict)
        
    return clients_list

def resultp(result_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------------")
    for client in result_list:
        print(client["ip"]+ "\t\t" + client["mac"])
      
    
arg_opt = arguments()
scan_result=scan(arg_opt.target)
resultp(scan_result)
