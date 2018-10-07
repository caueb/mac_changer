#!/usr/bin/env python
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="Target IP address")
    options = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify a target IP, use --help for more info")
    return options

def scan(ip, mac):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []

    for element in answered_list:
        client_list = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_list)
    return clients_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.ip, "ff:ff:ff:ff:ff:ff:")
print_result(scan_result)