#!/usr/bin/python3
# Author: Dahir Muhammad Dahir
# Date: 28-04-2019 10:44 PM
# This module requires scapy

from scapy.layers.inet import ICMP
from scapy.all import *

interface = input("name of interface\n>>> ")


def main():
    sniff(iface=interface, filter="icmp", prn=process_packet)


def process_packet(pkt):
    if pkt[ICMP].type == 8:
        data = chr(pkt[ICMP].load[-8])
        print(data, end="", flush=True)


if __name__ == "__main__":
    main()
