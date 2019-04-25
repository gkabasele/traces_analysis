import argparse
import random
import time
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("--sip", type=str, dest="sip", action="store")
parser.add_argument("--dip", type=str, dest="dip", action="store")
parser.add_argument("--dport", type=int, dest="dport", action="store")
parser.add_argument("--npkt", type=int, dest="npkt", action="store")
parser.add_argument("--inter", type=float, dest="inter", action="store")

args = parser.parse_args()

sip = args.sip
dip = args.dip
dport = args.dport
npkt = args.npkt
inter = args.inter

for _ in xrange(npkt):
    ip_hdr = IP(src = sip, dst = dip)
    sport = random.randint(1024, 65535)
    tcp_hdr = TCP(sport = sport, dport = dport)  
    pkt = ip_hdr/tcp_hdr
    send(pkt)
    time.sleep(inter)
