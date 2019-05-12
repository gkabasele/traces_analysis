import argparse
import os
import random
import time
import logging
import csv
import socket
import threading
import Queue
import errno
from subprocess import Popen, PIPE
from ipaddress import IPv4Address, ip_address, ip_network


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
log_name = '../logs/attack_scanner.log'
if os.path.exists(log_name): 
    os.remove(log_name)
file_handler = logging.FileHandler(filename=log_name)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

parser = argparse.ArgumentParser()
parser.add_argument("--net", type=str, dest="net", action="store")
parser.add_argument("--size", type=int, dest="size", action="store")
parser.add_argument("--inter", type=float, dest="inter", action="store")
parser.add_argument("--nbr", type=int, dest="nbr", action="store")

args = parser.parse_args()

inter = args.inter
size = args.size
range_ip = ip_network(unicode(args.net)).hosts()
nbr_port = args.nbr

socket.setdefaulttimeout(5)
print_lock = threading.Lock()

def host_is_alive(ip):
    cmd = ["ping", "-c", "1", str(ip)]
    out, err = Popen(cmd, stdout=PIPE).communicate()
    return ("1 received" in out)

def portscan(server_ip, server_port, logger):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((server_ip, server_port))
        with print_lock:
            logger.debug("%s is open", server_port) 
        s.close()
    except socket.error as err:
        if err.errno == errno.ECONNREFUSED:
            pass
        else:
            logger.error("%s", err)

def threader(server_ip, inter, q, logger):
    while True:
        worker = q.get()
        portscan(server_ip, worker, logger)
        q.task_done()
        if inter != 0:
            time.sleep(inter)

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

#ARPTABLE = get_arp_table()
#dst_mac = get_mac(ARPTABLE, dip)

#logger.debug("ARP table: %s", ARPTABLE)

for _ in range(size):
    ip = str(next(range_ip))
    if host_is_alive(ip):
        q = Queue.Queue()
        logger.debug("Host %s is alive", ip)
        for x in range(10):
            t = threading.Thread(target=threader, args=(ip, inter, q, logger))
            t.daemon = True
            t.start()
        logger.debug("Running scan attack on host %s", ip)
        for worker in range(2, nbr_port):
            q.put(worker)
        q.join()
    time.sleep(5)
