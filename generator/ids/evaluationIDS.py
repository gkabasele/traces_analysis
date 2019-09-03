import os
import argparse
import re
from datetime import datetime, timedelta

REG =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: (?P<proto>(tcp|TCP|udp|UDP|icmp|ICMP))( |, length )(?P<size>\d+){0,1}"

TS = "ts"
SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"

class Params(object):

    def __init__(self):
        self.start = None
        self.end = None
        self.period = 0

def getdata(reg, line):
    res = reg.match(line)
    ts = datetime.fromtimestamp(float(res.group(TS)))
    src = res.group(SRC)
    dst = res.group(DST)
    sport = res.group(SPORT)
    dport = res.group(DPORT)
    return ts, src, sport, dst, dport

def run(dirname, period, attack_ip):
    listdir = sorted(os.listdir(dirname))
    params = Params()
    reg = re.compile(REG)
    period_size = timedelta(seconds=period)
    attack_periods = []
    for trace in listdir:
        filename = os.path.join(dirname, trace)
        with open(filename, "r") as f:
            get_attack_period(f, period_size, attack_periods, attack_ip, params, reg)
    return attack_periods

def get_attack_period(f, period_size, attack_periods, attack_ip, params, reg):
    for line in f:
        res = getdata(reg, line)
        if not res:
            continue

        ts, src, sport, dst, dport = res

        if params.start is None:
            params.start = ts
            params.end = ts + period_size
            if src == attack_ip or dst == attack_ip:
                attack_periods.append(params.period)
        else:
            if ts >= params.end:
                if src == attack_ip or dst == attack_ip:
                    attack_periods.append(params.period)
                params.period += 1
            else:
                if src == attack_ip or dst == attack_ip:
                    attack_periods.append(params.period)

def main(indir, period, attacker_ip):
    attack_periods = run(indir, period, attacker_ip)
    print(attack_periods) 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")
    parser.add_argument("--atk", type=str, dest="atk")

    parser.add_argument("--period", type=str, dest="period")
    args = parser.parse_args()
    indir = args.indir
    atk = args.atk
    period = args.period
    main(indir, period, atk)
