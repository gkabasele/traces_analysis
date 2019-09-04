import os
import argparse
import re
import pdb
from datetime import datetime, timedelta

import sketch
import idsTSA

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
        self.found_in_period = False
        self.attack_periods = []

    def add_period(self):
        self.attack_periods.append(self.period)

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
    for trace in listdir:
        filename = os.path.join(dirname, trace)
        with open(filename, "r") as f:
            get_attack_period(f, period_size, attack_ip, params, reg)
    return params

def get_attack_period(f, period_size, attack_ip, params, reg):
    for line in f:
        res = getdata(reg, line)
        if not res:
            continue

        ts, src, sport, dst, dport = res

        if params.start is None:
            params.start = ts
            params.end = ts + period_size
            if ((src == attack_ip or dst == attack_ip) and
                    not params.found_in_period):
                params.add_period()
                params.found_in_period = True
        else:
            if ts >= params.end:
                params.found_in_period = False
                params.period += 1
                params.start = params.end
                params.end = params.start + period_size
                if ((src == attack_ip or dst == attack_ip) and
                        not params.found_in_period):
                    params.add_period()
                    params.found_in_period = True
            else:
                if ((src == attack_ip or dst == attack_ip) and
                        not params.found_in_period):
                    params.add_period()
                    params.found_in_period = True

def main(indir, period, attacker_ip):
    #ground truth
    params = run(indir, period, attacker_ip)
    attack_interval = set(params.attack_periods)
    tmp = set([i for i in xrange(params.period)])
    normal_interval = tmp.difference(attack_interval)

    ids = sketch.SketchIDS(reg=re.compile(REG), nrows=5, ncols=100, n_last=5,
                           alpha=4, beta=0.7, training_period=20, thresh=3,
                           consecutive=3, period=period, quiet=True)

    ids.run(indir)
    detected_atk = set(ids.mal_interval)
    tmp = set([i for i in xrange(ids.current_interval)])
    detected_norm = tmp.difference(detected_atk)

    true_positive = attack_interval.intersection(detected_atk)
    false_positive = detected_atk.difference(attack_interval)

    true_negative = normal_interval.intersection(detected_norm)
    false_negative = detected_norm.difference(normal_interval)

    tp = len(true_positive)
    fp = len(false_positive)

    tn = len(true_negative)
    fn = len(false_negative)

    tpr = float(tp)/(tp + fn)
    fpr = float(fn)/(tn + fp)

    print("TPR:{}, FPR:{}".format(tpr, fpr))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")
    parser.add_argument("--atk", type=str, dest="atk")

    parser.add_argument("--period", type=int, dest="period")
    args = parser.parse_args()
    indir = args.indir
    atk = args.atk
    period = args.period
    main(indir, period, atk)
