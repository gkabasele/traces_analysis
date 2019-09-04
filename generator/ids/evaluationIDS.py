import os
import argparse
import re
import pdb
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import math
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


def get_ids_metrics(attack_interval, normal_interval, detected_atk,
                    detected_norm):

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

    return tpr, fpr

def evaluate_sketch_ids(indir, attacker_ip, nbr_round=5):
    period = 60
    params = run(indir, period, attacker_ip)
    attack_interval = set(params.attack_periods)
    tmp = set([i for i in xrange(params.period)])
    normal_interval = tmp.difference(attack_interval)

    tpr_list = []
    fpr_list = []

    beta_s = [0.1, 0.4, 0.5, 0.7, 0.9]
    thresh_s = [1, 2, 3, 4, 5]
    for i in xrange(nbr_round):
        ids = sketch.SketchIDS(reg=re.compile(REG), nrows=5, ncols=100, n_last=5,
                               alpha=4, beta=beta_s[i], training_period=20,
                               thresh=thresh_s[i], consecutive=3,
                               period=period, quiet=True)
        ids.run(indir)
        detected_atk = set(ids.mal_interval)
        tmp = set([i for i in xrange(ids.current_interval)])
        detected_norm = tmp.difference(detected_atk)
        tpr, fpr = get_ids_metrics(attack_interval, normal_interval,
                                   detected_atk, detected_norm)

        print("TPR:{}, FPR:{}".format(tpr, fpr))

        tpr_list.append(tpr)
        fpr_list.append(fpr)

    return tpr_list, fpr_list

def evaluate_ts_ids(indir, attacker_ip, nbr_round=5):
    interval_size = 5
    params = run(indir, interval_size, attacker_ip)
    attack_interval = set(params.attack_periods)
    tmp = set([i for i in xrange(params.period)])
    normal_interval = tmp.difference(attack_interval)

    tpr_list = []
    fpr_list = []

    exporter = idsTSA.FlowCreationCounter(interval_size, re.compile(REG), indir)
    ts_creation_flow = exporter.new_flow_ts()
    span_s = [30, 70, 90, 110, 150]
    cthresh_s = [1.5, 2, 3, 5, 7]
    csum_s = [3, 4, 5, 6, 7]
    big_M_s = [10, 20, 30, 40, 50]
    thresh_sum_upper_s = [50, 500, 5000, 50000, 500000]
    for i in xrange(nbr_round):
        span = span_s[i]
        N = math.ceil(span/interval_size)
        alpha = float(2)/(N+1)
        cthresh = cthresh_s[i]
        csum = csum_s[i]
        big_M = big_M_s[i]
        thresh_sum_upper = thresh_sum_upper_s[i]
        analyzer = idsTSA.TSAnalyzer(alpha, cthresh, big_M, csum, N,
                                     thresh_sum_upper)
        analyzer.run(ts_creation_flow)

        detected_atk = set(analyzer.mal_interval)
        tmp = set([i for i in xrange(analyzer.current_period)])
        detected_norm = tmp.difference(detected_atk)

        tpr, fpr = get_ids_metrics(attack_interval, normal_interval,
                                   detected_atk, detected_norm)

        print("TPR:{}, FPR:{}".format(tpr, fpr))
        tpr_list.append(tpr)
        fpr_list.append(fpr)

    return tpr_list, fpr_list

def main(indir, attacker_ip):

    sketch_tpr, sketch_fpr = evaluate_sketch_ids(indir, attacker_ip)
    ewma_tpr, ewma_fpr = evaluate_ts_ids(indir, attacker_ip)

    plt.plot(sketch_fpr, sketch_tpr, 'o', label="sketch")
    plt.plot(ewma_fpr, ewma_tpr, 'o', label="ewma")

    plt.legend(loc="upper right")

    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")
    parser.add_argument("--atk", type=str, dest="atk")

    args = parser.parse_args()
    indir = args.indir
    atk = args.atk
    main(indir, atk)
