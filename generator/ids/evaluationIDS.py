import os
import argparse
import re
import pdb
from decimal import *
import matplotlib.pyplot as plt
import numpy as np
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

    # among all the attack, how many were detected
    try:
        tpr = float(tp)/(tp + fn)
    except ZeroDivisionError:
        tpr = 0        

    #among all alarm raise, ratio of the one being meaningfull
    try:
        fpr = float(fp)/(tp + fp)
    except ZeroDivisionError:
        fpr = 0

    return tpr, fpr

def evaluate_sketch_ids(indir, attacker_ip, take_last, nbr_round=5):
    period = 60
    params = run(indir, period, attacker_ip)
    attack_interval = set(params.attack_periods)
    tmp = set([i for i in xrange(params.period)])
    normal_interval = tmp.difference(attack_interval)

    tpr_list = []
    fpr_list = []

    for i in xrange(nbr_round):
        ids = sketch.SketchIDS(reg=re.compile(REG), nrows=5, ncols=100,
                               n_last=5,alpha=4, beta=0.7, 
                               training_period=15,thresh=3, consecutive=1,
                               period=period, quiet=True, take_last=take_last)
        ids.run(indir)
        detected_atk = set(ids.mal_interval)
        tmp = set([i for i in xrange(ids.current_interval)])
        detected_norm = tmp.difference(detected_atk)
        tpr, fpr = get_ids_metrics(attack_interval, normal_interval,
                                   detected_atk, detected_norm)

        tpr_list.append(tpr)
        fpr_list.append(fpr)

    return np.mean(tpr_list), np.std(tpr_list), np.mean(fpr_list), np.std(fpr_list)


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
    cthresh_s = [0.5, 1.5, 2, 3, 5]
    csum_s = [1, 3, 4, 6, 7]
    big_M_s = [10, 20, 30, 40, 50]
    thresh_sum_upper_s = [70, 50, 20, 13, 5]
    for i in xrange(nbr_round):
        span = 900#span_s[i]
        N = math.ceil(span/interval_size)
        alpha = float(2)/(N+1)
        cthresh = 1.5 #cthresh_s[i]
        csum = 5#csum_s[i]
        big_M = 0#big_M_s[i]
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

def autolabel(ax, rects):
    form = '0.001'
    for rect in rects:
        height = rect.get_height()
        h = Decimal(height).quantize(Decimal(form), rounding=ROUND_UP) 
        ax.annotate('{}'.format(h),
                    xy=(rect.get_x() + rect.get_width()/2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')

def main(attacker_ip):

    dirs = [
            "./2hours_real",
            "./2hours_short_scan",
            "./2hours_short_scan2",
            "./2hours_short_scan3",
            "./2hours_short_scan4"
            ]

    markers = ["-o", "--x", ":1", "-.d", "^:"]

    """
    print("Evaluating TSA")

    for i, indir in enumerate(dirs):
        ewma_tpr, ewma_fpr = evaluate_ts_ids(indir, attacker_ip)
        plt.plot(ewma_fpr, ewma_tpr, markers[i],label ="trace{}".format(i+1))

    plt.xlabel("False Positive Rate")
    plt.ylabel("Detection Rate")
    plt.title("Receiver Operating Characteristic")
    plt.legend(loc="center right")
    plt.show()

    pdb.set_trace()
    """

    lab_loc = np.arange(len(dirs))
    width = 0.35

    tpr_means = []
    fpr_means = []
    tpr_errors = []
    fpr_errors = []
    labels = ["trace{}".format(i+1) for i in range(len(dirs))]

    print("Evaluating Sketch")
    for i, indir in enumerate(dirs):
        tpr, etpr, fpr, efpr = evaluate_sketch_ids(indir, attacker_ip, True, nbr_round=7)
        print("TPR:{}, FPR:{}".format(tpr, fpr))
        tpr_means.append(tpr)
        tpr_errors.append(etpr)
        fpr_means.append(fpr)
        fpr_errors.append(efpr)

    fig, ax = plt.subplots()

    rects1 = ax.bar(lab_loc - width/2, tpr_means, width, label='DR',
                    yerr=tpr_errors)
    rects2 = ax.bar(lab_loc + width/2, fpr_means, width, label='FPR',
                    yerr=fpr_errors)

    ax.set_ylabel('Rates')
    ax.set_title('DR and FPR by trace')
    ax.set_xticks(lab_loc)
    ax.set_xticklabels(labels)
    ax.legend()

    autolabel(ax, rects1)
    autolabel(ax, rects2)
    plt.show()

    """
    print("Evaluating Sketch")
    for i, indir in enumerate(dirs):
        tpr, fpr = evaluate_sketch_ids(indir, attacker_ip, False)
        print("TPR:{}, FPR:{}".format(tpr, fpr))
        tpr_means.append(tpr)
        fpr_means.append(fpr)

    fig, ax = plt.subplots()

    rects1 = ax.bar(lab_loc - width/2, tpr_means, width, label='DR')
    rects2 = ax.bar(lab_loc + width/2, fpr_means, width, label='FPR')

    ax.set_ylabel('Rates')
    ax.set_title('DR and FPR by trace')
    ax.set_xticks(lab_loc)
    ax.set_xticklabels(labels)
    ax.legend()

    autolabel(ax, rects1)
    autolabel(ax, rects2)
    plt.show()
    pdb.set_trace()
    """



if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--atk", type=str, dest="atk")

    args = parser.parse_args()
    atk = args.atk
    main(atk)
