import os
import argparse
import re
import pdb
import cPickle as pickle
from decimal import *
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta
import math
import sketch
import idsTSA
import trustguard
import idsPattern
import idsFlow

REG =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: (?P<proto>(tcp|TCP|udp|UDP|icmp|ICMP))( |, length )(?P<size>\d+){0,1}"

REG_MAC = "(?P<ts>\d+\.\d+) (?P<msrc>(\d|\w{1,2}:){5}(\d|\w){1,2}) > (?P<mdst>((\d|\w){1,2}:){5}(\d|\w){1,2}), IPv4,( | length )(?P<len>\d+){0,1}: (?P<src>(\d{1,3}\.){3}\d{1,3})\.(?P<sport>\d+){0,1} > (?P<dst>(\d{1,3}\.){3}\d{1,3})\.(?P<dport>\d+){0,1}: (?P<proto>tcp|TCP|udp|UDP|icmp|ICMP) (?P<size>\d+){0,1}"

TS = "ts"
SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"

ETHSRC = "msrc"
ETHDST = "mdst"

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
    try:
        msrc = res.group(ETHSRC)
        mdst = res.group(ETHDST)
        return ts, src, sport, dst, dport, msrc, mdst

    except AttributeError:
        pass
    return ts, src, sport, dst, dport

def run(dirname, period, attack_ip, exp=REG, attack_mac=None):
    listdir = sorted(os.listdir(dirname))
    params = Params()
    reg = re.compile(exp)
    period_size = timedelta(seconds=period)
    for trace in listdir:
        filename = os.path.join(dirname, trace)
        with open(filename, "r") as f:
            get_attack_period(f, period_size, attack_ip, params, reg, attack_mac)
    return params

def get_attack_period(f, period_size, attack_ip, params, reg, attack_mac=None):
    for line in f:
        res = getdata(reg, line)
        if not res:
            continue

        if len(res) == 5:

            ts, src, sport, dst, dport = res

        elif len(res) == 7:
            ts, src, sport, dst, dport, msrc, mdst = res

        if params.start is None:
            params.start = ts
            params.end = ts + period_size
            if ((src == attack_ip or dst == attack_ip) and
                    not params.found_in_period):
                params.add_period()
                params.found_in_period = True

            elif (attack_mac is not None and not params.found_in_period and 
                    (msrc == attack_mac or mdst == attack_mac)):
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

                elif (attack_mac is not None and not params.found_in_period and 
                        (msrc == attack_mac or mdst == attack_mac)):
                    params.add_period()
                    params.found_in_period = True

            else:
                if ((src == attack_ip or dst == attack_ip) and
                        not params.found_in_period):
                    params.add_period()
                    params.found_in_period = True

                elif (attack_mac is not None and not params.found_in_period and 
                        (msrc == attack_mac or mdst == attack_mac)):
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

def evaluate_pattern_ids(indir, attacker_ip):
    period = 15

    params = run(indir, period, attacker_ip)
    attack_interval = set(params.attack_periods)
    tmp = set([i for i in xrange(params.period)])
    normal_interval = tmp.difference(attack_interval)


    tpr_list = []
    fpr_list = []

    thresh_match = 0.7
    thresh_alert = [0.1, 0.2, 0.3, 0.4, 0.5]

    for t in thresh_alert:
        ids = idsPattern.PatternIDS(indir, re.compile(REG), period=period,
                                    tresh_match=0.7, tresh_alert=t)
        ids.run()
        detected_atk = ids.mal_interval
        tmp = set([i for i in xrange(ids.current_interval)])
        detected_norm = tmp.difference(detected_atk)
        tpr, fpr = get_ids_metrics(attack_interval, normal_interval,
                                   detected_atk, detected_norm)

        print("TPR:{}, FPR:{}".format(tpr, fpr))
        tpr_list.append(tpr)
        fpr_list.append(fpr)
    return tpr_list, fpr_list

def evaluate_flow_ids(indir, mac_dir, attack_ip, attacker_mac):
    period = 300
    
    training = 5

    params = run(mac_dir, period, "", exp=REG_MAC, attack_mac=attacker_mac)
    attacker_interval = set(params.attack_periods)
    tmp = set([i for i in xrange(params.period)])
    normal_interval = tmp.difference(attacker_interval)

    tpr_list = []
    fpr_list = []

    maxps_s = [6.607, 8.58]
    maxipt_s = [6.075, 5.66]

    for mps, mipt in zip(maxps_s, maxipt_s):

        ids = idsFlow.FlowIDS(indir, re.compile(REG), period=period, ip=attack_ip,
                              number_seen=training, syn=False, maxps=mps,
                              maxipt=mipt)
        ids.run_detection()
        detected_atk = ids.mal_interval
        tmp = set([i for i in xrange(ids.current_interval)])
        detected_norm = tmp.difference(detected_atk)
        tpr, fpr = get_ids_metrics(attacker_interval, normal_interval, detected_atk,
                                   detected_norm)

        print("TPR: {}, FPR:{}".format(tpr, fpr))
    tpr_list.append(tpr)
    fpr_list.append(fpr)
    return tpr_list, fpr_list
    
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
    thresh_sum_upper_s = [70, 50, 20, 10, 5]
    for i in xrange(nbr_round):
        span = 900#span_s[i]
        N = math.ceil(span/interval_size)
        alpha = float(2)/(N+1)
        cthresh = 1.5 #cthresh_s[i]
        csum = 5#csum_s[i]
        big_M = 20#big_M_s[i]
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

def evaluate_trustguard(indir, attacker_ip):
    interval_size=60
    params = run(indir, interval_size, attacker_ip)
    attack_interval = set(params.attack_periods)
    tmp = set([i for i in xrange(params.period)])
    normal_interval = tmp.difference(attack_interval)

    tpr_list = []
    fpr_list = []

    threshs = [0.1, 0.2, 0.3, 0.4, 0.5, 0.8]

    for t in threshs:
        ids = trustguard.TrustGuard(reg=re.compile(REG), period_size=interval_size,
                                    pkt_bins=trustguard.PKT_SIZE_LVL, quiet=True, thresh=t)

        ids.run(indir)
        detected_atk = set(ids.mal_interval)
        tmp = set([i for i in xrange(ids.current_interval)])
        detected_norm = tmp.difference(detected_atk)
        tpr, fpr = get_ids_metrics(attack_interval, normal_interval,
                                   detected_atk, detected_norm)
        print("TPR: {}, FPR:{}".format(tpr, fpr))
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

def main(attacker_ip, mode, attacker_mac=None):

    flow_ids_dir = ["./2hour_seq_spur"]
    mac_ids_dir = ["./2hours_seq_spur_mac"]

    dirs = [
            "./2hours_real",
            "./2hours_short_scan",
            "./2hours_short_scan2",
            "./2hours_short_scan3",
            "./2hours_short_scan4"
            ]

    markers = ["-o", "--x", ":1", "-.d", "^:"]

    labels = ["trace{}".format(i+1) for i in range(len(dirs))]

    print("Evaluating IDS Flow")
    tprs = []
    fprs = []
    if mode == "w" or mode == "c":
        assert attacker_mac is not None
        for indir, macdir in zip(flow_ids_dir, mac_ids_dir):
            tpr, fpr = evaluate_flow_ids(indir, macdir, attacker_ip, attacker_mac) 
            tprs.append(tpr)
            fprs.append(fpr)
        if mode == "w":
            pickle.dump((tprs, fprs), open("eval_flow", "wb"))
    elif mode == "r":
        tprs, fprs = pickle.load("eval_flow", "rb")

    i = 0
    for tpr, fpr in zip(tprs, fprs):
        plt.plot(fpr, tpr, markers[i], label=labels[i])
        i += 1

    plt.xlabel("False Positive Rate")
    plt.ylabel("Detection Rate")
    plt.title("Receiver Operating Characteristic")
    plt.legend(loc="center right")
    plt.show()

    """
    print("Evaluating IDS Pattern")
    tprs = []
    fprs = []
    if mode == "w" or mode == "c":
        for i, indir in enumerate(dirs):
            tpr, fpr = evaluate_pattern_ids(indir, attacker_ip)
            tprs.append(tpr)
            fprs.append(fpr)

        if mode == "w":
            pickle.dump((tprs, fprs), open("eval_pattern", "wb"))
    elif mode == "r":
        tprs, fprs = pickle.load("eval_pattern", "rb")

    i = 0

    for tpr, fpr in zip(tprs, fprs):
        plt.plot(fpr, tpr, markers[i], label=labels[i])
        i += 1

    plt.xlabel("False Positive Rate")
    plt.ylabel("Detection Rate")
    plt.title("Receiver Operating Characteristic")
    plt.legend(loc="center right")
    plt.show()
    """

    """
    print("Evaluating TSA")
    if mode == "w" or mode == "c":
        tprs = []
        fprs = []

        for i, indir in enumerate(dirs):
            ewma_tpr, ewma_fpr = evaluate_ts_ids(indir, attacker_ip)
            tprs.append(ewma_tpr)
            fprs.append(ewma_fpr)

        if mode == "w":
            pickle.dump((tprs, fprs), open("eval_tsa", "wb"))

    elif mode == "r":
        tprs, fprs = pickle.load("eval_tsa", "rb")

    i = 0
    for tpr, fpr in zip(tprs, fprs):
        plt.plot(fpr, tpr, markers[i], label=labels[i])
        i += 1

    plt.xlabel("False Positive Rate")
    plt.ylabel("Detection Rate")
    plt.title("Receiver Operating Characteristic")
    plt.legend(loc="center right")
    plt.show()
    """

    """
    print("Evaluating Sketch")
    lab_loc = np.arange(len(dirs))
    width = 0.35

    if mode == "w" or mode = "c":

        tpr_means = []
        fpr_means = []
        tpr_errors = []
        fpr_errors = []

        for i, indir in enumerate(dirs):
            tpr, etpr, fpr, efpr = evaluate_sketch_ids(indir, attacker_ip, True, nbr_round=7)
            print("TPR:{}, FPR:{}".format(tpr, fpr))
            tpr_means.append(tpr)
            tpr_errors.append(etpr)
            fpr_means.append(fpr)
            fpr_errors.append(efpr)

        if mode == "w":
        
            pickle.dump((tpr_means, fpr_means, tpr_errors, fpr_errors),
                        open("eval_sketch", "rb"))

    elif mode == "r":

        (tpr_means, fpr_means, tpr_errors, fpr_errors) = pickle.load("eval_sketch", "rb")
          
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

    """
    print("Evaluation TrustGuard")
    tprs = []
    fprs = []

    if mode == "w" or mode == "c":

        for i, indir in enumerate(dirs):
            tpr, fpr = evaluate_trustguard(indir, attacker_ip)
            tprs.append(tpr)
            fprs.append(fpr)
            print("Done dir {}".format(indir))

        if mode == "c":

            pickle.dump((tprs, fprs), open("eval_trustguard_small_inter.bin", "wb"))

    elif mode == "r":
        tprs, fprs = pickle.load(open("eval_trustguard_small_inter.bin", "rb"))

    i = 0
    for tpr, fpr in zip(tprs, fprs):
        plt.plot(fpr, tpr, markers[i], label=labels[i])
        i +=1

    plt.legend(loc="center right")
    plt.xlabel("False Positive Rate")
    plt.ylabel("Detection Rate")
    plt.title("Receiver Operating Characteristic")
    plt.show()
    """

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--atkip", type=str, dest="atkip")
    parser.add_argument("--atkmac", type=str, dest="atkmac")
    parser.add_argument("--mode", type=str, choices=["r","w", "c"], dest="mode")

    args = parser.parse_args()
    atkip = args.atkip
    atkmac = args.atkmac
    mode = args.mode
    
    main(atkip, mode, atkmac)
