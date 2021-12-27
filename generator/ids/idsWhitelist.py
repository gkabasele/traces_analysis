import os
import pdb
import re
import argparse
from datetime import datetime
from datetime import timedelta
from collections import namedtuple
from idsFlow import TS
from idsFlow import SRC
from idsFlow import DST
from idsFlow import SPORT
from idsFlow import DPORT
from idsFlow import PROTO
from idsFlow import REG
from evaluationIDS import REG_MAC
from evaluationIDS import ETHSRC
from evaluationIDS import ETHDST

Flow = namedtuple("Flow", "{} {} {} {} {}".format(SRC, SPORT, DST, DPORT, PROTO))

def getdata(reg, line):
    res = reg.match(line)
    ts = datetime.fromtimestamp(float(res.group(TS)))
    src = res.group(SRC)
    dst = res.group(DST)
    sport = res.group(SPORT)
    dport = res.group(DPORT)
    proto = res.group(PROTO)
    try:
        msrc = res.group(ETHSRC)
        mdst = res.group(ETHDST)
        return ts, src, sport, dst, dport, proto, msrc, mdst
    except AttributeError:
        pass
    except IndexError:
        pass
         
    return ts, src, sport, dst, dport, proto


class WhitelistIDS(object):

    def __init__(self, dirname, learning_trace, duration, match):
        self.dirname = dirname
        self.learning_trace = learning_trace
        self.duration = timedelta(seconds=duration)
        self.whitelist = set()
        self.reg = match
        self.alerts = set()
        self.legit = set()
        self.nbr_learn = 0
        self.nbr_pkts = 0

    
    def create_flow(self, flow_tuple):
        ts, src, sport,dst,dport, proto = flow_tuple
        return ts, Flow(src, sport, dst, dport, proto)

    def build_whitelist(self):
        start = None
        listdir = sorted(os.listdir(self.learning_trace))
        for trace in listdir:
            filename = os.path.join(self.learning_trace, trace)
            with open(filename, "r") as f:
                for line in f:
                    res = getdata(self.reg, line)
                    if not res:
                        continue
                    self.nbr_learn += 1
                    ts, flow = self.create_flow(res)
                    if start is None:
                        start = ts
                    if ts <= start + self.duration:
                        self.whitelist.add(flow)
                    else:
                        return


    def run_detection(self):
        listdir = sorted(os.listdir(self.dirname))
        for trace in listdir:
            filename = os.path.join(self.dirname, trace)
            with open(filename, "r") as f:
                for line in f:
                    res = getdata(self.reg, line)
                    if not res:
                        continue
                    ts, flow = self.create_flow(res)
                    self.nbr_pkts += 1
                    if flow not in self.whitelist:
                        self.alerts.add((ts,flow))
                    else:
                        self.legit.add((ts,flow))


def get_malicious_packets(indir, reg, atk_ip, atk_mac=None):
    listdir = sorted(os.listdir(indir))
    attack_pkts = set()
    normal_pkts = set()
    fail = 0
    for trace in listdir:
        filename = os.path.join(indir, trace)
        with open(filename, "r") as f:
            for line in f:
                res = getdata(reg, line)
                if not res:
                    continue

                if len(res) == 6:
                    ts, src, sport, dst, dport, proto = res
                elif len(res) == 8:
                    ts, src, sport, dst, dport, proto, msrc, mdst = res

                flow = Flow(src, sport, dst, dport, proto)

                if atk_mac is None:
                    if src == atk_ip or dst == atk_ip:
                        attack_pkts.add((ts,flow))
                    else:
                        normal_pkts.add((ts,flow))

                else:
                    if msrc == atk_mac or mdst == atk_mac:
                        attack_pkts.add((ts,flow))
                    else:
                        normal_pkts.add((ts,flow))
    return normal_pkts, attack_pkts

def main(indir, learning_trace, duration, atk_ip, atk_mac=None):
    if atk_mac is None:
        reg = re.compile(REG)
    else:
        reg = re.compile(REG_MAC)

    normal_pkts, atk_packets = get_malicious_packets(indir, reg, atk_ip, atk_mac)
    reg = re.compile(REG)
    ids = WhitelistIDS(indir, learning_trace, duration, reg)
    ids.build_whitelist()
    """
    print("Size whitelist:{}, #PKTS:{}".format(len(ids.whitelist),
                                               ids.nbr_learn))
    """
   
    ids.run_detection()
    """
    print("#PKTS:{}, Norm:{}, Atk:{}".format(ids.nbr_pkts,
                                            len(normal_pkts),
                                            len(atk_packets)))
    """

    #pdb.set_trace()

    true_negatives = len(normal_pkts.intersection(ids.legit))
    true_positives = len(atk_packets.intersection(ids.alerts))
    false_positives = len(ids.alerts.difference(atk_packets))
    false_negatives = len(atk_packets.intersection(ids.legit))

    total = (true_positives + true_negatives
             + false_positives + false_negatives)

    #print("Total: {}".format(total))

    fpr = float(false_positives)/(false_positives + true_negatives)
    tpr = float(true_positives)/(true_positives + false_negatives)
    """
    print("TN:{}, FN:{}, TP:{}, FP:{}".format(true_negatives,
                                              false_negatives,
                                              true_positives,
                                              false_positives))
    print("TPR:{}, FPR:{}".format(tpr,fpr))
    """

    return tpr, fpr

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")
    parser.add_argument("--learning", type=str, dest="learning")
    parser.add_argument("--ip", type=str, dest="atk_ip")
    parser.add_argument("--duration", type=int, dest="duration")

    args = parser.parse_args()
    atk_ip = args.atk_ip
    indir = args.indir
    learning = args.learning
    for duration in [8, 360, 720, 1800, 3600, 7200]:
        tpr, fpr = main(indir, learning, duration, atk_ip)
        print("Duration: {}, TPR:{}, FPR:{}".format(duration, tpr, fpr))
