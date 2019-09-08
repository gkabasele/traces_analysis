import os
import re
import argparse
import time
from subprocess import Popen, call, PIPE
from subprocess import check_output
import numpy as np
import scipy.stats as stats
import matplotlib.pyplot as plt
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.clean import cleanup

from autocorr import REG_FLOW
from autocorr import update_flow_txt

NORM = "norm"
GAMMA = "gamma"
CAUCHY = "cauchy"
EXPON = "expon"
POI = "poisson"
UNI = "uniform"
WEIB = "weibull"

RECV_CMD = "~/D-ITG-2.8.1-r1023/bin/ITGRecv" 
SEND_CMD = "~/D-ITG-2.8.1-r1023/bin/ITGSend"
HOURS_IN_MILLIS = "7200000"
THREE_MIN = "180"

class SingleSwitchTopo(Topo):
    "Single switch connected to 2 host"

    def build(self, n=2):
        switch = self.addSwitch("s1")
        for h in range(n):
            host = self.addHost('h%s' % (h+1))
            self.addLink(host, switch)

def simpleTest(nbr, mean_pkt_size, dist, params):
    "Create and test a simple network)"
    topo = SingleSwitchTopo(4)
    net = Mininet(topo)
    net.start()
    hosts = net.hosts

    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")
    net.pingAll()

    CLI(net)
    """
    receiver = hosts[0]
    recv_cmd = [RECV_CMD]
    print(recv_cmd)
    capt_cmd = ["sudo", "tcpdump", "-i", "h1-eth0", "-w",
                "ditg-{}.pcap".format(dist)]
    print("Running receiver")
    recv_popen = receiver.popen(recv_cmd, stdout=PIPE, shell=True)

    print("Running capture")
    capt_popen = receiver.popen(capt_cmd, stdout=PIPE, shell=True)

    time.sleep(1)

    sender = hosts[1]
    send_cmd = [SEND_CMD, "-a", "10.0.0.1", "-T", "TCP", "-z", nbr, "-t",
                THREE_MIN, "-c", mean_pkt_size, "-%s"%dist]

    if len(params) > 2:
        tmp = [str(int(params[i])) for i in range(1, len(params))]
    else:
        tmp = [str(int(i)) for i in params]

    send_cmd.extend(tmp)
    print(send_cmd)
    print("Running Sender")
    send_popen = sender.popen(send_cmd, stdout=PIPE, shell=True)

    try:
        send_popen.wait()
    except Exception:
        pass
    finally:
        capt_popen.kill()
        recv_popen.kill()
    """
    net.stop()
    cleanup()

def run(indir):
    listdir = sorted(os.listdir(indir))
    flows = {}
    for trace in listdir:
        filename = os.path.join(indir, trace)
        with open(filename, "r") as f:
            update_flow_txt(f, flows, re.compile(REG_FLOW))
    return flows

def plot_cdf(data, lab):
    x = np.sort(data)
    n = x.size
    y = np.arange(1, n+1)/float(n)
    plt.plot(x, y, label=lab)

def process_dist(data, min_val, max_val):
    for i in xrange(len(data)):
        if data[i] < min_val:
            data[i] = min_val
        elif data[i] > max_val:
            data[i] = max_val

def write_dist_to_file(data, filename):
    with open(filename, "w") as f:
        for idt in data:
            f.write("{}\n".format(idt))

def get_dist_params(rdata, gdata, data_persec, dparams, title, plot=True,
                    write=True):

    plot_cdf(rdata, 'data')

    plot_cdf(gdata, 'gen')

    N = len(rdata)

    min_val = np.min(rdata)
    max_val = 1.5*np.max(rdata)
    print("Length data: {}".format(N))

    print("Fitting Normal")
    fit_loc, fit_scale = stats.norm.fit(rdata)
    dparams[NORM] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    norm_data = stats.norm.rvs(loc=fit_loc, scale=fit_scale, size=N)
    process_dist(norm_data, min_val, max_val)  
    if write:
        write_dist_to_file(norm_data, "norm_idt.txt")
    if plot:
        plot_cdf(norm_data, lab='norm')

    print("Fitting Gamma")
    fit_alpha, fit_loc, fit_scale = stats.gamma.fit(rdata)
    dparams[GAMMA] = (fit_alpha, fit_loc, fit_scale)
    print("alpha:{}, loc:{}, scale:{}".format(fit_alpha, fit_loc,
                                             fit_scale))
    #gamma_data = stats.gamma.rvs(fit_alpha, loc=fit_loc,
    #                             scale=fit_scale, size=N)
    gamma_data = stats.gamma.rvs(fit_alpha, scale=fit_scale, size=N)
    process_dist(gamma_data, min_val, max_val)
    if write:
        write_dist_to_file(gamma_data, "gamma_idt.txt")
    if plot:
        plot_cdf(gamma_data,
                 lab='gamma')

    print("Fitting Cauchy")
    fit_loc, fit_scale = stats.cauchy.fit(rdata)
    dparams[CAUCHY] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    cauchy_data = stats.cauchy.rvs(loc=fit_loc, scale=fit_scale, size=N)
    process_dist(cauchy_data, min_val, max_val)
    if write:
        write_dist_to_file(cauchy_data, "cauchy_idt.txt")
    if plot:
        plot_cdf(cauchy_data,
                 lab='cauchy')

    print("Fitting Exponential")
    fit_loc, fit_scale = stats.expon.fit(rdata)
    dparams[EXPON] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    print("PPS mean:{}".format(np.mean(data_persec)))
    expon_data = stats.expon.rvs(loc=fit_loc, scale=fit_scale, size=N)
    process_dist(expon_data, min_val, max_val)
    if write:
        write_dist_to_file(cauchy_data, "expon_idt.txt")
    if plot:
        plot_cdf(expon_data,
                 lab='expon')

    print("Fitting Poisson")
    fit_lambda = np.mean(rdata)
    dparams[POI] = (fit_lambda,)
    print("lambda: {}".format(fit_lambda))
    print("PPS mean:{}".format(np.mean(data_persec)))
    poi_data = stats.poisson.rvs(fit_lambda, size=N)
    process_dist(poi_data, min_val, max_val)
    if write:
        write_dist_to_file(poi_data, "poi_idt.txt")
    if plot:
        plot_cdf(poi_data,
                 lab='poisson')

    print("Uniform distribution")
    fit_loc, fit_scale = stats.uniform.fit(rdata)
    dparams[UNI] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    uni_data = stats.uniform.rvs(loc=fit_loc, scale=fit_scale, size=N)
    process_dist(uni_data, min_val, max_val)
    if write:
        write_dist_to_file(uni_data, "uni_idt.txt")
    if plot:
        plot_cdf(uni_data,
                 lab='uniform')

    print("Weibull distribution")
    fit_c, fit_loc, fit_scale = stats.weibull_min.fit(rdata)
    dparams[WEIB] = (fit_c, fit_loc, fit_scale)
    print("Min, c: {}, loc:{}, scale:{}".format(fit_c, fit_loc,
                                                fit_scale))
    wei_data = stats.weibull_min.rvs(fit_c, loc=fit_loc, scale=fit_scale, size=N)
    process_dist(wei_data, min_val, max_val)
    if write:
        write_dist_to_file(wei_data, "wei_idt.txt")
    if plot:
        plot_cdf(wei_data,
                 lab='wei_min')

    #fit_c, fit_loc, fit_scale = stats.weibull_max.fit(rdata)
    #print("Max, c: {}, loc:{}, scale:{}".format(fit_c, fit_loc,
    #                                            fit_scale))
    #plot_cdf(stats.weibull_max.rvs(fit_c, loc=fit_loc, scale=fit_scale, size=N),
    #         lab='wei_max')

    #ps_fit_beta, fit_loc, fit_scale = stats.pareto.fit(ps, floc=0)
    #print("Fitting Pareto")
    #print("beta:{}, loc:{}, scal:{}".format(ps_fit_beta, fit_loc,
    #                                        fit_scale))
    if plot:
        plt.title(title)
        plt.legend(loc="upper right")
        plt.show()

def main(indir, gendir, r_src, r_dst, sport, dport, g_src, g_dst):

    flows_r = run(indir)
    flows_g = run(gendir)
    proto = 'tcp'
    flow_r = (r_src, sport, proto, r_dst, dport)
    flow_g = (g_src, sport, proto, g_dst, dport)
    rev_flow_r = (r_dst, dport, proto, r_src, sport)
    st_r = flows_r[flow_r]
    rev_st_r = flows_r[rev_flow_r]
    st_g = flows_g[flow_g]

    ps = np.array(st_r.ps)
    ipt = np.array(st_r.ipt)
    pps = np.array(st_r.pps)

    ps_g = np.array(st_g.ps)
    ipt_g = np.array(st_g.ipt)
    pps_g = np.array(st_g.pps)


    title = "IPT Distbribution"
    dist_ipt = {NORM:None, GAMMA:None, CAUCHY:None, EXPON:None, POI:None,
                UNI:None, WEIB:None}

    dist_ps = {NORM:None, GAMMA:None, CAUCHY:None, EXPON:None, POI:None,
               UNI:None, WEIB:None}

    get_dist_params(ipt, ipt_g, pps, dist_ipt, title, plot=False, write=False)
    
    #nbr = str(len(ps) + 1)
    nbr = "100"
    mean_pkt_size = str(int(np.mean(ps)))
    dist_arg = 'G'

    simpleTest(nbr, mean_pkt_size, dist_arg, dist_ipt[GAMMA])

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--realdir", type=str, dest="realdir", action="store")
    parser.add_argument("--gendir", type=str, dest="gendir", action="store")
    parser.add_argument("--rsrc", type=str, default="192.168.246.45",
                        dest="rsrc", action="store")
    parser.add_argument("--rdst", type=str, default="192.168.246.228",
                        dest="rdst", action="store")
    parser.add_argument("--gsrc", type=str, default="10.0.0.3", dest="gsrc")
    parser.add_argument("--gdst", type=str, default="10.0.0.1", dest="gdst")
    parser.add_argument("--sport", type=str, default="2499",
                        dest="sport", action="store")
    parser.add_argument("--dport", type=str, default="55434",
                        dest="dport", action="store")

    args = parser.parse_args()
    main(args.realdir, args.gendir, args.rsrc, args.rdst, args.sport, args.dport,
         args.gsrc, args.gdst)
