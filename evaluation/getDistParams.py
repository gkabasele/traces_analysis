import os
import re
import argparse
from subprocess import Popen, call, PIPE
from subprocess import check_output
import numpy as np
import scipy.stats as stats
import matplotlib.pyplot as plt
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections

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

class SingleSwitchTopo(Topo):
    "Single switch connected to 2 host"

    def build(self, n=2):
        switch = self.addSwitch("s1")
        for h in range(n):
            host = self.addHost('h%s' % (h+1))
            self.addLink(host, switch)

def simpleTest(nbr, mean_pkt_size, dist, params):
    "Create and test a simple network)"
    topo = SingleSwitchTopo(2)
    net = Mininet(topo)
    net.start()
    hosts = net.hosts
    receiver = hosts[0]
    sender = hosts[1]
    send_cmd = [SEND_CMD, "-T", "TCP", "-z", nbr, "-c", mean_pkt_size,
                "-%s"%dist]
    send_cmd.extend(params)
    recv_cmd = [RECV_CMD]

    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")
    net.pingAll()

    send_popen = sender.popen(send_cmd) 
    recv_popen = receiver.popen(recv_cmd)
    net.stop()

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

def plot_all(rdata, gdata, dparams, title, to_plot=True):

    plot_cdf(rdata, 'data')

    plot_cdf(gdata, 'gen')

    N = len(rdata)
    print("Length data: {}".format(N))

    print("Fitting Normal")
    fit_loc, fit_scale = stats.norm.fit(rdata)
    dparams[NORM] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    if to_plot:
        plot_cdf(stats.norm.rvs(loc=fit_loc, scale=fit_scale, size=N),
                 lab='norm')

    print("Fitting Gamma")
    fit_alpha, fit_loc, fit_beta = stats.gamma.fit(rdata)
    dparams[GAMMA] = (fit_alpha, fit_loc, fit_beta)
    print("alpha:{}, loc:{}, beta:{}".format(fit_alpha, fit_loc,
                                             fit_beta))
    if to_plot:
        plot_cdf(stats.gamma.rvs(fit_alpha, loc=fit_loc,
                                 scale=fit_scale, size=N),
                 lab='gamma')

    print("Fitting Cauchy")
    fit_loc, fit_scale = stats.cauchy.fit(rdata)
    dparams[CAUCHY] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    if to_plot:
        plot_cdf(stats.cauchy.rvs(loc=fit_loc, scale=fit_scale, size=N),
                 lab='cauchy')

    print("Fitting Exponential")
    fit_loc, fit_scale = stats.expon.fit(rdata)
    dparams[EXPON] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    if to_plot:
        plot_cdf(stats.expon.rvs(loc=fit_loc, scale=fit_scale, size=N),
                 lab='expon')

    print("Fitting Poisson")
    fit_lambda = np.mean(rdata)
    dparams[POI] = (fit_lambda,)
    print("lambda: {}".format(fit_lambda))
    if to_plot:
        plot_cdf(stats.poisson.rvs(fit_lambda, size=N),
                 lab='poisson')

    print("Uniform distribution")
    fit_loc, fit_scale = stats.uniform.fit(rdata)
    dparams[UNI] = (fit_loc, fit_scale)
    print("loc:{}, scale:{}".format(fit_loc, fit_scale))
    if to_plot:
        plot_cdf(stats.uniform.rvs(loc=fit_loc, scale=fit_scale, size=N),
                 lab='uniform')

    print("Weibull distribution")
    fit_c, fit_loc, fit_scale = stats.weibull_min.fit(rdata)
    dparams[WEIB] = (fit_c, fit_loc, fit_scale)
    print("Min, c: {}, loc:{}, scale:{}".format(fit_c, fit_loc,
                                                fit_scale))
    if to_plot:
        plot_cdf(stats.weibull_min.rvs(fit_c, loc=fit_loc, scale=fit_scale, size=N),
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
    if to_plot:
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

    ps_g = np.array(st_g.ps)
    ipt_g = np.array(st_g.ipt)

    title = "IPT Distbribution"
    dist_ipt = {NORM:None, GAMMA:None, CAUCHY:None, EXPON:None, POI:None,
                UNI:None, WEIB:None}

    dist_ps = {NORM:None, GAMMA:None, CAUCHY:None, EXPON:None, POI:None,
               UNI:None, WEIB:None}

    plot_all(ipt, ipt_g, dist_ipt, title, False)

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
