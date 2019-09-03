import argparse
import os
import numpy as np
import pdb

def autocorr_coef(timeseries, t=1):
    lista = [i for i in timeseries[:-(t)]]
    listb = [i for i in timeseries[t:]]
    
    ex_val = np.mean(timeseries)

    num = 0
    denum = 0
    for i in xrange(len(timeseries)):
        if i < len(lista):
            num += (lista[i]-ex_val) * (listb[i] - ex_val)
        denum += (timeseries[i] - ex_val)**2

    return float(num)/denum


def autocorr(x, t=1):
    return np.corrcoef(np.array([x[:-t], x[t:]]))[0,1]

def main():

    ts = [9.08, 12.63, 15.00, 20.73, 2.20, 18.00, 7.16, 18.28, 21.00, 19.68,
          15.54, 24.00, 16.10, 11.93, 27.00, 12.51, 20.04, 30.00, 12.41, 14.33,
          33.00, 22.11, 17.91, 36.00]

    print(autocorr(ts, 3))
    print(autocorr_coef(ts, 3))

if __name__=="__main__":
    main()
