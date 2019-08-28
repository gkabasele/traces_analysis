import pdb
import struct
import ipaddress
import numpy as np
import matplotlib.pyplot as plt
from sketch import *


def test_lms():
    n = 4
    lms = LMS(n)
    N = 500
    x = np.random.normal(0, 1, N)
    v= np.random.normal(0, 0.1, N)
    d = x + v
    
    forecasted = [i for i in d[:n]]
    errors = []
    n_last = []
    for i in range(N):

        if len(n_last) > n:
            n_last.pop(0)

        if len(n_last) == n:
            lms.estimate_next(n_last)
            forecasted.append(lms.forecast)
            lms.compute_error(d[i])
            errors.append(lms.error)
            lms.update_weight(n_last)

        n_last.append(d[i])

    forecast_np = np.array(forecasted)
    errors_np = np.array(errors)

    x_axis = np.arange(N) 
    plt.plot(x_axis, d)
    plt.plot(x_axis, forecasted)
    plt.show()
    print("Mean:{}, std:{}".format(np.mean(forecast_np),
                                   np.std(forecast_np)))
    print("Error Mean: {}, Error Std: {}".format(np.mean(errors_np),
                                                 np.std(errors_np)))

def test_cell():
    pass

def test_hash_func_set_get():
    limit = 100
    value_a = 5
    value_b = 7

    n = 5

    ipa = ipaddress.ip_address(unicode("10.0.0.3"))
    ipb = ipaddress.ip_address(unicode("10.0.0.4"))

    hash_f = HashFunc(PRIME_NBR, limit, n)
    key_a = struct.unpack("!I", ipa.packed)[0]
    key_b = struct.unpack("!I", ipb.packed)[0]
    hash_f.update(key_a, value_a)
    hash_f.update(key_b, value_b)

    assert hash_f.get(key_a) == value_a
    assert hash_f.get(key_b) == value_b
    assert hash_f.get(key_a) != value_b

def test_hash_func_divergence():
    n = 5
    limit = 100

    ipa = ipaddress.ip_address(unicode("10.0.0.3"))
    ipb = ipaddress.ip_address(unicode("10.0.0.4"))
    ipc = ipaddress.ip_address(unicode("10.0.0.5"))
    ipd = ipaddress.ip_address(unicode("10.0.0.6"))

    ips = [ipa, ipb, ipc, ipd]
    keys = [struct.unpack("!I", ip.packed)[0] for ip in ips]
    hash_f = HashFunc(PRIME_NBR, limit, n)
    collisions = set([hash_f.hash(k) for k in keys])
    assert len(collisions) == len(ips)

    estimate = [4, 3, 2, 1]

    for k, e in zip(keys, estimate):
        hash_f.update(k, 1)
        hash_f.cells[hash_f.hash(k)].estim_val = e
    hash_f.compute_distribution()

    for k,e in zip(keys, estimate):
        assert hash_f.cells[hash_f.hash(k)].curr_prob == 0.25
        assert hash_f.cells[hash_f.hash(k)].estim_prob == float(e)/sum(estimate)

    try:
        div = hash_f.compute_divergence()
        assert  div == 1.20833333
    except AssertionError:
        print(div)


test_hash_func_set_get()
test_hash_func_divergence()
#test_lms()
