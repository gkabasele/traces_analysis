import pdb
import struct
import ipaddress
import random
from decimal import *
import numpy as np
import matplotlib.pyplot as plt
from sketch import *

def test_cell():
    n = 4
    cell = Cell(n)
    N = 500
    x = np.random.normal(0, 1, N)
    v= np.random.normal(0, 0.1, N)
    d = x + v

    forecasted = [i for i in d[:n]]
    errors = []
    for i in range(N):
        cell.curr_val = d[i]

        if len(cell.n_last) == n:
            cell.estimate()
            cell.update_estimator()
            forecasted.append(cell.estim_val)
            errors.append(cell.estimator.error)
        cell.add_counter()

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

def test_cell_lms():
    n = 4
    training = 5

    n_inter = 100
    dist = [(3, 5), (7, 10), (3, 6), (19, 22)]
    for d in dist:
        cell = Cell(n)
        ts = [random.randint(d[0], d[1]) for _ in range(n_inter)] 
        
        forecasted = []
        errors = []
        for i, val in enumerate(ts):
            cell.curr_val = val
            if i < n:
                cell.add_counter()
                forecasted.append(val)
            else:
                cell.estimate()
                cell.update_estimator()
                forecasted.append(cell.estim_val)
                errors.append(cell.estimator.error)
                cell.add_counter()

        x_axis = np.arange(n_inter)
        plt.plot(x_axis, ts)
        plt.plot(x_axis, forecasted)
        plt.show()

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

def update_cells(hash_f, keys, values, attr):
    for k, v in zip(keys, values):
        setattr(hash_f.cells[hash_f.hash(k)], attr, v)

def same(p, q):
    form = '0.00001'
    p_rf = Decimal(p).quantize(Decimal(form), rounding=ROUND_UP)    
    q_rf = Decimal(q).quantize(Decimal(form), rounding=ROUND_UP)
    return p_rf == q_rf

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

    update_cells(hash_f, keys, estimate, "estim_val")
    hash_f.compute_distribution()

    for k, e in zip(keys, estimate):
        assert hash_f.cells[hash_f.hash(k)].curr_prob == 0.25
        assert hash_f.cells[hash_f.hash(k)].estim_prob == float(e)/sum(estimate)

    assert sum([cell.curr_prob for cell in hash_f.cells]) == 1
    assert sum([cell.estim_prob for cell in hash_f.cells]) == 1

    div_a = hash_f.compute_divergence()
    #((0.25-0.4)^2/0.4)+((0.25-0.3)^2/0.3)+((0.25-0.2)^2/0.2)+((0.25-0.1)^2/0.1)
    assert  same(div_a, 0.302083333)

    hash_f.adapt()
    mu_a = hash_f.div_mean
    sig_a = hash_f.div_std

    assert hash_f.div_mean == div_a
    assert hash_f.div_std == 0

    estimate = [2.7, 2.3, 2.5, 2.5]
    update_cells(hash_f, keys, estimate, "estim_val")
    hash_f.compute_distribution()
    div_b = hash_f.compute_divergence()
    assert same(div_b, 0.003220612)
    hash_f.adapt()
    mu_b = hash_f.div_mean
    sig_b = hash_f.div_std
    assert same(hash_f.div_mean, (0.7 * mu_a + 0.3 * div_a))
    assert same(hash_f.div_std, (0.7 * sig_a + 0.3 * (div_b - mu_b)**2))

    estimate = [6, 1, 2, 1]
    update_cells(hash_f, keys, estimate, "estim_val")
    hash_f.compute_distribution()
    div_c = hash_f.compute_divergence()
    assert same(div_c, 0.66666667)
    hash_f.adapt()
    mu_c = hash_f.div_mean
    assert same(hash_f.div_mean, 0.7 * mu_b + 0.3 * div_b)
    assert same(hash_f.div_std, (0.7 * sig_b + 0.3 * (div_b - mu_c)**2))

    assert hash_f.consecutive_exceed == 1

def create_and_test_matrix(ids, ips, n_inter, dist, debug=False):

    matrix = [[random.randint(d[0], d[1]) for d in dist] for _ in range(n_inter)]
    print(np.matrix(matrix))

    for row in matrix:
        for j, val in enumerate(row):
            ip = ips[j]
            for _ in range(val):
                ids.update_sketch(ip)
        ids.run_detection(debug)
        ids.current_interval += 1


def test_sketch_ids():
    n = 5
    limit = 100
    training_period = 10
    ipa = ipaddress.ip_address(unicode("10.0.0.3"))
    ipb = ipaddress.ip_address(unicode("10.0.0.4"))
    ipc = ipaddress.ip_address(unicode("10.0.0.5"))
    ipd = ipaddress.ip_address(unicode("10.0.0.6"))

    ips = [ipa, ipb, ipc, ipd]
    keys = [struct.unpack("!I", ip.packed)[0] for ip in ips]

    ids = SketchIDS(reg=None, nrows=5, ncols=100, n_last=4,
                    alpha=3, beta=0.7, training_period=training_period,
                    thresh=4, consecutive=3)

    print("Normal mode")
    n_inter = 20
    dist = [(3, 5), (7, 10), (3, 6), (19, 22)]
    create_and_test_matrix(ids, ips, n_inter, dist)

    print("Attack mode")
    n_inter_att = 5
    attack_dist = [(300, 500), (7, 10), (3, 6), (19, 22)]
    create_and_test_matrix(ids, ips, n_inter_att, attack_dist)

    print("Normal mode")
    n_inter_norm = 20
    create_and_test_matrix(ids, ips, n_inter_norm, dist)

    ##plot divergences
    for i in range(n):
        hash_f = ids.sketch.hashes[i]
        div_mean = np.mean(hash_f.filter_divergences[:2])
        div_std = np.std(hash_f.filter_divergences[:2])
        threshold = [div_mean + ids.alpha*div_std]
        for j in range(2, len(hash_f.filter_divergences)+1):
            div_mean = np.mean(hash_f.filter_divergences[:j-1])
            div_std = np.std(hash_f.filter_divergences[:j])
            threshold.append(div_mean + ids.alpha * div_std)

        x_axis = np.arange(n_inter + n_inter_norm + n_inter_att-training_period)
        plt.plot(x_axis, hash_f.divergences, label='div')
        plt.plot(x_axis, hash_f.filter_divergences, label='div_prime')
        plt.plot(x_axis, hash_f.thresholds, '-.', label='dyn_thresh')
        plt.plot(x_axis, threshold, '--', label='thresh')
        plt.legend(loc='right')
        plt.show()

#test_hash_func_set_get()
#test_hash_func_divergence()
#test_cell()
#test_cell_lms()
test_sketch_ids()
