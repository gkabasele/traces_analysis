import time
import math
import numpy as np
import scipy as sp
import scipy.stats as stats
from threading import Timer
from collections import Counter

class RepeatedTimer(object):

    """Repeat `function` every `interval` seconds."""

    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False

def proposal_function(params, sigmas):
    res = []
    for i, val in enumerate(params):
        res.append(stats.norm(val,sigmas[i]).rvs(1))
    return res

def manual_log_lik_gamma(x, data):
    return np.sum((x[0]-1)*np.log(data) - (1/x[1])*data - x[0]*np.log(x[1]) - np.log(math.gamma(x[0])))

def log_lik_gamma(x, data):
    return np.sum(np.log(stats.gamma(a=x[0], scale=x[1],
                         loc=0).pdf(data)))

def log_lik_lomax(x,data):
    return np.sum(np.log(stats.lomax(c=x[0], scale=x[1],
                                     loc=0).pdf(data)))

def prior(w):
    if(w[0]<=0 or w[1] <= 0):
        return 0
    else:
        return 1

def acceptance(x, x_new):
    if x_new > x:
        return True
    else:
        accept = np.random.uniform(0, 1)
        return (accept <(np.exp(x_new-x)))


                  
def metroplolis_algorithm(likelihood_func, prior_func, transition_model,
                          param_init, iterations, data, acceptance_rule, sigmas):
    x = param_init
    accepted = []
    rejected = []
    for i in range(iterations):
        x_new = transition_model(x, sigmas)
        x_lik = likelihood_func(x, data)
        x_new_lik = likelihood_func(x_new, data)
        if (acceptance_rule(x_lik + np.log(prior_func(x)), x_new_lik +
                            np.log(prior_func(x_new)))):
            x = x_new
            accepted.append(x_new)
        else:
            rejected.append(x_new)
    return np.array(accepted), np.array(rejected)

def get_pmf(data):
    C = Counter(data)
    total = float(sum(C.values()))
    for key in C:
        C[key] /= total
    return C

def estimate_distribution(data, iterations, param_init , sigmas,dist="gamma"):

    if dist == "gamma":
        return metroplolis_algorithm(log_lik_gamma, prior,
                                     proposal_function, param_init, iterations,
                                     data, acceptance, sigmas)
    elif dist == "lomax":
        return metroplolis_algorithm(log_lik_lomax, prior,
                                     proposal_function, param_init, iterations,
                                     data, acceptance, sigmas)

def main():
    pass


if __name__ == "__main__":
    main()
