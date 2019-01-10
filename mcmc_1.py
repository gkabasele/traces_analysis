import numpy as np
import math
import matplotlib as mpl
import scipy as sp
import scipy.stats as stats
import matplotlib.pyplot as plt

#From scratch: Bayesian Inference MCMC
def generate_population(size):
    return stats.norm(10, 3).rvs(size)

pop_size = 300000
obs_size = 1000
pop = generate_population(pop_size)
obs = pop[np.random.randint(0, pop_size, obs_size)]

fig = plt.figure(figsize=(10, 10))
ax = fig.add_subplot(1, 1, 1)
ax.hist( obs, bins=35 ,)
ax.set_xlabel("Value")
ax.set_ylabel("Frequency")
ax.set_title("Distribution of 1000 observations samples from population of 30,0000")
mu_obs = obs.mean()
plt.show()
print mu_obs

# In this example the mu is fixed 

def proposal_distribution(x):
    mu = x[0]
    sigma = stats.norm(x[1], 0.5).rvs(1)
    return [mu, sigma]

def log_likelihood_normal(x, data):
    return np.sum(np.log(stats.norm(x[0], x[1]).pdf(data)))

def manual_log_like_normal(x, data):
    #x[0] = mu, x[1]=sigma (new or current)
    #data = the observation
    return np.sum(-np.log(x[1] * np.sqrt(2 * np.pi)) - ((data - x[0])**2) / (2*x[1]**2))

def prior(x):
    if(x[0] <= 0 or x[1] <= 0):
        return 0
    return 1

def acceptance(x, x_new):
    if x_new > x:
        return True
    else:
        accept = np.random.uniform(0, 1)
        return (accept < (np.exp(x_new-x)))

def metropolis_algorigthm(likelihood_computer, prior_computer, transition_model, 
                          param_init, iterations, data, acceptance_rule):
    x = param_init
    accepted = []
    rejected = []
    for i in range(iterations):
        x_new = transition_model(x)
        x_lik = likelihood_computer(x, data)
        x_new_lik = likelihood_computer(x_new, data)
        if (acceptance_rule(x_lik + np.log(prior_computer(x)), x_new_lik + np.log(prior_computer(x_new)))):
            x = x_new
            accepted.append(x_new)
        else:
            rejected.append(x_new)
    return np.array(accepted), np.array(rejected)

accepted, rejected = metropolis_algorigthm(manual_log_like_normal, prior, proposal_distribution,
                                           [mu_obs, 0.1], 50000, obs, acceptance)

print accepted[-50:]
