import numpy as np
import matplotlib.pyplot as plt
"""
real_alert = [52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 6, 9, 10, 8, 7, 8, 5, 5, 5, 7, 6] 
gen_alert = [52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 7, 4, 9, 5, 3, 4, 5, 10, 7]
attack_alert = [52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 7, 6, 4, 8, 7, 3, 4, 5, 11, 8]

t = np.arange(0, len(real_alert), 1)

fig = plt.figure()
ax = fig.add_subplot(1, 1, 1)

inc_real, = ax.plot(t, real_alert, label="real")
inc_gen, = ax.plot(t, gen_alert, label="gen")
inc_attack, = ax.plot(t, attack_alert, label="attack")

plt.legend(handles=[inc_real, inc_gen, inc_attack])
plt.show()

fig = plt.figure()
ax = fig.add_subplot(1, 1, 1)

real_score = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6.651377377222681, 15.456155491760676, 15.188659143467861, 33.7036222271139, 26.447277212319488, 54.76264751516073, 47.060576810360615, 68.3530806597881, 66.73825576597127, 41.98133602450258, 6.812322146286159, 15.75962428468227]

gen_score = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6.2461559141762155, 11.586303247729106, 16.320016148861416, 13.60946286017069, 7.869070782912869, 23.944562354868516, 36.426651020695985, 52.21638491467408, 38.117146028000846, 7.109961902423045, 6.285423581329048, 15.689072947231438]

attack_score = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28.175878926151217, 32.77271844939597, 34.72834640921259, 30.39691248635565, 32.80194919746282, 31.763209341348084, 30.610378168838356, 61.87532707559374, 43.68724807844697, 29.682751621437085, 16.64402172795711, 26.61035605953478]

inc_real, = ax.plot(t, real_score, label="real")
inc_gen, = ax.plot(t, gen_score, label="gen")
inc_attack, = ax.plot(t, attack_score, label="attack")

plt.legend(handles=[inc_real, inc_gen, inc_attack])
plt.show()
"""

n_groups = 3

bar_width = 0.25
no_margin = [82, 78, 78]
margin_gen = [19, 8, 20]
margin_real = [21, 11, 20]

r1 = np.arange(len(no_margin))
r2 = [x + bar_width for x in r1]
r3 = [x + bar_width for x in r2]

col1 = "#7f6d5f"
col2 = "#557f2d"
col3 = "#2d7f5e"


fig, ax = plt.subplots()

rect1 = plt.bar(r1, no_margin, width=bar_width,
                label='No Margin')

rect2 = plt.bar(r2, margin_gen, width=bar_width,
                label='From Gen')

rect3 = plt.bar(r3, margin_real, width=bar_width,
                label='From Real')

plt.xlabel("Trace", fontweight="bold")
plt.ylabel("Nbr Alerts")
plt.xticks([r + bar_width for r in range(n_groups)], ["Real", "Gen", "Atk"])
plt.title("Nbr alerts raised")
plt.legend()
plt.tight_layout()
plt.show()
