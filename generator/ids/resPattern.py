import numpy as np
import matplotlib.pyplot as plt

def stacked_bar(data, series_label, category_labels=None,
                show_values=False, value_format="{}", y_label=None,
                grid=False, reverse=False):
    ny = len(data[0])
    ind = list(range(ny))
    
    axes = []
    cum_size = np.zeros(ny)

    data = np.array(data)

    if reverse:
        data = np.flip(data, axis=1)
        category_labels = reversed(category_labels)

    for i, row_data in enumerate(data):
        axes.append(plt.bar(ind, row_data, bottom=cum_size,
                            label=series_label[i]))
        cum_size += row_data
    if category_labels:
        plt.xticks(ind, category_labels)
    if y_label:
        plt.ylabel(y_label)

    plt.legend()

    if grid:
        plt.grid()

    '''
    if show_values:
        for axis in axes:
            for bar in axes:
                for b in bar:
                    w = b.get_width()
                    h = b.get_height()
                    plt.text(b.get_x() + w/2, b.get_y() + h/2,
                            value_format.format(h), ha="center",
                            va="center")
    '''

N = 2

data = [
    [2.96, 1.12],
    [4.65, 2.14],
    [1.80, 1.04],
    [1.41, 0.51],
    [0.81, 0.38],
    [1.48, 0.78],
    [7.43, 3.50],
    [15.37, 7.44],
    [0, 51.64],
    [2.92, 1.34],
    [1.52, 0.63],
    [7.49, 3.45],
    [15.29, 6.97],
    [9.34, 4.29],
    [7.30, 3.48],
    [18.09, 10.31],
    [1.85, 0.88]
]



#host15 = (2.96, 1.12)
#host14 = (4.65, 2.14)
#host17 = (1.80, 1.04)
#host16 = (1.41, 0.51)
#host11 = (0.81, 0.38)
#host10 = (1.48, 0.78)
#host13 = (7.43, 3.50)
#host12 = (15.37, 7.44)
#host19 = (0, 51.64)
#host9 = (2.92, 1.34)
#host8 = (1.52, 0.63)
#host5 = (7.49, 3.45)
#host4 = (15.29, 6.97)
#host7 = (9.34, 4.29)
#host6 = (7.30, 3.48)
#host3 = (18.09, 10.31)
#host2 = (1.85, 0.88)

category_labels = ["Normal", "Attack"]
series_label = ["a", "b", "c", "d", "e", "f", "g", "h", "i",
                "j", "k", "l", "m", "n", "o", "p", "q"]
stacked_bar(
    data,
    series_label,
    category_labels=category_labels,
    show_values=True,
    value_format="{:.1f}",
    y_label="Packets"
)

plt.title("Attack effects")

plt.show()
