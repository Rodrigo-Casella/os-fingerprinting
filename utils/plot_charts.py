import os

import matplotlib.pyplot as plt
import numpy as np


def make_charts(work_dir, data: "dict[int, dict]", output):
    data_len = len(data)
    cols = 4
    rows = (data_len - 1) // cols + 1
    _, axes = plt.subplots(nrows=rows, ncols=cols, figsize=(cols*4, rows*3))

    axes_flat = axes.flatten()

    for idx, (category, subcategories) in enumerate(data.items()):
        axs = axes_flat[idx]

        labels = list(subcategories.keys())
        values = np.array(list(subcategories.values()), dtype=np.float_)
        values = values / np.sum(values) * 100

        axs.pie(values, labels=labels, autopct='', labeldistance=None)

        legend_texts = []
        for key, pct in zip(labels, values):
            pct = f'{pct:.1f}%'
            subcategories[key] = pct
            legend_texts.append(f'{key}: {pct}')

        axs.legend(legend_texts, loc='center', bbox_to_anchor=(
            1, 0), fontsize='medium', title=f'Cluster {category}')

        axs.axis('off')
        axs.set_aspect('equal')

    n_unused = cols - (data_len % cols)
    if n_unused != cols:
        for i in range(n_unused):
            idx = data_len + i 
            axes_flat[idx].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(work_dir, f'{output}_pie_charts.png'))
