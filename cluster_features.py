import argparse
import itertools
import json
import os
import time

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from kmedoids import KMedoids
from matplotlib.backends.backend_pdf import PdfPages
from sklearn import preprocessing
from sklearn.metrics import silhouette_score
from sklearn.metrics.pairwise import pairwise_distances


def make_charts(work_dir, data: "dict[int, dict]", n_clusters):
    n_charts_per_page = 6

    n_pages = (len(data) - 1) // n_charts_per_page + 1

    with PdfPages(os.path.join(work_dir, f'{n_clusters}_pie_charts.pdf')) as pdf:
        for page in range(n_pages):
            start_idx = page * n_charts_per_page
            end_idx = min(start_idx + n_charts_per_page, len(data))

            fig, axs = plt.subplots(nrows=3, ncols=2, figsize=(8, 12), dpi=150)

            for idx, entry in enumerate(list(data)[start_idx:end_idx]):
                row_idx = idx // 2
                col_idx = idx % 2

                inner_dict = data[entry]

                for key, value in inner_dict.copy().items():
                    if value == 0:
                        del inner_dict[key]

                draw_pie_chart(axs, entry, row_idx, col_idx, inner_dict)

            n_unused = n_charts_per_page - (end_idx - start_idx)

            for i in range(n_unused):
                row_idx = (end_idx - start_idx + i) // 2
                col_idx = (end_idx - start_idx + i) % 2
                axs[row_idx, col_idx].set_visible(False)

            plt.subplots_adjust(right=0.8, hspace=0.4, wspace=0.4)

            pdf.savefig(fig)
            plt.close(fig)


def draw_pie_chart(axs, entry, row_idx, col_idx, inner_dict):
    axs[row_idx, col_idx].pie(inner_dict.values(), labels=inner_dict.keys(
    ), autopct='%1.1f%%', textprops={'fontsize': 8}, pctdistance=1.25, labeldistance=None)

    legend_labels = [f'{label}: {size}' for label, size in inner_dict.items()]
    axs[row_idx, col_idx].legend(
        legend_labels, loc='right', bbox_to_anchor=(1.5, 0.), fontsize='small')

    axs[row_idx, col_idx].set_title(f'Cluster {entry}', fontsize=8)

    axs[row_idx, col_idx].get_xaxis().set_visible(False)
    axs[row_idx, col_idx].get_yaxis().set_visible(False)


WEIGHTS = np.array([1, 1, 1, 1, 10, 10])


def hamming_dist(x, y):
    return np.sum(WEIGHTS * (x != y))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("features", type=str,
                        help="features file to read data to cluster")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    args = parser.parse_args()

    features_filename: str = args.features

    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)

    df = pd.read_csv(features_filename, dtype=str, delimiter=';')
    df.dropna(inplace=True)

    X = df.iloc[:, 2:].drop_duplicates().to_numpy(dtype=np.str_)
    X_enc = preprocessing.OrdinalEncoder().fit_transform(X)

    unique_rows = [','.join(x) for x in X]
    
    distances = pairwise_distances(X_enc, metric=hamming_dist)

    silhouette_avgs = []
    for n in range(2, len(X_enc)):
        labels = KMedoids(
            n_clusters=n, metric='precomputed', random_state=0).fit_predict(distances)

        silhouette_avgs.append(silhouette_score(
            distances, labels, metric='precomputed', random_state=0))

    n_clusters = np.argmax(silhouette_avgs).item() + 2
    score = silhouette_avgs[n_clusters - 2]

    labels = KMedoids(
        n_clusters=n_clusters, metric='precomputed', random_state=0).fit_predict(distances)

    print(f'Number of cluster: {n_clusters}, Silhouette_score: {score}')

    cluster2features = {k: [] for k in range(n_clusters)}
    unique_uas = df['user_agent'].unique()

    fp_entries = np.append(['Cluster_ID'], unique_uas)

    fp_db = {feature: {entry: 0 for entry in fp_entries}
             for feature in unique_rows}

    for cluster_id, feature in zip(labels, unique_rows):
        cluster2features[cluster_id.item()].append(feature)
        fp_db[feature]['Cluster_ID'] = cluster_id.item()

    cluster2occurance = {k: {ua: 0 for ua in unique_uas}
                         for k in range(n_clusters)}

    for _, row in df.iterrows():
        signature = row[2:].str.cat(sep=',')
        user_agent = row['user_agent']

        fp_db[signature][user_agent] += 1

        cluster_id = fp_db[signature]['Cluster_ID']
        cluster2occurance[cluster_id][user_agent] += 1

    deleted_clusters = set()
    for key in list(cluster2occurance.keys()):
        if sum(cluster2occurance[key].values()) < 10 and len(cluster2features[key]) < 5:
            del cluster2features[key]
            del cluster2occurance[key]
            deleted_clusters.add(key)

    n_clusters -= len(deleted_clusters)

    print(f'Final number of cluster: {n_clusters}')

    fp_df: pd.DataFrame = pd.DataFrame.from_dict(fp_db, orient='index')

    fp_df = fp_df[~fp_df['Cluster_ID'].isin(deleted_clusters)]
    fp_df.replace(0, '', inplace=True)

    clusters_file_basename = f'{n_clusters}_' + \
        os.path.basename(features_filename.rstrip(".csv"))

    fp_df.to_csv(f'{os.path.join(work_dir, "signatures_" + clusters_file_basename)}.csv',
                 index_label='Signature', sep=';', na_rep='')

    make_charts(work_dir, cluster2occurance, n_clusters)

    with open(f'{os.path.join(work_dir, "clusters_" + clusters_file_basename)}.json', "w") as fp:
        json.dump(cluster2features, fp, indent=4,
                  sort_keys=True)
        
    real_clusters = {k: [row.str.cat(sep=',') for _, row in d.drop(columns=['user_agent']).drop_duplicates(keep='last').iterrows()] for k, d in df.iloc[:, 1:].groupby('user_agent')}
    with open(f'{os.path.join(work_dir, "real_clusters_" + clusters_file_basename)}.json', "w") as fp:
        json.dump(real_clusters, fp, indent=4,
                  sort_keys=True)


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
