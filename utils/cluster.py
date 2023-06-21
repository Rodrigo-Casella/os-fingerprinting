import json
import os
from matplotlib import pyplot as plt

import numpy as np
import pandas as pd
from utils.plot_charts import make_charts
from sklearn import preprocessing
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score
from sklearn.metrics.pairwise import pairwise_distances

# ttl: 0, ws: 1, mss: 2, win scale: 3, tcp opts: 4, ciphersuites: 5, supported groups: 6
WEIGHTS = np.array([1, 1, 1, 1, 5, 5, 5])
K_PERCENTILE = 90


class Cluster:

    def __init__(self, dir='.', output='X'):
        self.dir = dir
        self.output = output

    def cluster_fingerprints(self, dataframe: pd.DataFrame, labels_column):
        data = dataframe.dropna().iloc[:, 1:].drop_duplicates()
        X = data.to_numpy()
        concatenated_row = data.apply(
            lambda row: ','.join(row.astype(str)), axis=1)
        cluster_labels, n_clusters = self._cluster_data(X)
        cluster2fingerprint, cluster2occurance = self._build_cluster_dicts(
            dataframe, labels_column, concatenated_row, cluster_labels, n_clusters)
        cluster_filename = "clusters_" + self.output
        make_charts(self.dir, cluster2occurance, cluster_filename)
        cluster_data = {cluster_id: {'Fingerprints': cluster2fingerprint[cluster_id],
                                     'Os_percetange': cluster2occurance[cluster_id]} for cluster_id in cluster2fingerprint}
        with open(f'{os.path.join(self.dir, cluster_filename)}.json', "w") as fp:
            json.dump(cluster_data, fp, indent=4,
                      sort_keys=True)

    def _cluster_data(self, X):
        X_enc = preprocessing.OrdinalEncoder().fit_transform(X)
        print(len(X_enc))
        distance_matrix = pairwise_distances(
            X_enc, metric='hamming', n_jobs=-1, w=WEIGHTS)
        model = AgglomerativeClustering(
            metric="precomputed", linkage='average', compute_full_tree=False)
        sample_range = range(2, len(X_enc))
        silhouette_avgs = []
        for n in sample_range:
            model.set_params(n_clusters=n)
            model = model.fit(distance_matrix)
            silhouette_avgs.append(silhouette_score(
                distance_matrix, model.labels_, metric='precomputed', random_state=0))
        best_idx = np.argmax(silhouette_avgs)
        best_n_clusters = best_idx + 2
        model.set_params(n_clusters=best_n_clusters)
        model = model.fit(distance_matrix)
        print(
            f"n_clusters: {best_n_clusters}, average silhouette score: {silhouette_avgs[best_idx]}")
        return model.labels_, model.n_clusters_

    def _build_cluster_dicts(self, dataframe: pd.DataFrame, labels_column, data_arr, cluster_labels, n_clusters):
        cluster2data = {k: [] for k in range(n_clusters)}
        data2cluster = {}
        for cluster_id, elem in zip(cluster_labels, data_arr):
            cluster2data[cluster_id.item()].append(elem)
            data2cluster[elem] = cluster_id.item()
        labels = dataframe[labels_column].unique()
        cluster2occurance = {k: {label: 0 for label in labels}
                             for k in range(n_clusters)}
        cluster_ids = np.array([data2cluster[','.join(map(str, row[1:]))]
                               for row in dataframe.itertuples(index=False)])
        occurance_counts = np.zeros(n_clusters)
        for cluster_id, label in zip(cluster_ids, dataframe[labels_column]):
            cluster2occurance[cluster_id][label] += 1
            occurance_counts[cluster_id] += 1
        threshold = np.percentile(occurance_counts, K_PERCENTILE)
        print(f"Threshold at {K_PERCENTILE}th perctile: {threshold:.1f}")
        indices = np.where(occurance_counts < threshold)[0]
        cluster2data = {k: v for k, v in cluster2data.items()
                        if k not in indices}
        cluster2occurance = {k: {label: count for label, count in cluster2occurance[k].items(
        ) if count > 0} for k in cluster2occurance if k not in indices}
        n_clusters -= len(indices)
        print(f"Final number of clusters: {n_clusters}")
        return cluster2data, cluster2occurance
