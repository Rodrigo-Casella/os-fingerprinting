import json
import os
import tempfile
import math
import joblib
import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score
from sklearn.metrics.pairwise import pairwise_distances
from sklearn.feature_selection import SelectKBest, mutual_info_classif

from utils.plot_charts import make_charts

# ttl: 0, ws: 1, mss: 2, win scale: 3, tcp opts: 4, ciphersuites: 5, supported groups: 6
WEIGHTS = np.array([1, 1, 1, 1, 5, 5, 5])
K_PERCENTILE = 85


class Cluster:

    def __init__(self, dir='.', output='X'):
        self.dir = dir
        self.output = output

    def cluster_fingerprints(self, dataframe: pd.DataFrame, labels_column: str):
        dataframe = dataframe.drop(
            columns=['extensions_list'], errors='ignore').dropna()
        X = dataframe.iloc[:, 1:].drop_duplicates().values
        concatenated_features = np.array([','.join(x.astype(str)) for x in X])

        cluster_labels, n_clusters = self._cluster_data(X)

        clusters_dict = self._build_cluster_dict(
            dataframe, labels_column, concatenated_features, cluster_labels, n_clusters)

        clusters_filename = "clusters_" + self.output
        with open(f'{os.path.join(self.dir, clusters_filename)}.json', "w") as fp:
            json.dump(clusters_dict, fp, indent=4,
                      sort_keys=True)
    
    def _cluster_data(self, X: np.ndarray):
        X_enc = preprocessing.OrdinalEncoder().fit_transform(X)

        distance_matrix = pairwise_distances(
            X_enc, metric='hamming', n_jobs=-1, w=WEIGHTS)
        
        model = AgglomerativeClustering(
                metric="precomputed", linkage='average', compute_full_tree=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = joblib.Memory(temp_dir, verbose=0)
            model.set_params(memory=memory)

            sample_range = range(2, len(X_enc))
            silhouette_avgs = np.zeros(len(sample_range))
            for n in sample_range:
                model.set_params(n_clusters=n)
                labels = model.fit_predict(distance_matrix)
                silhouette_avgs[n - 2] = silhouette_score(
                    distance_matrix, labels, metric='precomputed', random_state=0)

            best_idx = np.argmax(silhouette_avgs)
            model.set_params(n_clusters=best_idx + 2)
            model = model.fit(distance_matrix)

        print(
            f"n_clusters: {model.n_clusters_}, average silhouette score: {silhouette_avgs[best_idx]}")
        
        return model.labels_, model.n_clusters_
        

    def _build_cluster_dict(self, dataframe: pd.DataFrame, labels_column: str, human_readble_data: np.ndarray, cluster_labels: np.ndarray, n_clusters: int):
        cluster2data = {k: [] for k in range(n_clusters)}
        data2cluster = {}

        for cluster_id, elem in zip(cluster_labels, human_readble_data):
            cluster2data[cluster_id.item()].append(elem)
            data2cluster[elem] = cluster_id.item()

        cluster2occurance = {k: {label: 0 for label in dataframe[labels_column].unique()}
                             for k in range(n_clusters)}

        rows = np.array([','.join(row.astype(str)) for row in dataframe.iloc[:, 1:].values])
        cluster_ids = np.array([data2cluster[row] for row in rows])

        occurance_counts = np.zeros(n_clusters)
        for cluster_id, label in zip(cluster_ids, dataframe[labels_column].values):
            cluster2occurance[cluster_id][label] += 1
            occurance_counts[cluster_id] += 1

        threshold = math.floor(np.percentile(occurance_counts, K_PERCENTILE))
        print(f"Threshold at {K_PERCENTILE}th perctile: {threshold}")

        indices = np.where(occurance_counts <= threshold)[0]
        cluster2data = {k: v for k, v in cluster2data.items()
                        if k not in indices}
        cluster2occurance = {k: {label: count for label, count in cluster2occurance[k].items(
        ) if count > 0} for k in cluster2occurance if k not in indices}
        n_clusters -= len(indices)
        print(f"Number of clusters above threshold: {n_clusters}")

        clusters_img_path = os.path.join(
            self.dir, f'percentages_{self.output}')
        make_charts(cluster2occurance, clusters_img_path)

        for k, occurances in cluster2occurance.copy().items():
            labels = list(occurances.keys())
            values = np.array(list(occurances.values()), dtype=np.float_)
            predominat_class_idx = np.argmax(values)
            cluster2occurance[k] = labels[predominat_class_idx]
            if values[predominat_class_idx] >= 55:
                cluster2occurance[k] = labels[predominat_class_idx]
                continue
            del cluster2occurance[k]
            del cluster2data[k]
            n_clusters -= 1

        print(f"Final number of clusters: {n_clusters}")

        clusters = {cluster_id: {'Fingerprints': cluster2data[cluster_id],
                                 'Os': cluster2occurance[cluster_id]} for cluster_id in cluster2data}
        return clusters
