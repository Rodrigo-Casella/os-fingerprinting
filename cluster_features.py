import argparse
import itertools
import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.metrics.pairwise import pairwise_distances
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score


def hamming_distance(x, y):
    return np.sum(x != y)


def longest_list(a, b):
    a_index = np.nonzero(a == -1)[0]
    b_index = np.nonzero(b == -1)[0]

    return max(a_index[0] + 1 if a_index.size > 0 else a.shape[0], b_index[0] + 1 if b_index.size > 0 else b.shape[0])


def list_distance(l1, l2, max_tcp_features_len):
    tcp_dist = hamming_distance(
        l1[:max_tcp_features_len], l2[:max_tcp_features_len])
    tls_dist = hamming_distance(
        l1[max_tcp_features_len:], l2[max_tcp_features_len:])

    scaling_factor = tcp_dist / \
        longest_list(l1[:max_tcp_features_len],
                     l2[:max_tcp_features_len])
        
    return tcp_dist + tls_dist * scaling_factor


def string2numpy(string):
    array = np.stack(list(itertools.zip_longest(
        *(np.char.split(np.char.rstrip(string, ","), ",")), fillvalue="-1")), axis=-1).astype(np.float32)
    return array


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("features", type=str,
                        help="features file to read data to cluster")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    """parser.add_argument("-k", "--clusters", required=True,
                        type=int, help="number of initial cluster")"""
    args = parser.parse_args()

    features_filename: str = args.features
    # n_clusters = args.clusters

    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)

    df = pd.read_csv(features_filename, dtype=str, delimiter=';')

    df.dropna(subset=['tcp', 'user_agent', 'tls'], inplace=True)
    data_set = df.loc[:, ['user_agent', 'tcp', 'tls']]

    unique_features = np.unique(np.stack((data_set['tcp'].to_numpy(
        dtype=np.str_), data_set['tls'].to_numpy(dtype=np.str_)), axis=-1), axis=0)

    tcp_features = string2numpy(unique_features[:, 0])
    max_tcp_features_len = tcp_features.shape[1]

    tls_features = string2numpy(unique_features[:, 1])

    unique_features = np.char.add(
        unique_features[:, 0], np.char.add(":", unique_features[:, 1]))

    X = np.concatenate((tcp_features, tls_features), axis=1)

    metric_params = {'max_tcp_features_len': max_tcp_features_len}

    distances = pairwise_distances(
        X, metric=list_distance, force_all_finite=False, **metric_params)

    silhouette_avgs = []
    for n in range(2, len(X)):
        labels = AgglomerativeClustering(
            n_clusters=n, metric='precomputed', linkage='complete').fit_predict(distances)
        
        silhouette_avgs.append(silhouette_score(
            distances, labels, metric='precomputed', random_state=0))
        
    n_clusters = np.argmax(silhouette_avgs).item() + 2
    score = silhouette_avgs[n_clusters - 2]
    
    labels = AgglomerativeClustering(
        n_clusters=n_clusters, metric='precomputed', linkage='complete').fit_predict(distances)

    print(f'Number of cluster: {n_clusters}, Silhouette_score: {score}')
    
    cluster2features = {k: [] for k in range(n_clusters)}
    fp_db = {}

    for feature, cluster_id in zip(unique_features, labels):
        if feature not in fp_db:
            fp_db[feature] = {}
        fp_db[feature]['Cluster_ID'] = cluster_id.item()
        cluster2features[cluster_id.item()].append(feature)
    
    cluster2occurance = {k: {'Android': 0, 'iOS': 0, 'Linux': 0, 'Mac OS X': 0, 'Windows': 0} for k in range(n_clusters)}

    for index, row in df.iterrows():
        signature = f'{row["tcp"]}:{row["tls"]}'
        user_agent = row['user_agent']

        if user_agent not in fp_db[signature]:
            fp_db[signature][user_agent] = 0

        fp_db[signature][user_agent] += 1
        cluster_id = fp_db[signature]['Cluster_ID']
        cluster2occurance[cluster_id][user_agent] += 1

    clusters_file_basename = f'{n_clusters}_' + \
        os.path.basename(features_filename.rstrip(".csv"))

    fp_df = pd.DataFrame.from_dict(fp_db, orient='index')

    fp_df.to_csv(f'{os.path.join(work_dir, "signatures_" + clusters_file_basename)}.csv',
              index_label='Signature', sep=';')
    
    clstr2occurr_df = pd.DataFrame.from_dict(cluster2occurance, orient='index')
    
    clstr2occurr_df.to_csv(f'{os.path.join(work_dir, "occurrance_" + clusters_file_basename)}.csv',
              index_label='Cluster_ID', sep=';')

    with open(f'{os.path.join(work_dir, "clusters_" + clusters_file_basename)}.json', "w") as fp:
        json.dump(cluster2features, fp, indent=4,
                  sort_keys=True)


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
