import argparse
import json
import os
import time
from matplotlib import gridspec

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, accuracy_score

FEATURES_SET = ['ttl', 'tcp_window', 'mss', 'win_scale',
                'tcp_opts', 'ciphersuites', 'supp_groups']
MOST_WEIGHT = {'tcp_opts', 'ciphersuites', 'supp_groups'}
WEIGHTS = np.array([1, 1, 1, 1, 5, 5, 5])


def json2dict(clusters_dict: dict):
    database = {}
    for _, data in clusters_dict.items():
        for signature in data['Fingerprints']:
            database[signature] = data['Os']

    return clusters_dict


def json2mod_dict(clusters_dict: dict):
    generic_clusters = {k: {feature: set() for feature in FEATURES_SET}
                        for k in clusters_dict}

    for k, cluster_data in clusters_dict.items():
        generic_clusters[k]['Os'] = cluster_data['Os']

        for signature in cluster_data['Fingerprints']:
            values = signature.split(",")

            for feature, value in zip(FEATURES_SET, values):
                generic_clusters[k][feature].add(value)

    return generic_clusters


def plot_confusion_matrix(actual_labels, pred_labels, class_names, img_name):
    cfm = confusion_matrix(actual_labels, pred_labels)

    precision, recall, f1_score, _ = precision_recall_fscore_support(
        actual_labels, pred_labels, average=None)
    accuracy = accuracy_score(actual_labels, pred_labels)
    precision_str = [f"{value:.4f}" for value in precision]
    recall_str = [f"{value:.4f}" for value in recall]
    f1_score_str = [f"{value:.4f}" for value in f1_score]

    metrics_df = pd.DataFrame({
        'Precision': precision_str,
        'Recall': recall_str,
        'F1-score': f1_score_str
    }, index=class_names)

    fig = plt.figure(figsize=(10, 5))
    gs = gridspec.GridSpec(1, 2, width_ratios=[2, 1])

    ax0 = plt.subplot(gs[0])
    sns.heatmap(cfm, annot=True, cmap='Blues', fmt='g',
                xticklabels=class_names, yticklabels=class_names)
    ax0.set_xlabel('Predicted')
    ax0.set_ylabel('Actual')
    ax0.set_title('Confusion Matrix')

    ax1 = plt.subplot(gs[1])
    table = ax1.table(cellText=metrics_df.values, colLabels=metrics_df.columns,
                      rowLabels=metrics_df.index, loc='center')
    ax1.annotate(f'Accuracy: {(accuracy * 100):.2f}%',
                 xy=(0.5, -0.05), xycoords='axes fraction', ha='center')
    table.scale(1.0, 4.0)
    ax1.axis('off')
    ax1.set_title('Metrics')

    plt.savefig(f'{img_name}', bbox_inches='tight')


class Fingerprinter:

    def __init__(self, clusters_filename, output_dir):
        clusters_dict = {}
        with open(clusters_filename, "r") as fp:
            clusters_dict: dict = json.load(fp)

        self.database = json2dict(clusters_dict)
        self.mod_database = json2mod_dict(clusters_dict)
        self.output_dir = output_dir
        self.flows = {}
        self.fingerprints = []

    def _search_fingerprint_in_db(self, fp_str) -> str:
        fingerprint = self.database.get(fp_str, None)

        if fingerprint is None:
            max_score = 0
            most_similar_cluster = -1

            for cluster_id, cluster_data in self.mod_database.items():
                curr_score = 0

                for feature, value in zip(FEATURES_SET, fp_str.split(",")):
                    if value in cluster_data[feature]:
                        if feature in MOST_WEIGHT:
                            curr_score += 5
                            continue
                        curr_score += 1

                if curr_score > max_score:
                    max_score = curr_score
                    most_similar_cluster = cluster_id

            fingerprint = self.mod_database[most_similar_cluster]['Os']

        return fingerprint

    def process_csv(self, input):
        df = pd.read_csv(input)

        for row in df.itertuples(index=False):
            fp = ','.join(map(str, row[1:]))
            self.fingerprints.append(self._search_fingerprint_in_db(fp))

        df['match'] = self.fingerprints

        actual_labels = df['os_name'].values
        predicted_labels = df['match'].values
        class_names = np.unique(actual_labels)

        outfile = os.path.splitext(os.path.basename(input))[0]
        df.to_csv(os.path.join(self.output_dir,
                  f"{outfile}_fp.csv"), index=False)

        img_name = os.path.join(self.output_dir, f"{outfile}_cf.png")
        plot_confusion_matrix(
            actual_labels, predicted_labels, class_names, img_name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("json", type=str,
                        help="json file of the db")
    parser.add_argument("-i", "--input", required=True,
                        help="csv file to read and classify")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    args = parser.parse_args()

    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)

    fingerprinter = Fingerprinter(args.json, output_dir=args.dir)
    fingerprinter.process_csv(args.input)


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
