import argparse
import os
import re
import sys
import time
from matplotlib import gridspec

import numpy as np
import pandas as pd
import seaborn as sns
from user_agents import parse
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

UNIX_UAS = {'Debian', 'Ubuntu', 'CentOS', 'FreeBSD', 'Chrome OS', 'Android', 'OpenBSD', 'Fedora'}
IPV4_PATTERN = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')


def is_ipv4_address(ip_address_str):
    return IPV4_PATTERN.match(ip_address_str)


def parse_user_agent_file(hosts: "list[dict]", log_file):
    with open(log_file, mode="r") as fp:
        for line in fp:
            ip_string, log_entry = line.split(' ', maxsplit=1)
            if not is_ipv4_address(ip_string):
                continue
            log_entry = log_entry.split('\" \"', maxsplit=1)
            if len(log_entry) < 2:
                continue
            ua = parse(log_entry[-1])
            os_name = f'{ua.os.family}'.strip()
            if os_name != "Other":
                if os_name in UNIX_UAS:
                    os_name = 'Linux'
                hosts.append({'flow_key': ip_string, 'os': os_name})


def plot_confusion_matrix(actual_labels, pred_labels, class_names, img_name):

    cfm = confusion_matrix(actual_labels, pred_labels)
    precision, recall, f1_score, _ = precision_recall_fscore_support(actual_labels, pred_labels, average=None)
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
    sns.heatmap(cfm, annot=True, cmap='Blues', fmt='g', xticklabels=class_names, yticklabels=class_names)
    ax0.set_xlabel('Predicted')
    ax0.set_ylabel('Actual')
    ax0.set_title('Confusion Matrix')
    ax1 = plt.subplot(gs[1])
    table = ax1.table(cellText=metrics_df.values, colLabels=metrics_df.columns, rowLabels=metrics_df.index, loc='center')
    table.scale(1.0, 4.0)
    ax1.axis('off')
    ax1.set_title('Metrics')
    plt.savefig(f'{img_name}', bbox_inches='tight')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--logs", required=True,
                        type=str, help="directory with user agent log files to parse")
    parser.add_argument("-f", "--fp", required=True,
                        type=str, help="fingerprints csv file to validate")
    parser.add_argument('-d','--dir', required=True,
                      help='file to write with hosts os name')
    args = parser.parse_args()
    user_agent_log_dir: str = args.logs
    if not os.path.isdir(user_agent_log_dir):
        print(f"The path '{user_agent_log_dir}' is not a valid directory.")
        sys.exit(1)
    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)
    hosts_list = []
    for filename in os.listdir(user_agent_log_dir):
        if filename.endswith('.log'):
            parse_user_agent_file(hosts_list, os.path.join(
                user_agent_log_dir, filename))
    hosts_df = pd.DataFrame(hosts_list, dtype=np.str_)
    hosts_df.drop_duplicates(inplace=True)
    fingerprints_df = pd.read_csv(args.fp, sep=';', dtype=np.str_)
    hosts_df = pd.merge_ordered(hosts_df, fingerprints_df, on=['flow_key']).dropna()
    hosts_df = hosts_df.iloc[:, 1:3][hosts_df.match != 'No match in db']
    actual_labels = []
    predicted_labels = []
    for row in hosts_df.itertuples(index=False):
        if row.os in row.match:
            actual_labels.append(row.os)
            predicted_labels.append(row.os)
            continue
        os_list: "list[str]" = row.match[1:-1].split(', ')
        os_list = [os_name[:os_name.find(':')].strip('\'') for os_name in os_list]
        for os_name in os_list:
            actual_labels.append(row.os)
            predicted_labels.append(os_name)

    actual_labels = np.array(actual_labels, dtype=np.str_)
    predicted_labels = np.array(predicted_labels, dtype=np.str_)
    class_names = np.unique(actual_labels)
    outfile = os.path.join(work_dir, f"{os.path.splitext(os.path.basename(args.fp))[0]}_cf.png")
    plot_confusion_matrix(actual_labels, predicted_labels, class_names, outfile)

if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))