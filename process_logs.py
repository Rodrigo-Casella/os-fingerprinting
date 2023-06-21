import argparse
import os
import sys
import time

import pandas as pd
from utils.logs_process import parse_user_agent_file, parse_features_file, FEATURES_SET
import matplotlib.pyplot as plt


def process_logs(features_log_dir, user_agent_log_dir):
    host2features: "dict[str, dict[str, str]]" = {}
    for filename in os.listdir(user_agent_log_dir):
        if filename.endswith('.log'):
            parse_user_agent_file(os.path.join(
                user_agent_log_dir, filename), host2features)
    for filename in os.listdir(features_log_dir):
        if filename.endswith('.log'):
            parse_features_file(host2features, os.path.join(
                features_log_dir, filename))
    return host2features


def plot_log_stats(work_dir, logs_dir_basename, percentages):
    fig, ax = plt.subplots()
    ax.grid(axis='x', zorder=0)
    ax.barh(percentages.index, percentages.values, zorder=3)
    ax.set_xlabel('Percentage')
    ax.set_xticklabels(['{:.1f}%'.format(x) for x in ax.get_xticks()])
    plt.savefig(f'{os.path.join(work_dir, logs_dir_basename + "_logs_stats.png")}', dpi=300, bbox_inches='tight')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--logs_dir", required=True,
                        type=str, help="directory with user agent log files to parse")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    args = parser.parse_args()
    features_log_dir: str = os.path.join(args.logs_dir, 'features_logs')
    if not os.path.isdir(features_log_dir):
        print(f"The path '{features_log_dir}' is not a valid directory.")
        sys.exit(1)
    user_agent_log_dir: str = os.path.join(args.logs_dir, 'uas_logs')
    if not os.path.isdir(user_agent_log_dir):
        print(f"The path '{user_agent_log_dir}' is not a valid directory.")
        sys.exit(1)
    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)
    logs_dir_basename = os.path.basename(os.path.normpath(args.logs_dir))
    host2features = process_logs(features_log_dir, user_agent_log_dir)
    df = pd.DataFrame.from_dict(
        host2features, orient='index', columns=FEATURES_SET).drop(columns=['extensions_list']).dropna()
    df.to_csv(f'{os.path.join(work_dir, logs_dir_basename)}.csv', index=False)
    percentages = df['os_name'].value_counts(normalize=True) * 100
    plot_log_stats(work_dir, logs_dir_basename, percentages)


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
