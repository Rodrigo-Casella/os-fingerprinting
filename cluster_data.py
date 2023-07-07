import argparse
import os
import time

import pandas as pd
from utils.cluster import Cluster
from sklearn.model_selection import train_test_split

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("data", type=str, help="csv file with data to cluster")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    args = parser.parse_args()

    data_file = args.data
    df = pd.read_csv(data_file).drop(['extensions_list'], errors='ignore')
    df = df.sample(frac=1, random_state=0)
    train_df, test_df = train_test_split(df, test_size=0.2, shuffle=False)

    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)
    
    data_file_basename = os.path.splitext(os.path.basename(data_file))[0]
    train_df.to_csv(os.path.join(work_dir, f'{data_file_basename}_train.csv'), index=False)
    test_df.to_csv(os.path.join(work_dir, f'{data_file_basename}_test.csv'), index=False)
    cluster = Cluster(dir=work_dir, output=data_file_basename)
    cluster.cluster_fingerprints(train_df, labels_column='os_name')

if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))