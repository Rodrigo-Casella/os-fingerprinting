import argparse
import os
import time

import pandas as pd
from utils.cluster import Cluster

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("data", type=str, help="csv file with data to cluster")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    args = parser.parse_args()

    data_file = args.data
    df = pd.read_csv(data_file).drop(['extensions_list'], errors='ignore')

    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)
    
    data_file_basename = os.path.splitext(os.path.basename(data_file))[0]
    cluster = Cluster(dir=work_dir, output=data_file_basename)
    cluster.cluster_fingerprints(df, labels_column='os_name')

if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))