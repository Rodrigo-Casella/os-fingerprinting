#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Error: Provide the path to the logs dir and the path to the dir where the results will be saved."
  echo "Usage: $0 <path/to/logs/dir> <path/where/to/save/results>"
  exit 1
fi
logs_dir=$1
logs_dir_basename=$(basename "$logs_dir")
save_to=${2%/}
echo -e "Processing logs files...\n"
python3 process_logs.py -l $logs_dir -d $save_to
echo ""
echo -e "Clustering signatures...\n"
python3 cluster_data.py "$save_to/$logs_dir_basename.csv" -d $save_to