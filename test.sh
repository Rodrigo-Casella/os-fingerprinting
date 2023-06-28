#!/bin/bash

if [ $# -ne 4 ]; then
  echo "Error: Provide the path to the json file of the clustering, the pcap file or interface for the fingerprint process, the path to the https logs of the capture and the path to the dir where the results will be saved."
  echo "Usage: $0 <path/to/json/file> <path/to/pcap/file | interface> <path/to/https/logs> <path/where/to/save/results>"
  exit 1
fi

clusters_file=$1
input=$2
if [[ $input == *.pcap ]]; then
  input_without_extension=$(basename "$input" .pcap)
else
  input_without_extension=$input
fi
logs_dir=$3
save_to=${4%/}
echo -e "Starting fingerprint process...\n"
python3 fingerprint.py $clusters_file -i $input -d $save_to
echo ""
echo -e "Calculating confusion matrix...\n"
python3 validate_fp.py -l $logs_dir --fp "$save_to/${input_without_extension}_fp.csv" -d $save_to