#!/bin/bash

bpf_filter='tcp[tcpflags] == tcp-syn or (tcp[tcp[12]/16*4] == 22 and (tcp[tcp[12]/16*4+5] == 1))'
dests=("www.google.com" "www.github.com" "www.unipi.it")
capture_file="./capture.pcap"

tcpdump -i eth0 -w $capture_file $bpf_filter &
tcpdump_pid=$!

sleep 1

for dest in "${dests[@]}"
do
    curl -s https://$dest > /dev/null
done

sleep 2

kill $tcpdump_pid

echo "Traffic captured in file: $capture_file"
