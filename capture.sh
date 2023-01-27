#!/bin/bash

# BPF filter for capturing TCP SYN packets and TLS Client Hello messages
#bpf_filter='tcp[tcpflags] & tcp-syn != 0 or (tcp[((tcp[12] & 0xf0) >> 2) + 5] == 22)'
bpf_filter='tcp[tcpflags] == tcp-syn or (tcp[tcp[12]/16*4] == 22 and (tcp[tcp[12]/16*4+5] == 1))'
# Target server and port
dests=("www.google.com" "www.youtube.com" "www.unipi.it")
#server="www.google.com"
port=443

# Capture file name
capture_file="./capture.pcap"

# Capture the traffic using tcpdump
tcpdump -i eth0 -w $capture_file $bpf_filter &

# save the pid of the tcpdump process
tcpdump_pid=$!

# wait for 2 seconds before starting httperf
sleep 1

for dest in "${dests[@]}"
do
    # Use openssl s_client to connect to the destination
    openssl s_client -connect $dest:443 < /dev/null > /dev/null
    if [ $? -eq 0 ]; then
    echo "Connected to $dest successfully"
    else
    echo "Unable to connect to $dest"
    fi
    curl https://$dest
done

# Generate traffic using httperf for 30 seconds
#httperf --server=$server --port=$port --wsess=10,5,2 --rate=1 --timeout=5 --ssl --ssl-no-reuse

# wait for 2 seconds after httperf finishes
sleep 5

# stop the tcpdump capture
kill $tcpdump_pid

# print the output
echo "Traffic captured in file: $capture_file"
