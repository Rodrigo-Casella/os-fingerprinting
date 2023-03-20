# os-fingerprinting

The script captures network packets either from a live network interface or a pcap file and logs TCP-SYN or TLS Client Hello parameters from each packet to multiples log files.

## Requirements

- Python 3.8+
- <code>apt-get install libpcap-dev</code>
- <code>python3 -m pip install 'Cython>=0.29.33'</code>
- <code>python3 -m pip install -r requirements.txt</code>

## Usage

<code>sudo -E python3 packet_capture.py [-h] -i INPUT -d DIR [-l LOG_INTERVAL] [-t TIME] [-f FILTER] [-p PORT] [-e] [-v]</code>

### Arguments
- `-h, --help`: show the help message and exit
- `-i INPUT, --input INPUT:` specify the network interface to capture packets from or pcap file to read
- `-d DIR, --dir DIR`: specify the path to the log directory
- `-l LOG_INTERVAL, --log_interval LOG_INTERVAL`: capture time before flushing the log file and saving the log file (in seconds) (default: 60)
- `-t TIME, --time TIME`: total time to capture packets (in seconds) (default: 0 which means the capture will continue until interrupted)
- `-f FILTER, --filter FILTER`: specify a BPF filter to apply (default will capture all TCP-SYN and TLS Client Hello packets)
- `-p PORT, --port PORT`: specify a TCP port from which to capture traffic
- `-e, --vlan_tag`: enable capturing of VLAN tagged packets
- `-v, --verbose`: enable verbose mode
### Examples:

Capture packets from a live network interface, log them to the `logs` directory and enable verbose mode:

<code>sudo -E python3 capture_fp.py -i eth0 -d logs -v</code>

CTRL + C to stop the script

Capture packets from a live network interface, log them to the `logs` directory and write a log file every `60` seconds for a total of `300` seconds:

<code>sudo -E python3 capture_fp.py -i eth0 -d logs -l 60 -t 300</code>

Capture packets from a pcap file, log them to the `logs` directory:

<code>sudo -E python3 capture_fp.py -i capture.pcap -d logs</code>

## Output

Log file with source IP address and features of the packet, such as IP TTL, TCP window size, TCP option list or TLS ciphersuites:

```log
[08/Mar/2023:12:41:07 +0100]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 17850703239813529600), (1, 0), (3, 7)]
172.27.5.66: [4866, 4867, 4865, 4868, 49196, 52393, 49325, 49162, 49195, 49324, 49161, 49200, 52392, 49172, 49199, 49171, 157, 49309, 53, 156, 49308, 47, 159, 52394, 49311, 57, 158, 49310, 51]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 13103132311635886080), (1, 0), (3, 7)]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 5744936066012413952), (1, 0), (3, 7)]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 2366747479422009344), (1, 0), (3, 7)]
172.27.5.66: [4866, 4867, 4865, 4868, 49196, 52393, 49325, 49162, 49195, 49324, 49161, 49200, 52392, 49172, 49199, 49171, 157, 49309, 53, 156, 49308, 47, 159, 52394, 49311, 57, 158, 49310, 51]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 17850703849698885632), (1, 0), (3, 7)]
172.27.5.66: [4866, 4867, 4865, 4868, 49196, 52393, 49325, 49162, 49195, 49324, 49161, 49200, 52392, 49172, 49199, 49171, 157, 49309, 53, 156, 49308, 47, 159, 52394, 49311, 57, 158, 49310, 51]
```
