import argparse
import os
import socket
import time

import dpkt
from pylibpcap import OpenPcap
from pylibpcap.base import Sniff
from pylibpcap.exception import LibpcapError

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1

def log_pkts(log_file, packets):
    if packets:
        for packet in packets:
            log_file.write(f'{packet}\n')
        log_file.flush()


def read_pkt(packets: list, plen, buf, verboseprint):
    if plen <= 0:
        return
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except dpkt.dpkt.NeedData as e:
        verboseprint(e)
        return

    if not isinstance(eth.data, dpkt.ip.IP):
        verboseprint("Not a IPv4 packet")
        return

    ip = eth.data
    if not isinstance(ip.data, dpkt.tcp.TCP):
        verboseprint("Not a TCP packet")
        return

    tcp = ip.data
    src_ip = socket.inet_ntoa(ip.src)
    features = None

    if tcp.flags == dpkt.tcp.TH_SYN:
        verboseprint("Got a TCP SYN packet")
        tcp_opts = []

        for opt in dpkt.tcp.parse_opts(tcp.opts):
            tcp_opts.append((opt[0], int.from_bytes(opt[1], 'big')))

        features = f"{ip.ttl},{tcp.win},{tcp_opts}"
    elif len(tcp.data) > 0 and tcp.data[0] == TLS_HANDSHAKE:
        verboseprint("Got a TLS HANDSHAKE packet")
        try:
            record = dpkt.ssl.TLSRecord(tcp.data)
        except dpkt.dpkt.NeedData as e:
            verboseprint(e)
            return

        if len(record.data) < 4:
            verboseprint("Record data too short")
            return

        if record.data[0] != TLS_CLIENT_HELLO or int.from_bytes(record.data[1:4], byteorder='big') < 34:
            verboseprint("Not a TLS CLIENT HELLO packet")
            return

        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
            verboseprint(e)
            return

        client_hello: dpkt.ssl.TLSClientHello = handshake.data

        features = f"{[x.code for x in client_hello.ciphersuites]}"

    if features is not None:
        pkt = f"{src_ip}: {features}"
        verboseprint(pkt)
        packets.append(pkt)


def offline_capture(input: str, logs_dir, bpf_filter, verboseprint):
    capture = OpenPcap(input, mode="r", filters=bpf_filter)

    packets = []
    with open(f'{logs_dir}{os.sep}{os.path.basename(input.rstrip(".pcap"))}.log', mode="w") as log_file:
        try:
            for plen, ts, buf in capture.read():
                read_pkt(packets, plen, buf, verboseprint)
            log_pkts(log_file, packets)
        except KeyboardInterrupt:
            pass


def live_capture(input, tot_capture_time, log_interval, logs_dir, bpf_filter, verboseprint):
    try:
        sniff = Sniff(input, filters=bpf_filter, promisc=1, timeout=2000)
    except LibpcapError as e:
        print(e)
        exit(1)

    start_time = time.time()
    end_time = start_time + tot_capture_time

    packets = []
    i = 1
    while not tot_capture_time or time.time() < end_time:
        with open(f'{logs_dir}{os.sep}{input}_{i}.log', mode="w") as log_file:
            log_file.write(f'[{time.strftime("%d/%b/%Y:%H:%M:%S %z")}]\n')
            capture_start_time = time.time()
            capture_end_time = capture_start_time + log_interval
            try:
                for plen, ts, buf in sniff.capture():
                    read_pkt(packets, plen, buf, verboseprint)
                    if ts > capture_end_time:
                        break
                log_pkts(log_file, packets)
                packets = []
            except KeyboardInterrupt:
                log_pkts(log_file, packets)
                break
        i += 1


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--input", required=True,
                        help="specify the network interface to capture packets from or pcap file to read")
    parser.add_argument("-d", "--dir", required=True,
                        help="specify the path to the log directory")
    parser.add_argument("-l", "--log_interval", type=int, default=60,
                        help="capture time before flushing the log file and saving the log file (in seconds) (default: 60)")
    parser.add_argument("-t", "--time", type=int, default=0,
                        help="total time to capture packets (in seconds) (default: 0 which means the capture will continue until CTRL-C)")
    parser.add_argument("-f", "--filter", type=str,
                        help="specify a BPF filter to apply (default will capture all TCP-SYN and TLS Client Hello packets)")
    parser.add_argument("-p", "--port", type=int,
                        help="specify a TCP port from which to capture traffic")
    parser.add_argument("-e", "--vlan_tag",
                        help="enable capturing of VLAN tagged packets", action="store_true")
    parser.add_argument("-v", "--verbose",
                        help="enable verbose mode", action="store_true")

    args = parser.parse_args()

    input: str = args.input

    log_interval = args.log_interval

    logs_dir = args.dir
    
    verboseprint = print if args.verbose else lambda *a, **k: None

    # to capture only TCP SYN packets or Client Hello records in TLS Handshakes
    bpf_filter = "(tcp[tcpflags] = tcp-syn or (tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1)))"

    if args.filter is not None:
        bpf_filter = args.filter

    if args.vlan_tag:
        bpf_filter = f'vlan and {bpf_filter}'
    
    if args.port:
        bpf_filter = f'tcp port {args.port} and {bpf_filter}'
    
    verboseprint(f'Bpf filter is: {bpf_filter}')
    
    if not os.path.isdir(logs_dir):
        os.makedirs(os.path.relpath(logs_dir), mode=0o755, exist_ok=True)

    if input.endswith(".pcap"):
        verboseprint("Starting offline capture...")
        offline_capture(input, logs_dir, bpf_filter, verboseprint)
    else:
        verboseprint("Starting live capture...")
        live_capture(input, args.time, log_interval,
                     logs_dir, bpf_filter, verboseprint)


if __name__ == '__main__':
    main()
