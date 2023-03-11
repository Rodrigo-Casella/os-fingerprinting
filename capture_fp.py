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


def print_verbose(to_print, msg):
    if to_print:
        print(msg)
        
def log_pkts(log_file, packets):
    if packets:
        for packet in packets:
            log_file.write(f'{packet}\n')
        log_file.flush()


def read_pkt(packets: list, plen, buf, verbose):
    if plen <= 0:
        return
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except dpkt.dpkt.NeedData:
        return

    if not isinstance(eth.data, dpkt.ip.IP):
        return

    ip = eth.data
    if not isinstance(ip.data, dpkt.tcp.TCP):
        return

    tcp = ip.data
    src_ip = socket.inet_ntoa(ip.src)
    features = None

    if tcp.flags == dpkt.tcp.TH_SYN:
        tcp_opts = []

        for opt in dpkt.tcp.parse_opts(tcp.opts):
            tcp_opts.append((opt[0], int.from_bytes(opt[1], 'big')))

        features = f"{ip.ttl},{tcp.win},{tcp_opts}"
    elif len(tcp.data) > 0 and tcp.data[0] == TLS_HANDSHAKE:
        try:
            record = dpkt.ssl.TLSRecord(tcp.data)
        except dpkt.dpkt.NeedData:
            return

        if len(record.data) < 4:
            return

        if record.data[0] != TLS_CLIENT_HELLO or int.from_bytes(record.data[1:4], byteorder='big') < 34:
            return

        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return

        client_hello: dpkt.ssl.TLSClientHello = handshake.data

        features = f"{[x.code for x in client_hello.ciphersuites]}"

    if features is not None:
        pkt = f"{src_ip}: {features}"
        print_verbose(verbose, pkt)
        packets.append(pkt)


def offline_capture(input: str, logs_dir, bpf_filter, verbose):
    capture = OpenPcap(input, mode="r", filters=bpf_filter)

    packets = []
    with open(f'{logs_dir}{os.sep}{os.path.basename(input.rstrip(".pcap"))}.log', mode="w") as log_file:
        try:
            for plen, ts, buf in capture.read():
                read_pkt(packets, plen, buf, verbose)
            log_pkts(log_file, packets)
        except KeyboardInterrupt:
            pass


def live_capture(input, tot_capture_time, log_interval, logs_dir, bpf_filter, verbose):
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
                    read_pkt(packets, plen, buf, verbose)
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
                        help="network interface to capture packets from or pcap file to read")
    parser.add_argument("-d", "--dir", required=True,
                        help="path to log dir")
    parser.add_argument("-l", "--log_interval", type=int, default=60,
                        help="capture time before to flush the log file (in seconds)")
    parser.add_argument("-t", "--time", type=int, default=0,
                        help="total time to capture packets (in seconds)")
    parser.add_argument("-f", "--filter", type=str,
                        help="bpf filter to apply (default will capture all tcp-syn and tls client hello packet with vlan tag)")
    parser.add_argument("-v", "--verbose",
                        help="enable verbose mode", action="store_true")

    args = parser.parse_args()

    input: str = args.input

    log_interval = args.log_interval

    logs_dir = args.dir
    
    verbose = args.verbose

    # to capture only TCP SYN packets or Client Hello records in TLS Handshakes with VLAN tag
    bpf_filter = "vlan and (tcp[tcpflags] = tcp-syn or (tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1)))"

    if args.filter is not None:
        bpf_filter = args.filter

    if not os.path.isdir(logs_dir):
        os.makedirs(os.path.relpath(logs_dir), mode=0o755, exist_ok=True)

    if input.endswith(".pcap"):
        offline_capture(input, logs_dir, bpf_filter, verbose)
    else:
        live_capture(input, args.time, log_interval, logs_dir, bpf_filter, verbose)


if __name__ == '__main__':
    main()
