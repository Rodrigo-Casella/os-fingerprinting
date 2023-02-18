import argparse
import socket
import time
from os import sep

import dpkt
from pylibpcap.base import Sniff
from pylibpcap import OpenPcap
from pylibpcap.exception import LibpcapError

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1

# to capture only TCP SYN packets or Client Hello records in TLS Handshakes with VLAN tag
BPF_FILTER = "(tcp[tcpflags] = tcp-syn or (tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1)))"


def log(log_file, packets):
    if packets:
        for packet in packets:
            log_file.write(f"{packet[0]}: {packet[1]}\n")
        log_file.flush()


def read_pkt(packets: list, plen, buf):
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
        
        if record.data[0] == TLS_CLIENT_HELLO and int.from_bytes(record.data[1:4], byteorder='big') > 0:
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.ssl.SSL3Exception or dpkt.dpkt.NeedData:
                return
            
            client_hello: dpkt.ssl.TLSClientHello = handshake.data
            features = f"{[x.code for x in client_hello.ciphersuites]}"
            
    if features is not None:
        packets.append((src_ip, features))


def offline_capture(input, log_file):
    capture = OpenPcap(input, mode="r", filters=BPF_FILTER)

    packets = []
    try:
        for plen, ts, buf in capture.read():
            read_pkt(packets, plen, buf)
        log(log_file, packets)
    except KeyboardInterrupt:
        pass


def live_capture(input, tot_capture_time, log_interval, log_file):
    try:
        sniff = Sniff(input, filters=BPF_FILTER, promisc=1, timeout=5000)
    except LibpcapError as e:
        print(e)
        exit(1)

    start_time = time.time()
    end_time = start_time + tot_capture_time

    packets = []

    while time.time() < end_time or not tot_capture_time:
        capture_start_time = time.time()
        capture_end_time = capture_start_time + log_interval

        try:
            for plen, ts, buf in sniff.capture():
                read_pkt(packets, plen, buf)

                if ts > capture_end_time:
                    break
            log(log_file, packets)
            packets = []
        except KeyboardInterrupt:
            break

    log(log_file, packets)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True,
                        help="network interface to capture packets from or pcap file to read")
    parser.add_argument("-d", "--dir", required=True,
                        help="path to log dir")
    parser.add_argument("-l", "--log_interval", type=int, default=60,
                        help="capture time before to write the log file (in seconds)")
    parser.add_argument("-t", "--time", type=int, default=0,
                        help="total time to capture packets (in seconds)")
    args = parser.parse_args()

    input: str = args.input

    log_interval = args.log_interval

    log_filename = f"{args.dir}{sep}capture.log"
    log_file = open(log_filename, "w")

    if input.endswith(".pcap"):
        offline_capture(input, log_file)
    else:
        live_capture(input, args.time, log_interval, log_file)

    log_file.close()


if __name__ == '__main__':
    main()
