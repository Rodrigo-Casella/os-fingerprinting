import argparse
import os
import time

from utils.capture import Capture
from utils.pkt_process import process_pkt

SKIP_KEYS = {'src_ip', 'dst_ip', 'src_port', 'dst_port'}


def flow2string(flow):
    pkt_log = f"{flow['src_ip']}: "
    for key in flow.keys():
        if key in SKIP_KEYS:
            continue
        pkt_log += f"{flow[key]},"
    return pkt_log[:-1]


def capture_and_log(input: str, *, capture_filter=None, tot_capture_time=0, log_interval=0, filename, logs_dir, to_print):
    capture_handle = Capture(input, filter=capture_filter,
                             immediate_mode=True, timeout=50)
    end_time = 0
    if tot_capture_time:
        end_time = time.time() + tot_capture_time
    i = 1
    while not tot_capture_time or time.time() < end_time:
        with open(os.path.join(logs_dir, f'{filename}_{i}.log'), mode="w") as log_file:
            capture_end_time = 0
            if log_interval:
                log_file.write(f'[{time.strftime("%d/%b/%Y:%H:%M:%S %z")}]\n')
                capture_end_time = time.time() + log_interval
            try:
                for ts, buf in capture_handle.read():
                    if log_interval and ts > capture_end_time:
                        break
                    flow = process_pkt(buf)
                    if not flow:
                        continue
                    pkt_log = flow2string(flow)
                    to_print(pkt_log)
                    log_file.write(f'{pkt_log}\n')
                    log_file.flush()
                if not log_interval:
                    break
            except KeyboardInterrupt:
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
    if args.filter:
        bpf_filter = args.filter
    if args.vlan_tag:
        bpf_filter = f'vlan and {bpf_filter}'
    if args.port:
        bpf_filter = f'tcp port {args.port} and {bpf_filter}'
    verboseprint(f'Bpf filter is: {bpf_filter}')
    if not os.path.isdir(logs_dir):
        os.makedirs(os.path.relpath(logs_dir), mode=0o755, exist_ok=True)
    if '.pcap' in input:
        verboseprint("Starting offline capture...")
        capture_and_log(input, capture_filter=bpf_filter, filename=os.path.basename(
            input.rstrip(".pcap")), logs_dir=logs_dir, to_print=verboseprint)
    else:
        verboseprint("Starting live capture...")
        capture_and_log(input, capture_filter=bpf_filter, tot_capture_time=args.time,
                        log_interval=log_interval, filename=input, logs_dir=logs_dir, to_print=verboseprint)


if __name__ == '__main__':
    main()
