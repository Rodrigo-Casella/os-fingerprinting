import argparse
import json
import math
import os
import sys
import time

import numpy as np
import pandas as pd
from utils.capture import Capture
from utils.pkt_process import process_pkt

FEATURES_SET = {'ttl', 'tcp_window', 'mss', 'win_scale',
                'tcp_opts', 'ciphersuites', 'supp_groups'}

COMPLETE_FLOW = {'ttl', 'tcp_window', 'tcp_opts', 'ciphersuites', 'supp_groups'}

BPF_FILTER = "tcp port 443 and (tcp[tcpflags] = tcp-syn or (tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1)))"

TCP_OPT_MMS = 2
TCP_OPT_WS = 3

GREASE = range(2570, 64251, 4112)


def json2dict(filename):
    with open(filename, "r") as fp:
        clusters_dict = json.load(fp)
    return clusters_dict


def key_from_flow(flow):
    return f"{flow['src_ip']}:{flow['src_port']}"


def de_grease_tls(lst):
    return '-'.join([f"{elem}" for elem in lst if elem not in GREASE])


def flow2str_repr(flow):
    exponent = math.ceil(math.log2(int(flow['ttl'])))
    flow['ttl'] = 2 ** exponent
    if flow['ttl'] > 255:
        flow['ttl'] = 255
    flow['win_scale'] = 0
    flow['mss'] = 0
    tcp_opts_str = ''
    for (type, value) in flow['tcp_opts']:
        tcp_opts_str += f"{type}-"
        if type == TCP_OPT_MMS:
            flow['mss'] = value
        if type == TCP_OPT_WS:
            flow['win_scale'] = value
    flow['tcp_opts'] = tcp_opts_str[:-1]
    flow['ciphersuites'] = de_grease_tls(flow['ciphersuites'])
    flow['supp_groups'] = de_grease_tls(flow['supp_groups'])
    return f"{flow['ttl']},{flow['tcp_window']},{flow['mss']},{flow['win_scale']},{flow['tcp_opts']},{flow['ciphersuites']},{flow['supp_groups']}"


class Fingerprinter:

    def __init__(self, database, output_dir):
        self.database = json2dict(database)
        self.output_dir = output_dir
        self.flows = {}
        self.fingerprints = []


    def process(self, input):
        handler = Capture(input, filter=BPF_FILTER, immediate_mode=True, timeout=50)
        try:
            for _, buf in handler.read():
                flow = process_pkt(buf)
                if not flow:
                    continue        
                flow_key = key_from_flow(flow)
                if flow_key in self.flows:
                    if 'ttl' in self.flows[flow_key] and 'ciphersuites' in flow:
                        self.flows[flow_key] = {**self.flows[flow_key], **flow}
                        flow_repr = flow2str_repr(self.flows[flow_key])
                        self._search_fingerprint(flow_key, flow_repr)
                    del self.flows[flow_key]
                    continue
                self.flows.update({flow_key: flow})
        except KeyboardInterrupt:
            pass
        for flow_key in self.flows:
            if self.flows[flow_key].keys() >= COMPLETE_FLOW:
                flow_repr = flow2str_repr(self.flows[flow_key])
                self._search_fingerprint(flow_key, flow_repr)
        df = pd.DataFrame(self.fingerprints)
        df['flow_key'] = df['flow_key'].str.split(':').str[0]
        df.drop_duplicates(inplace=True)
        outfile = os.path.splitext(os.path.basename(input))[0]
        df.to_csv(f"{os.path.join(self.output_dir, outfile)}_fp.csv", sep=';', na_rep='Nan', index=False)


    def _search_fingerprint(self, flow_key, fp_str):
        fingerprint = {'flow_key' : flow_key, 'match': "No match in db", 'cluster_id': -1, 'fp_repr': fp_str}
        for cluster_id in self.database:
            if fp_str in self.database[cluster_id]['Fingerprints']:
                fingerprint['cluster_id'] = cluster_id
                fingerprint['match'] = f"{[f'{k}: {v}' for k, v in self.database[cluster_id]['Os_percetange'].items()]}"
                break
        self.fingerprints.append(fingerprint)
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("json", type=str,
                        help="json file of the db")
    parser.add_argument("-i", "--input", required=True,
                        help="specify the network interface to capture packets from or pcap file to read")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    args = parser.parse_args()
    database_file = args.json
    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)
    fingerprinter = Fingerprinter(database_file, output_dir=args.dir)
    fingerprinter.process(args.input)
    


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
