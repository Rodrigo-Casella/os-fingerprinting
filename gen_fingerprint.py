import sys
import json
from typing import List
import dpkt
import argparse
from suffix_tree import Tree

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1
DLT_RAW = 101

FEATURES_LIST = set(["TLS Cipher List", "TCP/IP Features"])

GREASE_EXT_GRP = [2570, 6682, 10794, 14906, 19018, 23130, 27242,
                  31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250]

GREASE_CIPHER = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
                 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]


def tcp_ip_param2str(ip_hdr: dpkt.ip.IP, tcp_hdr: dpkt.tcp.TCP):
    tcp_ip_features_str = ','.join(map(str, [ip_hdr.ttl, tcp_hdr.win]))

    tcp_options = []
    for option in dpkt.tcp.parse_opts(tcp_hdr.opts):
        if option[0] in [dpkt.tcp.TCP_OPT_TIMESTAMP, dpkt.tcp.TCP_OPT_SACK, dpkt.tcp.TCP_OPT_SACKOK]:
            tcp_options.append((option[0], 0))
        else:
            tcp_options.append((option[0], int.from_bytes(option[1], 'big')))

    tcp_ip_features_str = ','.join(
        [tcp_ip_features_str, '-'.join(map(str, tcp_options))])

    return tcp_ip_features_str


def tls_param2list_of_str(tls_client_hello: dpkt.ssl.TLSClientHello):
    cipher_list = tls_client_hello.ciphersuites

    for cipher in cipher_list.copy():
        if cipher.code in GREASE_CIPHER:
            cipher_list.remove(cipher)

    ciphersuites = [hex(x.code) for x in cipher_list]
    return ciphersuites


def extract_features_from_pcap(capture):
    linktype = capture.datalink()

    if linktype not in [dpkt.pcap.DLT_EN10MB, DLT_RAW]:
        print("Datalink is not Ethernet or Raw: " + f'{capture.datalink()}')
        return None

    tcp_ip_param_list: "list[str]" = []
    tls_param_list: "list[list[str]]" = []

    decoder = dpkt.ethernet.Ethernet

    if linktype == DLT_RAW:
        decoder = dpkt.ip.IP

    for ts, buf in capture:
        try:
            pkt_data = decoder(buf)
        except dpkt.UnpackError:
            continue

        if isinstance(pkt_data, dpkt.ethernet.Ethernet):
            pkt_data = pkt_data.data

        if not isinstance(pkt_data, dpkt.ip.IP):
            continue

        if not isinstance(pkt_data.data, dpkt.tcp.TCP):
            continue

        ip = pkt_data
        tcp = ip.data

        if tcp.flags == dpkt.tcp.TH_SYN:
            tcp_ip_str = tcp_ip_param2str(ip, tcp)
            if tcp_ip_str not in tcp_ip_param_list:
                tcp_ip_param_list.append(tcp_ip_str)
        elif len(tcp.data) > 0 and tcp.data[0] == TLS_HANDSHAKE:
            try:
                record = dpkt.ssl.TLSRecord(tcp.data)
            except dpkt.dpkt.NeedData:
                continue

            if record.data[0] == TLS_CLIENT_HELLO:
                try:
                    handshake = dpkt.ssl.TLSHandshake(record.data)
                except dpkt.ssl.SSL3Exception:
                    continue

                tls_str = tls_param2list_of_str(handshake.data)
                if tls_str not in tls_param_list:
                    tls_param_list.append(tls_str)

    return (tcp_ip_param_list, tls_param_list)


def get_max_rep_from_list_of_lists(list_of_lists: "list[list[str]]", sep: "str | None" = ","):
    """Get a list of maximal repeats from a set of lists of strings.

        The list will have only maximal repeats with more than one element.
    """
    tree = Tree()

    for idx, lst in enumerate(list_of_lists):
        tree.add(idx, lst)

    max_rep = []
    for k, path in sorted(tree.maximal_repeats()):
        if len(path) < 2:
            continue
        max_rep.append(str(path).replace(' ', sep))
    return max_rep


def produce_fingeprint(capture):
    features = extract_features_from_pcap(capture)
    if features is None:
        print("No features extracted")
        return None

    fingerprint = {"TCP/IP Features": [], "Ciphers Max Repeats": []}

    fingerprint["TCP/IP Features"] = list(features[0])

    fingerprint["Ciphers Max Repeats"] = get_max_rep_from_list_of_lists(
        features[1])

    print("Total Unique TCP/IP Features: " +
          f'{len(fingerprint["TCP/IP Features"])}')
    print("Maximal repeats in TLS Ciphersuites Lists: " +
          f'{len(fingerprint["Ciphers Max Repeats"])}')

    return fingerprint


def write_dict_to_json(filename: str, dict: dict):
    with open(filename, "w") as outfile:
        json_data = json.dumps(dict, indent=1)
        outfile.write(json_data)


def load_db(db_path: str):
    db = None
    try:
        fp = open(db_path, "r")
        db = json.load(fp)
    except FileNotFoundError:
        pass
    return db


def update_db(os2fingerprint: "dict[str, dict[str, list]]", fp_os: str, db: "dict[str, dict[str, list]] | None"):
    if db is None:
        return os2fingerprint

    if fp_os not in db:
        db[fp_os] = {"TCP/IP Features": [], "Ciphers Max Repeats": []}

    tcp_ip_fp_set = set(db[fp_os]["TCP/IP Features"])

    for tcp_ip_fp in os2fingerprint[fp_os]["TCP/IP Features"]:
        tcp_ip_fp_set.add(tcp_ip_fp)

    db[fp_os]["TCP/IP Features"] = list(tcp_ip_fp_set)

    os2tls_fp = {}

    for os in db.keys():
        if os != fp_os:
            os2tls_fp[os] = set(db[os]["Ciphers Max Repeats"])

    tls_fp_set = set(db[fp_os]["Ciphers Max Repeats"])
    
    tls_fp_set.update(os2fingerprint[fp_os]["Ciphers Max Repeats"])
    
    for os, tls_fp in os2tls_fp.items():
        tls_fp_set.difference_update(tls_fp)
        tls_fp.difference_update(os2fingerprint[fp_os]["Ciphers Max Repeats"])
    
    db[fp_os]["Ciphers Max Repeats"] = list(tls_fp_set)
    
    for os, tls_fp in os2tls_fp.items():
        db[os]["Ciphers Max Repeats"] = list(tls_fp)
        
    return db


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap", help="pcap file to process")
    parser.add_argument("-o", "--os", required=True, action="store",
                        help="Name of the operative system fingerprint to add to database")
    parser.add_argument("-d", "--db", required=False, action="store", default="new_db.json",
                        help="Databese json to read or create and add fingerprint")

    args = parser.parse_args()

    if args.os is None:
        print("You need to specify a the operative system to fingerprint")
        sys.exit()

    fingerprint = None

    with open(args.pcap, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as pcap_err:
            raise pcap_err
        fingerprint = produce_fingeprint(capture)

    if fingerprint is None:
        print("No fingerprint detected")
        sys.exit()

    os2fingerprint = {args.os: fingerprint}

    db = None
    if not args.db is None:
        db = load_db(args.db)

    db = update_db(os2fingerprint, args.os, db)

    write_dict_to_json(args.db, db)


if __name__ == '__main__':
    main()
