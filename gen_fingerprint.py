import sys
import json
import dpkt
import socket
from suffix_tree import Tree

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1
DLT_RAW = 101

FEATURES_LIST = set(["TLS Cipher List", "TCP/IP Features"])

GREASE_EXT_GRP = [2570, 6682, 10794, 14906, 19018, 23130, 27242,
                  31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250]

GREASE_CIPHER = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
                 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]


def add_ip_tcp_param_to_dict(pkt_features: dict, ip_hdr: dpkt.ip.IP, tcp_hdr: dpkt.tcp.TCP):
    tcp_ip_features = ','.join(map(str, [ip_hdr.ttl, tcp_hdr.win]))

    tcp_options = []
    for option in dpkt.tcp.parse_opts(tcp_hdr.opts):
        if option[0] in [dpkt.tcp.TCP_OPT_TIMESTAMP, dpkt.tcp.TCP_OPT_SACK, dpkt.tcp.TCP_OPT_SACKOK]:
            tcp_options.append((option[0], 0))
        else:
            tcp_options.append((option[0], int.from_bytes(option[1], 'big')))

    tcp_ip_features = ','.join(
        [tcp_ip_features, '-'.join(map(str, tcp_options))])
    pkt_features.update({"TCP/IP Features": tcp_ip_features})


def add_tls_param_to_dict(pkt_features: dict, tls_client_hello: dpkt.ssl.TLSClientHello):
    cipher_list = tls_client_hello.ciphersuites

    for cipher in cipher_list.copy():
        if cipher.code in GREASE_CIPHER:
            cipher_list.remove(cipher)
    ciphersuites = ','.join([hex(x.code) for x in cipher_list])
    pkt_features.update({"TLS Cipher List": ciphersuites})


def dump_pcap(pcap):
    fp = open(pcap, "rb")
    try:
        capture = dpkt.pcap.Reader(fp)
    except ValueError as pcap_err:
        raise pcap_err

    linktype = capture.datalink()
    if linktype not in [dpkt.pcap.DLT_EN10MB, DLT_RAW]:
        print("Datalink is not Ethernet or Raw: " + f'{capture.datalink()}')
        return {}

    flows: dict[str, dict] = {}
    
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

        flow = f'{socket.inet_ntop(socket.AF_INET, ip.src)}:{tcp.sport} -> {socket.inet_ntop(socket.AF_INET, ip.dst)}:{tcp.dport}'

        pkt_features: dict[str, str] = {}

        if tcp.flags == dpkt.tcp.TH_SYN:
            add_ip_tcp_param_to_dict(pkt_features, ip, tcp)
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

                add_tls_param_to_dict(pkt_features, handshake.data)

        if pkt_features == {}:
            continue
        
        if flow in flows:
            pkt_features.update(flows.get(flow))
            
        flows[flow] = pkt_features

    for flow, features in flows.copy().items():
        if FEATURES_LIST.difference(features.keys()) != set():
            flows.pop(flow)

    with open("flows.json", "w") as outfile:
        json_data = json.dumps(flows, indent=1)
        outfile.write(json_data)

    return flows


def produce_sign(input):
    flows = dump_pcap(input)
    if flows == {}:
        print("No flows detected")
        return

    signatures = []
    for features in flows.values():
        if features not in signatures:
            signatures.append(features)
    print("Total Flows: " + f'{len(flows)}')
    print("Total Signatures: " + f'{len(signatures)}')

    ciphersuites = [x["TLS Cipher List"] for x in signatures]
    tree = Tree()

    for idx, ciphersuite in enumerate(ciphersuites):
        hex_cipher = [cipher for cipher in ciphersuite.split(',')]
        tree.add(idx, hex_cipher)

    max_rep = []
    for k, path in sorted(tree.maximal_repeats()):
        max_rep.append(f'{k}: ' + str(path).replace(' ', ','))

    signatures.append(max_rep)

    with open("sign.json", "w") as outfile:
        json_data = json.dumps(signatures, indent=1)
        outfile.write(json_data)


def main():
    if len(sys.argv) < 2:
        print("You must provide a pcap file")
        sys.exit()

    produce_sign(sys.argv[1])


if __name__ == '__main__':
    main()
