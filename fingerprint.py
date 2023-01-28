import sys
import os
import json
from scapy.all import Packet, sniff, rdpcap
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import *

FEATURES_LIST = set(["TLS Cipher List", "TLS Extension List",
                     "TLS Supported Groups", "TTL", "Window Size", "TCP Options"])

GREASE_EXT_GRP = ["2570", "6682", "10794", "14906", "19018", "23130",
                  "27242", "31354", "35466", "39578", "43690", "47802", "51914", "56026", "60138", "64250"]

GREASE_CIPHER = ["0xa0a", "0x0a0a", "0x1a1a", "0x2a2a", "0x3a3a", "0x4a4a", "0x5a5a", "0x6a6a",
                 "0x7a7a", "0x8a8a", "0x9a9a", "0xaaaa", "0xbaba", "0xcaca", "0xdada", "0xeaea", "0xfafa"]


def add_tcp_param_to_dict(pkt_features: dict, packet: Packet):
    pkt_features.update({"TTL": f'{packet.getlayer(IP).ttl}'})
    pkt_features.update({"Window Size": f'{packet[TCP].window}'})

    tcp_options = []
    for option in packet[TCP].options:
        if option[0] in ["Timestamp", "SAck", "SAckOK", "NOP", "EOL"]:
            tcp_options.append((option[0], None))
        else:
            tcp_options.append(option)
    pkt_features.update({"TCP Options": f'{tcp_options}'})


def add_tls_param_to_dict(pkt_features: dict, packet: Packet, tls_cls):
    # Scapy return a string not a list
    cipher_str = packet[tls_cls].get_field("ciphers").i2repr(
        packet[tls_cls], packet[tls_cls].ciphers)
    
    cipher_str = cipher_str[1:len(cipher_str) - 1]
    cipher_list = cipher_str.split(", ")

    for cipher in cipher_list.copy():
        if cipher in GREASE_CIPHER:
            cipher_list.remove(cipher)

    pkt_features.update({"TLS Cipher List": f'{cipher_list}'})

    ext_list = list(ext.get_field("type").i2repr(
        ext, ext.getfieldval("type")) for ext in packet[tls_cls].ext)

    for ext in ext_list.copy():
        if ext in GREASE_EXT_GRP:
            ext_list.remove(ext)

    pkt_features.update({"TLS Extension List": f'{ext_list}'})

    for ext in packet[tls_cls].ext:
        if isinstance(ext, TLS_Ext_SupportedGroups):
            # Scapy return a string not a list
            groups_str = ext.get_field(
                "groups").i2repr(ext.groups, ext.getfieldval("groups"))
            
    groups_str = groups_str[1:len(groups_str) - 1]
    groups = groups_str.split(", ")
    
    for group in groups.copy():
        if group in GREASE_EXT_GRP:
            groups.remove(group)

    pkt_features.update({"TLS Supported Groups": f'{groups}'})


def dump_pcap(input):
    if os.path.isfile(input):
        packets = rdpcap(input)
    else:
        print(f'{input}' + " not a file")
        return {}

    sessions = {}
    for packet in packets:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            continue

        pkt_features = {}
        session = f'{packet[IP].src}:{packet[TCP].sport}'

        if packet[TCP].flags == "S":
            add_tcp_param_to_dict(pkt_features, packet)
        elif packet.haslayer(TLSClientHello):
            add_tls_param_to_dict(pkt_features, packet, TLSClientHello)
        elif packet.haslayer(TLS13ClientHello):
            add_tls_param_to_dict(pkt_features, packet, TLS13ClientHello)

        if session not in sessions and pkt_features != {}:
            sessions[session] = pkt_features
        elif session in sessions and pkt_features != {}:
            pkt_features.update(sessions.get(session))
            sessions[session] = pkt_features

    for session, features in sessions.copy().items():
        if FEATURES_LIST.difference(features.keys()) != set():
            sessions.pop(session)

    outfile = open("flows.json", "w")
    json_data = json.dumps(sessions, indent=1)
    outfile.write(json_data)
    return sessions


def produce_sign(input):
    sessions = dump_pcap(input)
    if sessions == {}:
        print("No flows detected")
        return

    signatures = []
    for features in sessions.values():
        if features not in signatures:
            signatures.append(features)
    print("Total Sessions: " + f'{len(sessions)}')
    print("Total Signatures: " + f'{len(signatures)}')
    outfile = open("sign.json", "w")
    json_data = json.dumps(signatures, indent=1)
    outfile.write(json_data)


def main():
    if len(sys.argv) < 2:
        print("You must provide a pcap file")
        sys.exit()

    produce_sign(sys.argv[1])


if __name__ == '__main__':
    main()
