import sys
import os
import json
from scapy.all import *
from scapy.layers.tls.all import *


def tls_param_to_dict(pkt_features: dict, packet: Packet, tls_cls):
    pkt_features.update({"TLS Cipher List": packet[tls_cls].get_field(
        "ciphers").i2repr(packet[tls_cls], packet[tls_cls].ciphers)})

    pkt_features.update({"TLS Extension List": ', '.join([ext.get_field("type").i2repr(
        ext, ext.getfieldval("type")) for ext in packet[tls_cls].ext])})

    for ext in packet[tls_cls].ext:
        if isinstance(ext, TLS_Ext_SupportedGroups):
            pkt_features.update({"TLS Supported Groups": ext.get_field(
                "groups").i2repr(ext.groups, ext.getfieldval("groups"))})


def dump_pkt(input):
    if os.path.isfile(input):
        packets = rdpcap(input)
    else:
        bpf_filter = "tcp[tcpflags] & tcp-syn != 0 or (tcp[tcp[12]/16*4] == 22 and (tcp[tcp[12]/16*4+5] == 1))"
        packets = sniff(count=10, filter=bpf_filter, iface=input)
    outfile = open("data.json", "a")
    flows = {}
    for index, packet in enumerate(packets):
        pkt_features = {}
        flow = f'{packet[IP].src}:{packet[TCP].sport}'
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            pkt_features.update({"TTL": f'{packet[IP].ttl}'})
            pkt_features.update({"Window Size": f'{packet[TCP].window}'})
            pkt_features.update({"TCP Options": f'{packet[TCP].options}'})
        elif packet.haslayer(TLSClientHello):
            tls_param_to_dict(pkt_features, packet, TLSClientHello)
        elif packet.haslayer(TLS13ClientHello):
            tls_param_to_dict(pkt_features, packet, TLS13ClientHello)
        if flow not in flows and pkt_features != {}:
            flows[flow] = pkt_features
        elif flow in flows and pkt_features != {}:
            pkt_features.update(flows.get(flow))
            flows[flow] = pkt_features
    
    json_data = json.dumps(flows, indent=1)
    print(json_data)
    outfile.write(json_data)

def main():
    if len(sys.argv) < 2:
        print("You must provide either an interface or a pcap file path")
        sys.exit()

    dump_pkt(sys.argv[1])


if __name__ == '__main__':
    main()
