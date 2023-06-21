import socket
import struct
import dpkt


TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1
SUPPORTED_GROUPS_TYPE = 10

def extract_tcp_features(ip_hdr, tcp_hdr, clean=False):
    tcp_opts = []
    for opt in dpkt.tcp.parse_opts(tcp_hdr.opts):
        tcp_opts.append((opt[0], int.from_bytes(opt[1], 'big')))
    features = {
        'ttl': ip_hdr.ttl,
        'tcp_window': tcp_hdr.win,
        'tcp_opts': tcp_opts
    }
    return features

def extract_tls_featurs(buf):
    try:
        record = dpkt.ssl.TLSRecord(buf)
    except dpkt.dpkt.NeedData as e:
        return None
    if len(record.data) < 4:
        return None
    if record.data[0] != TLS_CLIENT_HELLO or int.from_bytes(record.data[1:4], byteorder='big') < 34:
        return None
    try:
        handshake = dpkt.ssl.TLSHandshake(record.data)
    except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
        return None
    client_hello: dpkt.ssl.TLSClientHello = handshake.data
    supp_groups = []

    if not hasattr(client_hello, 'extensions'):
        return None
    
    for ext_type, ext_data in client_hello.extensions:
        if ext_type == SUPPORTED_GROUPS_TYPE:
            supp_groups_len = struct.unpack('!H', ext_data[:2])[0]
            ptr = 2
            while ptr <= supp_groups_len:
                supp_group = struct.unpack(
                    '!H', ext_data[ptr:ptr + 2])[0]
                ptr += 2
                supp_groups.append(supp_group)
    ciphersuites = [x.code for x in client_hello.ciphersuites]
    features = {
        'ciphersuites': ciphersuites,
        'supp_groups': supp_groups
    }
    return features

def process_pkt(buf):
        try:
            eth_hdr = dpkt.ethernet.Ethernet(buf)
        except dpkt.dpkt.NeedData as e:
            return None

        if not isinstance(eth_hdr.data, dpkt.ip.IP):
            return None

        ip_hdr = eth_hdr.data
        src_ip = socket.inet_ntoa(ip_hdr.src)
        dst_ip = socket.inet_ntoa(ip_hdr.dst)

        if not isinstance(ip_hdr.data, dpkt.tcp.TCP):
            return None

        tcp_hdr = ip_hdr.data
        src_port = tcp_hdr.sport
        dst_port = tcp_hdr.dport

        features = {}
        if tcp_hdr.flags == dpkt.tcp.TH_SYN:
            features = extract_tcp_features(ip_hdr, tcp_hdr)
        elif len(tcp_hdr.data) > 0 and tcp_hdr.data[0] == TLS_HANDSHAKE:
            features = extract_tls_featurs(tcp_hdr.data)
        else:
            return None
            
        if features is not None:
            flow = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
            }

            flow = {**flow, **features}
            return flow

        return None