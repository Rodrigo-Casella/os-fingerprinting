import math
import re

from user_agents import parse

GREASE = range(2570, 64251, 4112)

TPL_REGEX_PATTERN = re.compile(r'\((\d+), (\d+)\)')
TCP_OPT_WS = '3'
TCP_OPT_MMS = '2'
SAVE_VALUE_TCP_OPT = {TCP_OPT_MMS, TCP_OPT_WS}

NOT_LINUX_UAS = {'Windows', 'Mac OS X', 'iOS', 'Linux'}

FEATURES_SET = ['os_name', 'ttl', 'ws',
                'mss', 'win_scale', 'tcp_opts', 'ciphersuites', 'extensions_list', 'supported_groups']

IPV4_PATTERN = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')

def is_ipv4_address(ip_address_str):
    return IPV4_PATTERN.match(ip_address_str)


def parse_user_agent_file(log_file, hosts):
    with open(log_file, mode="r") as fp:
        for line in fp:
            ip_string, log_entry = line.split(' ', maxsplit=1)
            if not is_ipv4_address(ip_string):
                continue
            if ip_string in hosts:
                continue
            hosts[ip_string] = {}
            log_entry = log_entry.split('\" \"', maxsplit=1)
            if len(log_entry) < 2:
                del hosts[ip_string]
                continue
            user_agent = parse(log_entry[-1])
            os_name = f'{user_agent.os.family}'.strip()
            if os_name != "Other":
                if os_name not in NOT_LINUX_UAS:
                    os_name = 'Linux'
                hosts[ip_string]['os_name'] = os_name
                continue
            del hosts[ip_string]


def parse_features_file(host2features: "dict[str, dict[str, str]]", log_file):
    with open(log_file, 'r') as fp:
        fp.readline()
        for line in fp:
            ip_string, feature = line.rstrip().split(": ")
            if ip_string not in host2features:
                continue
            host = host2features[ip_string]
            if feature.startswith("["):
                if host.get('ciphersuites', None):
                    continue
                feature_lst = extract_tls_features(feature)
                if len(feature_lst) > 2:
                    host['ciphersuites'],  host['extensions_list'], host['supported_groups'] = feature_lst
                else:
                    host['ciphersuites'], host['supported_groups'] = feature_lst
                continue
            if host.get('ttl', None):
                continue
            host['ttl'], host['ws'], host['mss'], host['win_scale'], host['tcp_opts'] = extract_tcp_ip_features(
                feature)
            
            
def extract_tls_features(features_str: str) -> "list[str]":
    features_lst = []
    for feature in features_str.split('],['):
        features_lst.append('-'.join([element for element in feature.lstrip(
            '[').rstrip(']').split(', ') if int(element) not in GREASE]))
    return features_lst


def extract_tcp_ip_features(feature: str) -> "tuple[str, str, str, str, str]":
    ttl_str, windowSize_str, tcp_opts_str = feature.split(',', maxsplit=2)
    exponent = math.ceil(math.log2(int(ttl_str)))
    ttl_int = 2 ** exponent
    if ttl_int > 255:
        ttl_int = 255
        
    tpl_lst = TPL_REGEX_PATTERN.findall(tcp_opts_str)
    tcp_opts_str = ''
    maximumSegmentSize_str = '0'
    windowScaling_str = '0'
    for (option, value) in tpl_lst:
        tcp_opts_str += f'{option}-'
        if option == TCP_OPT_MMS:
            maximumSegmentSize_str = value
            continue
        if option == TCP_OPT_WS:
            windowScaling_str = value
    return f'{ttl_int}', f'{windowSize_str}', f'{maximumSegmentSize_str}', f'{windowScaling_str}', f'{tcp_opts_str[:-1]}'