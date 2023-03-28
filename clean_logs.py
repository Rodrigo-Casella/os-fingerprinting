import argparse
import os
import re
import sys
import time

import pandas as pd
from user_agents import parse

GREASE = range(2570, 64251, 4112)

TPL_REGEX_PATTERN = re.compile(r'\((\d+), (\d+)\)')
TCP_OPT_TIMESTAMP = '8'
TCP_OPT_MPTCP = '30'
SKIP_VALUE_TCP_OPT = {TCP_OPT_TIMESTAMP, TCP_OPT_MPTCP}

UNIX_UAS = {'Debian', 'Ubuntu', 'CentOS', 'FreeBSD', 'Chrome OS'}

FEATURES_SET = {'tcp', 'tls', 'user_agent'}

IPV4_PATTERN = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')


def is_ipv4_address(ip_address_str):
    return IPV4_PATTERN.match(ip_address_str)


def extract_cipher_list(feature: str) -> str:
    cipher_list = feature[1:-1].split(', ')
    cipher_list = [cipher for cipher in cipher_list if int(cipher) not in GREASE]
    return ','.join(cipher_list)


def extract_tcp_ip_features(feature: str) -> str:
    ttl_str, ws, tcp_opts_str = feature.split(',', maxsplit=2)

    ttl_int = int(ttl_str)

    if ttl_int < 32:
        ttl_int = 64
    elif ttl_int > 32 and ttl_int < 64:
        ttl_int = 64
    elif ttl_int > 64 and ttl_int < 128:
        ttl_int = 128
    elif ttl_int > 128 and ttl_int < 255:
        ttl_int = 255

    tpl_lst = TPL_REGEX_PATTERN.findall(tcp_opts_str)

    tcp_opts_str = ''
    for (option, value) in tpl_lst:
        tcp_opts_str += f'{option},'

        if option in SKIP_VALUE_TCP_OPT:
            continue

        if value != '0':
            # tcp_opts_str = tcp_opts_str[:-1] + f'.{value},'
            tcp_opts_str += f'{value},'

    return f'{ttl_int},{ws},{tcp_opts_str[:-1]}'


def parse_features_file(host2features: "dict[str, dict[str, str]]", log_file):
    with open(log_file, 'r') as fp:
        fp.readline()
        for line in fp:
            ip_string, feature = line.rstrip().split(": ")
            feature_kind = 'tcp'

            if feature.startswith("["):
                feature_kind = 'tls'
                feature = extract_cipher_list(feature)
            else:
                feature = extract_tcp_ip_features(feature)

            if ip_string not in host2features:
                continue

            if feature_kind not in host2features[ip_string]:
                host2features[ip_string][feature_kind] = ''

            if host2features[ip_string][feature_kind] != '':
                continue

            host2features[ip_string][feature_kind] = feature


def parse_user_agent_file(host2features: "dict[str, dict[str, str]]", log_file):
    with open(log_file, mode="r") as fp:
        for line in fp:
            ip_string, log_entry = line.split(' ', maxsplit=1)

            if not is_ipv4_address(ip_string):
                continue

            log_entry = log_entry.split('\" \"', maxsplit=1)

            if len(log_entry) < 2:
                continue

            os_name = parse(log_entry[-1]).os.family

            if os_name != "Other":

                if ip_string not in host2features:
                    host2features[ip_string] = {}

                if 'user_agent' not in host2features[ip_string]:
                    host2features[ip_string]['user_agent'] = ''

                if host2features[ip_string]['user_agent'] != '':
                    continue

                if os_name in UNIX_UAS:
                    os_name = 'Linux'

                host2features[ip_string]['user_agent'] = os_name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--features", required=True,
                        type=str, help="directory with feature log files to parse")
    parser.add_argument("-u", "--user_agent", required=True,
                        type=str, help="directory with user agent log files to parse")
    parser.add_argument("-d", "--dir", required=True,
                        help="dir where to store results")
    args = parser.parse_args()

    features_log_dir: str = args.features

    if not os.path.isdir(features_log_dir):
        print(f"The path '{features_log_dir}' is not a valid directory.")
        sys.exit(1)

    user_agent_log_dir: str = args.user_agent

    if not os.path.isdir(user_agent_log_dir):
        print(f"The path '{user_agent_log_dir}' is not a valid directory.")
        sys.exit(1)

    work_dir = args.dir
    os.makedirs(os.path.relpath(work_dir), mode=0o755, exist_ok=True)

    host2features: "dict[str, dict[str, str]]" = {}

    for filename in os.listdir(user_agent_log_dir):
        if filename.endswith('.log'):
            parse_user_agent_file(host2features, os.path.join(
                user_agent_log_dir, filename))

    for filename in os.listdir(features_log_dir):
        if filename.endswith('.log'):
            parse_features_file(host2features, os.path.join(
                features_log_dir, filename))

    log_file_basename = os.path.basename(os.path.normpath(work_dir))

    df = pd.DataFrame.from_dict(host2features, orient='index')

    df.dropna(subset=FEATURES_SET, inplace=True)

    df.to_csv(f'{os.path.join(work_dir, "fingerprints_" + log_file_basename)}.csv',
              index_label='ip_src', sep=';')


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
