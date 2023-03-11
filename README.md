# os-fingerprinting

Script per catturare pacchetti TCP SYN e TLS Client Hello da scrivere in un file di log.

## Requirements

- Python 3.8+
- <code>apt-get install libpcap-dev</code>
- <code>python3 -m pip install 'Cython>=0.29.33'</code>
- <code>python3 -m pip install -r requirements.txt</code>

## Usage

<code>sudo -E python3 capture_fp.py -i interface|pcap -d path/to/logs/dir [-l log_interval] [-t time] [-f filter] [-v verbose]</code>

E' possibile configurare l'intervallo di logging ed il tempo totale di cattura per le catture live ed il filtro da applicare.

Example:

<code>sudo -E python3 capture_fp.py -i eth0 -d logs</code>

CTRL + C per arrestare lo script

<code>sudo -E python3 capture_fp.py -i eth0 -d logs -l 60 -t 300</code>

Viene prodotto un file log ogni 60 secondi per un totale di 300 secondi

<code>sudo -E python3 capture_fp.py -i capture.pcap -d logs</code>

## Output

Lo script produce un file di log ogni <b>log_interval</b> secondi (60 secondi di default) in cui vengono riporati l'indirizzo IP sorgente assieme alla tupla \<ttl,window size,tcp options> o la lista dei cifrari presenti nel Client Hello

```log
[08/Mar/2023:12:41:07 +0100]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 17850703239813529600), (1, 0), (3, 7)]
172.27.5.66: [4866, 4867, 4865, 4868, 49196, 52393, 49325, 49162, 49195, 49324, 49161, 49200, 52392, 49172, 49199, 49171, 157, 49309, 53, 156, 49308, 47, 159, 52394, 49311, 57, 158, 49310, 51]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 13103132311635886080), (1, 0), (3, 7)]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 5744936066012413952), (1, 0), (3, 7)]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 2366747479422009344), (1, 0), (3, 7)]
172.27.5.66: [4866, 4867, 4865, 4868, 49196, 52393, 49325, 49162, 49195, 49324, 49161, 49200, 52392, 49172, 49199, 49171, 157, 49309, 53, 156, 49308, 47, 159, 52394, 49311, 57, 158, 49310, 51]
172.27.5.66: 64,64240,[(2, 1460), (4, 0), (8, 17850703849698885632), (1, 0), (3, 7)]
172.27.5.66: [4866, 4867, 4865, 4868, 49196, 52393, 49325, 49162, 49195, 49324, 49161, 49200, 52392, 49172, 49199, 49171, 157, 49309, 53, 156, 49308, 47, 159, 52394, 49311, 57, 158, 49310, 51]
```
