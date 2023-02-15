# os-fingerprinting

Script per estrarre e creare un database di firme TCP/IP e TLS a partire da un file pcap.

## Requirements

- Python 3.8+
- <code>pip install requirements.txt</code>

## Usage

Deve essere fornito un file pcap ed il nome del sistema operativo in cui è stata eseguita la cattura.
Se viene fornito un database esistente quest'ultimo viene aggiornato con le firme ottenute dall'esecuzione dello script.

<code>python3 gen_fingerprint.py -o os_name [-d db_name] pcap</code><br>

Example:

<code>python3 gen_fingerprint.py -o Windows_11 capture.pcap</code>

## Output

Lo script produce un file json che segue lo schema:

  ```json
{
    "OS_NAME": {
        "TCP/IP Features": [
            "..."
        ],
        "Ciphers Max Repeats": [
            "..."
        ]
    }
}
```
