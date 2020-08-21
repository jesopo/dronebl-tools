import argparse, base64, os.path, socket, sys
import requests

from typing import List, Set, Tuple

URL = "http://www.vpngate.net/api/iphone/"
PROXIES = {
    "http":  "socks5://localhost:9050",
    "https": "socks5://localhost:9050"
}

def _new_circuit(port: int, tpass: str):
    sock  = socket.socket()
    sock.settimeout(1)
    sock.connect(("localhost", port))
    sock.sendall(f'AUTHENTICATE "{tpass}"\r\n'.encode("utf8"))
    sock.sendall(b"SIGNAL NEWNYM\r\n")
    sock.close()

def _get() -> List[Tuple[str, int]]:
    try:
        resp = requests.request("GET", URL, timeout=5, proxies=PROXIES)
    except:
        return []

    lines = resp.content.split(b"\n")
    lines = [l.strip(b"*\r") for l in lines]
    lines = list(filter(bool, lines))

    ips: List[Tuple[str, int]] = []
    for line in lines[2:]:
        pieces  = line.split(b",")
        openvpn = base64.b64decode(pieces[14]).decode("utf8")
        for ovpn_line in openvpn.split("\n"):
            var, _, value = ovpn_line.partition(" ")
            if var == "remote":
                ip, port = value.split(" ", 1)
                ips.append((ip, int(port)))
                break
    return ips

def _main(
        tor_port: int,
        tor_pass: str):

    ip_set: Set[str] = set()

    while True:
        _new_circuit(tor_port, tor_pass)
        ips = _get()

        added = 0
        for ip, port in ips:
            if not ip in ip_set:
                ip_set.add(ip)
                sys.stdout.write(f"{ip}:{port}\n")
                sys.stdout.flush()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("torport", type=int)
    parser.add_argument("torpass", type=str)
    args = parser.parse_args()

    _main(args.torport, args.torpass)