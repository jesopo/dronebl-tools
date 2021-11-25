import argparse, base64, os.path, socket, sys, time
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

def _get() -> List[Tuple[str, str, int]]:
    try:
        resp = requests.request("GET", URL, timeout=5, proxies=PROXIES)
    except Exception:
        return []

    lines = resp.content.split(b"\n")
    lines = [l.strip(b"*\r") for l in lines]
    lines = list(filter(bool, lines))

    ips: List[Tuple[str, int]] = []
    for line in lines[2:]:
        pieces  = line.split(b",")
        openvpn = base64.b64decode(pieces[14]).decode("utf8")
        proto   = "tcp"
        for ovpn_line in openvpn.split("\n"):
            var, _, value = ovpn_line.strip("\r").partition(" ")
            if var == "remote":
                ip, port = value.split(" ", 1)
                ips.append((proto, ip, int(port)))
                break
            elif var == "proto":
                proto = value
    return ips

def _main(
        tor_port: int,
        tor_pass: str):

    known: Set[str] = set()

    while True:
        _new_circuit(tor_port, tor_pass)
        hosts = _get()

        added = 0
        for proto, ip, port in hosts:
            out = f"{proto} {ip} {port}"
            if not out in known:
                known.add(out)
                sys.stdout.write(f"{out}\n")
                sys.stdout.flush()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("torport", type=int)
    parser.add_argument("torpass", type=str)
    args = parser.parse_args()

    _main(args.torport, args.torpass)
