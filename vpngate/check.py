import argparse, os, socket, ssl, sys
from typing  import Set
from OpenSSL import crypto
from dronebl import DroneBL

CERT_CN = "*.opengw.net"
COMMENT = "VPNGate {proto} server (connect verified)"

UDP_SID   = os.urandom(8)
UDP_DATA  = b"8"
UDP_DATA += UDP_SID
UDP_DATA += b"\x00\x00\x00\x00\x00"

def _cn(ip: str, port: int) -> bool:
    sock = ssl.wrap_socket(socket.socket())
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
    except (socket.timeout, OSError):
        return None
    cert = sock.getpeercert(True)
    sock.close()

    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
    cn   = x509.get_subject().CN
    return cn == CERT_CN

def _udp(ip: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(UDP_DATA, (ip, port))
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        return False
    else:
        return data[14:22] == UDP_SID

def _main(
        key:    str,
        master: str):
    known: Set[str] = set()
    if os.path.isfile(master):
        with open(master, "r") as f_read:
            lines = f_read.read().split("\n")
            lines = list(filter(bool, lines))
            known.update(lines)

    f_app = open(master, "a")
    with open(key) as key_file:
        d = DroneBL(key_file.read().strip())
    for host in iter(sys.stdin.readline, ""):
        key           = host.strip()
        proto, ip, po = key.rsplit(" ", 2)
        port          = int(po)
        host          = f"{ip}:{port}"

        if not key in known:
            if ((proto == "tcp" and _cn(ip, port)) or
                    (proto == "udp" and _udp(ip, port))):
                look = d.lookup(ip, 19)
                if look is None:
                    comment = COMMENT.format(proto=proto.upper())
                    success, msg = d.add(ip, 19, comment, port)
                    print(f"+ {proto} {host}")
                else:
                    print(f"- {proto} {host}")

            else:
                print(f"! {proto} {host}")

            known.add(key)
            f_app.write(f"{key}\n")
        else:
            print(f"= {proto} {host}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("key")
    parser.add_argument("master")
    args = parser.parse_args()
    _main(args.key, args.master)
