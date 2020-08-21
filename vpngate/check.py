import argparse, os.path, socket, ssl, sys
from typing  import Set
from OpenSSL import crypto
from dronebl import DroneBL

CERT_CN = "*.opengw.net"
COMMENT = "VPNGate server (connect verified)"

def _cn(ip: str, port: int):
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
    return cn

def _main(
        key:    str,
        master: str):
    known: Set[str] = set()
    if os.path.isfile(master):
        with open(master, "r") as f_read:
            lines = f_read.read().split("\n")
            lines = list(filter(bool, lines))
            known.update(lines)

    with open(master, "a") as f_app:
        d = DroneBL(key)
        for host in iter(sys.stdin.readline, b""):
            host       = host.rstrip("\n")
            ip, port_s = host.rsplit(":", 1)
            port       = int(port_s)

            if not host in known:
                cn = _cn(ip, port)
                if cn == CERT_CN:
                    look = d.lookup(ip, 19)
                    if look is None:
                        success, msg = d.add(ip, 19, COMMENT, port)
                        print(f"+ {host}")
                    else:
                        print(f"- {host}")

                    known.add(ip)
                    f_app.write(f"{host}\n")
                else:
                    print(f"! {host} ({cn})")
            else:
                print(f"= {host}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("key")
    parser.add_argument("master")
    args = parser.parse_args()
    _main(args.key, args.master)
