import socket, ssl
from argparse import ArgumentParser
from os       import urandom
from OpenSSL  import crypto

CERT_CN   = "*.opengw.net"

UDP_SID   = urandom(8)
UDP_DATA  = b"8%b\x00\x00\x00\x00\x00"

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
    sid  = urandom(8)
    send = UDP_DATA % sid
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(send, (ip, port))
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        return False
    else:
        return data[14:22] == sid

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("proto")
    parser.add_argument("ip")
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    if args.proto == "tcp":
        if _tcp(args.ip, args.port):
            print("found")
        else:
            print("not found")
    elif args.proto == "udp":
        if _udp(args.ip, args.port):
            print("found")
        else:
            print("not found")
