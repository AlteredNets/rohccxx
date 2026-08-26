#!/usr/bin/env python3
"""Deterministic, byte-exact UDP stress driver for the Linux TUN integration."""

import argparse
import hashlib
import selectors
import socket
import struct
import time

MAGIC = b"RTST"
STOP = b"RSTOP"


def body(sequence, size, flow):
    prefix = MAGIC + struct.pack("!QBH", sequence, flow, size)
    return prefix + bytes(((sequence + flow * 17 + pos) & 0xff)
                          for pos in range(size - len(prefix)))


def server(address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((address, port))
    print("READY", flush=True)
    packets = byte_count = 0
    digest = hashlib.sha256()
    while True:
        data, peer = sock.recvfrom(2048)
        if data == STOP:
            break
        if len(data) < 15 or data[:4] != MAGIC:
            raise RuntimeError("invalid stress request")
        sequence, flow, declared = struct.unpack("!QBH", data[4:15])
        if declared != len(data) or data != body(sequence, declared, flow):
            raise RuntimeError(f"request corruption sequence={sequence}")
        if sock.sendto(data, peer) != len(data):
            raise RuntimeError("short stress reply")
        packets += 1
        byte_count += len(data)
        digest.update(data)
    print(f"STRESS_SERVER packets={packets} bytes={byte_count} sha256={digest.hexdigest()}",
          flush=True)


def client(address, port, minimum_packets, duration):
    sockets = []
    selector = selectors.DefaultSelector()
    for flow in range(16):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.bind(("10.44.0.1", 34000 + flow))
        sock.connect((address, port))
        sockets.append(sock)
        selector.register(sock, selectors.EVENT_READ, flow)
    sizes = (64, 256, 1200)
    start = time.monotonic()
    sequence = packets = byte_count = 0
    digest = hashlib.sha256()
    while packets < minimum_packets or time.monotonic() - start < duration:
        if sequence < minimum_packets // 3:
            flow_count = 1
        elif sequence < (minimum_packets * 2) // 3:
            flow_count = 4
        else:
            flow_count = 16
        flow = sequence % flow_count
        size = sizes[(sequence // 16) % len(sizes)]
        expected = body(sequence, size, flow)
        sock = sockets[flow]
        if sock.send(expected) != len(expected):
            raise RuntimeError("short stress request")
        ready = selector.select(2.0)
        if len(ready) != 1 or ready[0][0].fileobj is not sock:
            raise RuntimeError(f"missing/misdirected reply sequence={sequence}")
        reply = sock.recv(2048)
        if reply != expected:
            raise RuntimeError(f"reply corruption sequence={sequence}")
        digest.update(reply)
        packets += 1
        byte_count += len(reply)
        sequence += 1
    sockets[0].send(STOP)
    elapsed = time.monotonic() - start
    print(f"STRESS_CLIENT packets={packets} flows=1,4,16 sizes=64,256,1200 "
          f"bytes={byte_count} seconds={elapsed:.3f} sha256={digest.hexdigest()}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, default=33221)
    parser.add_argument("--minimum-packets", type=int, default=100000)
    parser.add_argument("--duration", type=float, default=300.0)
    args = parser.parse_args()
    if args.mode == "server":
        server(args.address, args.port)
    else:
        client(args.address, args.port, args.minimum_packets, args.duration)


if __name__ == "__main__":
    main()
