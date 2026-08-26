#!/usr/bin/env bash
# Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
# See LICENSE.md for licensing details.

set -euo pipefail

tunnel=${1:?usage: linux_tun_tunnel_netns.sh /path/to/rohccxx-tun-tunnel}
if [[ $(uname -s) != Linux || ! -x ${tunnel} || ! -c /dev/net/tun ]] ||
   ! command -v ip >/dev/null || ! command -v python3 >/dev/null; then
    echo "SKIP: Linux, /dev/net/tun, iproute2, Python 3, and the tunnel executable are required"
    exit 77
fi

suffix="$$"
ns_a="rohccxx-a-${suffix}"
ns_b="rohccxx-b-${suffix}"
tmp_dir=$(mktemp -d "/tmp/rohccxx-tun-${suffix}.XXXXXX")

cleanup() {
    set +e
    [[ -n ${pid_a:-} ]] && kill "${pid_a}" 2>/dev/null
    [[ -n ${pid_b:-} ]] && kill "${pid_b}" 2>/dev/null
    [[ -n ${relay_a:-} ]] && kill "${relay_a}" 2>/dev/null
    [[ -n ${relay_b:-} ]] && kill "${relay_b}" 2>/dev/null
    ip netns del "${ns_a}" 2>/dev/null
    ip netns del "${ns_b}" 2>/dev/null
    rm -rf -- "${tmp_dir}"
}
trap cleanup EXIT INT TERM

if ! ip netns add "${ns_a}" 2>/dev/null; then
    echo "SKIP: CAP_NET_ADMIN is required for the namespace integration test"
    exit 77
fi
if ! ip netns add "${ns_b}" 2>/dev/null; then
    echo "SKIP: CAP_NET_ADMIN is required for the namespace integration test"
    exit 77
fi

ip link add "vetha${suffix}" type veth peer name "vethb${suffix}"
ip link set "vetha${suffix}" netns "${ns_a}"
ip link set "vethb${suffix}" netns "${ns_b}"
ip -n "${ns_a}" addr add 192.0.2.1/24 dev "vetha${suffix}"
ip -n "${ns_b}" addr add 192.0.2.2/24 dev "vethb${suffix}"
ip -n "${ns_a}" link set lo up
ip -n "${ns_b}" link set lo up
ip -n "${ns_a}" link set "vetha${suffix}" up
ip -n "${ns_b}" link set "vethb${suffix}" up

cat > "${tmp_dir}/relay.py" <<'PY'
import os, select, socket, sys
local_port, local_target, underlay, peer, marker = sys.argv[1:]
local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
local.bind(("127.0.0.1", int(local_port)))
transport = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host, port = underlay.rsplit(":", 1)
transport.bind((host, int(port)))
host, port = peer.rsplit(":", 1)
transport.connect((host, int(port)))
while True:
    readable, _, _ = select.select([local, transport], [], [])
    for source in readable:
        data = bytearray(source.recv(65535))
        if source is local:
            if os.path.exists(marker) and len(data) > 8 and data[:4] == b"RHCT" and data[5] == 1:
                data[8] ^= 1
                os.unlink(marker)
            transport.send(data)
        else:
            local.sendto(data, ("127.0.0.1", int(local_target)))
PY

ip netns exec "${ns_a}" python3 "${tmp_dir}/relay.py" 20001 20000 192.0.2.1:10000 192.0.2.2:10000 "${tmp_dir}/corrupt-a" &
relay_a=$!
ip netns exec "${ns_b}" python3 "${tmp_dir}/relay.py" 20001 20000 192.0.2.2:10000 192.0.2.1:10000 "${tmp_dir}/corrupt-b" &
relay_b=$!

ip netns exec "${ns_a}" "${tunnel}" --tun rohca --local 127.0.0.1:20000 --peer 127.0.0.1:20001 --max-packet 2000 --stats-interval 60 >"${tmp_dir}/a.log" 2>&1 &
pid_a=$!
ip netns exec "${ns_b}" "${tunnel}" --tun rohcb --local 127.0.0.1:20000 --peer 127.0.0.1:20001 --max-packet 2000 --stats-interval 60 >"${tmp_dir}/b.log" 2>&1 &
pid_b=$!

for _ in $(seq 1 50); do
    ip -n "${ns_a}" link show rohca >/dev/null 2>&1 &&
    ip -n "${ns_b}" link show rohcb >/dev/null 2>&1 && break
    sleep 0.1
done
ip -n "${ns_a}" addr add 10.44.0.1/30 dev rohca
ip -n "${ns_b}" addr add 10.44.0.2/30 dev rohcb
ip -n "${ns_a}" link set rohca up mtu 1400
ip -n "${ns_b}" link set rohcb up mtu 1400

ip netns exec "${ns_a}" ping -c 2 -W 2 10.44.0.2 >/dev/null
ip netns exec "${ns_b}" ping -c 2 -W 2 10.44.0.1 >/dev/null

ip netns exec "${ns_b}" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.44.0.2",32123)); data,peer=s.recvfrom(4096); s.sendto(data,peer)' &
udp_server=$!
ip netns exec "${ns_a}" python3 -c 'import socket; p=bytes(range(256))*4; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(p,("10.44.0.2",32123)); assert s.recv(4096)==p'
wait "${udp_server}"

touch "${tmp_dir}/corrupt-a"
if ip netns exec "${ns_a}" ping -c 1 -W 1 10.44.0.2 >/dev/null 2>&1; then
    echo "corrupted compressed datagram unexpectedly delivered" >&2
    exit 1
fi
ip netns exec "${ns_a}" ping -c 2 -W 2 10.44.0.2 >/dev/null
echo "PASS: bidirectional ping, UDP integrity, corrupted-frame rejection, and recovery"
