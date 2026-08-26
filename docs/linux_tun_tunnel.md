<!--
Copyright (c) AlteredNets Cyber Solutions, Inc. 2026
See LICENSE.md for licensing details.
-->

# Linux IPv4 TUN laboratory tunnel

`rohccxx-tun-tunnel` is a minimal, single-threaded Linux laboratory endpoint.
It transports IPv4 packets between a TUN interface and a connected UDP socket,
using automatic profile selection in the public ROHCCXX C API. It is not an
encrypted tunnel and makes no confidentiality, authentication, or production
deployment claim.

```text
rohccxx-tun-tunnel --tun NAME --local IPv4:PORT --peer IPv4:PORT \
  [--max-packet BYTES] [--stats-interval SECONDS]
```

The versioned UDP envelope is `RHCT`, version `1`, message type `1` (compressed)
or `2` (feedback), and a two-byte network-order payload length. Statistics keep
inner IPv4 bytes, ROHC bytes, and complete tunnel bytes separate. Complete
tunnel bytes include the eight-byte envelope and an estimated 28-byte outer
IPv4/UDP header for every transmitted data or feedback datagram.
Feedback payloads contain a four-byte network-order small CID and the one-byte
validated public ROHCCXX feedback type.

Build on Linux with tests enabled:

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release -DROHCCXX_BUILD_TESTS=ON
cmake --build build-linux --parallel
```

Run two manually configured endpoints after creating and addressing their TUN
interfaces (the process creating a requested interface must remain running):

```bash
sudo build-linux/examples/linux_tun_tunnel/rohccxx-tun-tunnel \
  --tun rohca --local 192.0.2.1:5000 --peer 192.0.2.2:5000 \
  --max-packet 2000 --stats-interval 5
sudo build-linux/examples/linux_tun_tunnel/rohccxx-tun-tunnel \
  --tun rohcb --local 192.0.2.2:5000 --peer 192.0.2.1:5000 \
  --max-packet 2000 --stats-interval 5
```

The exact self-contained namespace demonstration creates its veth underlay,
TUN endpoints, routes, and a one-shot corruption relay, then verifies
bidirectional ping, UDP payload integrity, corrupted-frame rejection, and
recovery:

```bash
sudo tests/integration/linux_tun_tunnel_netns.sh \
  "$PWD/build-linux/examples/linux_tun_tunnel/rohccxx-tun-tunnel"
```

Without Linux `/dev/net/tun`, `iproute2`, Python 3, or `CAP_NET_ADMIN`, the
integration script exits with CTest skip status 77 and prints the missing
prerequisite.
