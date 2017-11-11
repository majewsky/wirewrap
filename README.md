# Wirewrap

Wirewrap extends [WireGuard](https://wireguard.com) with fault-tolerancy. When run on a set of servers, it will elect a
leader and make that leader the current WireGuard server. Clients can ask any running server who is the current leader,
then set up their Wireguard interface to point to that server. If the leader goes offline, the cluster elects a new
leader and clients are instructed to update their VPN, thus restoring connectivity usually after a few seconds.

## Installation

Run `make` to build the binary.

* Build-time dependencies: a [Go](https://golang.org) compiler
* Run-time dependencies:
  * [Wireguard](https://wireguard.com)
  * its `wg(8)` configuration utility
  * [iproute2](http://www.linuxfoundation.org/collaborate/workgroups/networking/iproute2)
  * on the server side only: [etcd](https://coreos.com/etcd/)

Run `make install` to install the binary. The conventional `DESTDIR` and `PREFIX` environment variables are recognized.

## Usage

### Configuration file format

Wirewrap requires a configuration file in the format accepted by `wg` (refer to
[`man 8 wg`](http://manpages.ubuntu.com/manpages/zesty/man8/wg.8.html) for details), except that one `[Peer]`
section must have multiple `PublicKey` and `Endpoint` settings like so:

```ini
[Peer]
PublicKey = yQ2QcbZ/Zjd5yNi4IP5CluBpamBgSGRTc4FLT5jiA3A=
Endpoint = vpn1.example.org:12345
PublicKey = zKx5ob+KIxxOVHnfMVjwolR5y48tu0RRPJ/b2ty/YgY=
Endpoint = vpn2.example.org:12345
PublicKey = bZBwUF2kNWcg1jMwepTA91bpfI7rP2bI+1UWTIDOqDk=
Endpoint = vpn3.example.org:12345
AllowedIPs = 0.0.0.0/0
```

Each endpoint corresponds to the public key directly above it. There must be an endpoint for each public key, and vice
versa. This `[Peer]` section contains all the servers that a client can speak to, but it is also required in the
configuration of the Wirewrap servers because they need to know which other servers are participating in the leader
election.

In the `[Interface]` section, the `PreUp`, `PreDown`, `PostUp` and `PostDown` keys are recognized and have the same
meaning as for `wg-quick` (see [`man 8 wg-quick`](http://manpages.ubuntu.com/manpages/zesty/man8/wg-quick.8.html) for
details).

Finally, on the servers, a section `[Wirewrap]` is required that references any nonzero number of client endpoints of an
[etcd cluster](https://coreos.com/etcd/docs/latest/) like so:

```ini
[Wirewrap]
Etcd = vpn1.example.org:2379
Etcd = vpn2.example.org:2379
Etcd = vpn3.example.org:2379
Etcd = etcd1.example.org:2379
Etcd = etcd2.example.org:2379
LeaderKey = /wirewrap/leader
```

The optional `LeaderKey` (default value as shown above) must be the same across all servers of one VPN, but unique
among VPNs utilizing the same etcd cluster.

### Invocation

Run Wirewrap as `wirewrap <config-file>`. This invocation is the same for clients and servers; servers recognize their
role by finding the public key corresponding to their private key in the multi-keyed `[Peer]` section, and by the
presence of the `[Wirewrap]` section.
