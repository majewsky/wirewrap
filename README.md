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

Wirewrap requires a configuration file in the format accepted by `wg` (refer to
[`man 8 wg-quick`](http://manpages.ubuntu.com/manpages/zesty/man8/wg-quick.8.html) for details), except for the
differences outlined below. When the configuration file is complete, invoke Wirewrap as

```
$ wirewrap <config-file>
```

### Configuration file format: Extensions for clients

The `[Peer]` sections can have an additional field `WirewrapID`.

```ini
[Peer]
WirewrapID = first-vpn
PublicKey = yQ2QcbZ/Zjd5yNi4IP5CluBpamBgSGRTc4FLT5jiA3A=
Endpoint = vpn1.example.org:12345
AllowedIPs = 0.0.0.0/0

[Peer]
WirewrapID = first-vpn
PublicKey = zKx5ob+KIxxOVHnfMVjwolR5y48tu0RRPJ/b2ty/YgY=
Endpoint = vpn2.example.org:12345
AllowedIPs = 0.0.0.0/0

[Peer]
WirewrapID = first-vpn
PublicKey = bZBwUF2kNWcg1jMwepTA91bpfI7rP2bI+1UWTIDOqDk=
Endpoint = vpn3.example.org:12345
AllowedIPs = 0.0.0.0/0
```

For each unique value of `WirewrapID`, Wirewrap will select and use only one of the peers with this ID at a time,
switching over to the next one when the current one fails.

### Configuration file format: Extensions for servers

On the servers that correspond to the `[Peer]` sections from above, an additional section `[Wirewrap]` is required that
references any nonzero number of client endpoints of an [etcd cluster](https://coreos.com/etcd/docs/latest/) like so:

```ini
[Wirewrap]
ID = first-vpn
Etcd = vpn1.example.org:2379
Etcd = vpn2.example.org:2379
Etcd = vpn3.example.org:2379
Etcd = etcd1.example.org:2379
Etcd = etcd2.example.org:2379
```

The `ID` field is an arbitrary string, but must be the same across all servers and clients, but different for each VPN
utilizing the same etcd cluster.
