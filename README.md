# Yggdrasil

[![Build status](https://github.com/yggdrasil-network/yggdrasil-go/actions/workflows/ci.yml/badge.svg)](https://github.com/yggdrasil-network/yggdrasil-go/actions/workflows/ci.yml)

## Introduction

Yggdrasil is an early-stage implementation of a fully end-to-end encrypted IPv6
network. It is lightweight, self-arranging, supported on multiple platforms and
allows pretty much any IPv6-capable application to communicate securely with
other Yggdrasil nodes. Yggdrasil does not require you to have IPv6 Internet
connectivity - it also works over IPv4.

## Supported Platforms

Yggdrasil works on a number of platforms, including Linux, macOS, Ubiquiti
EdgeRouter, VyOS, Windows, FreeBSD, OpenBSD and OpenWrt.

Please see our [Installation](https://yggdrasil-network.github.io/installation.html)
page for more information. You may also find other platform-specific wrappers, scripts
or tools in the `contrib` folder.

## Building

If you want to build from source, as opposed to installing one of the pre-built
packages:

1. Install [Go](https://golang.org)
2. Clone this repository
2. Run `./build`

Note that you can cross-compile for other platforms and architectures by
specifying the `GOOS` and `GOARCH` environment variables, e.g. `GOOS=windows
./build` or `GOOS=linux GOARCH=mipsle ./build`.

## Running

### Generate configuration

To generate static configuration, either generate a HJSON file (human-friendly,
complete with comments):

```
./yggdrasil -genconf > /path/to/yggdrasil.conf
```

... or generate a plain JSON file (which is easy to manipulate
programmatically):

```
./yggdrasil -genconf -json > /path/to/yggdrasil.conf
```

You will need to edit the `yggdrasil.conf` file to add or remove peers, modify
other configuration such as listen addresses or multicast addresses, etc.

### Run Yggdrasil

To run with the generated static configuration:

```
./yggdrasil -useconffile /path/to/yggdrasil.conf
```

To run in auto-configuration mode (which will use sane defaults and random keys
at each startup, instead of using a static configuration file):

```
./yggdrasil -autoconf
```

You will likely need to run Yggdrasil as a privileged user or under `sudo`,
unless you have permission to create TUN/TAP adapters. On Linux this can be done
by giving the Yggdrasil binary the `CAP_NET_ADMIN` capability.

## Documentation

Documentation is available [on our website](https://yggdrasil-network.github.io).

- [Installing Yggdrasil](https://yggdrasil-network.github.io/installation.html)
- [Configuring Yggdrasil](https://yggdrasil-network.github.io/configuration.html)
- [Frequently asked questions](https://yggdrasil-network.github.io/faq.html)
- [Version changelog](CHANGELOG.md)

## Communities

A number of IRC communities exist, including the `#yggdrasil` IRC channel on [libera.chat](https://libera.chat) and various others on [Yggdrasil-internal IRC networks](https://yggdrasil-network.github.io/services.html#irc).

## License

This code is released under the terms of the LGPLv3, but with an added exception
that was shamelessly taken from [godeb](https://github.com/niemeyer/godeb).
Under certain circumstances, this exception permits distribution of binaries
that are (statically or dynamically) linked with this code, without requiring
the distribution of Minimal Corresponding Source or Minimal Application Code.
For more details, see: [LICENSE](LICENSE).

## Decentralised service discovery (experimental)

**Development is ongoing.** This feature is experimental and not yet ready for
production use. Configuration and announcement formats may change during development.

Service discovery is opt-in and separate from multicast peer discovery. Configure
services with names and existing Yggdrasil IPv6 endpoints, for example:

```hjson
Discovery: {
  Enabled: true
  Forward: false
  RefreshInterval: "15m"
  Services: [
    {
      Name: "wiki"
      Address: "300:1234:5678:abcd::10"
      Port: 80
      Protocol: "tcp"
    }
    {
      Name: "dns"
      Address: "200:1234:5678:abcd::1"
      Port: 53
      Protocol: "tcp+udp"
    }
  ]
}
```

The addresses above are placeholders. Replace them with addresses derived from
this node's actual key; use `yggdrasilctl getSelf` to find its address and routed
subnet. Only these endpoints can be advertised:

- The exact Yggdrasil IPv6 address derived from the publishing node's public key.
- Any IPv6 address within the `/64` subnet derived from that same public key, for
  devices behind the node. Routing and firewall configuration must already allow
  access to those devices.

An arbitrary Yggdrasil address is not sufficient. Addresses belonging to another
node/key are rejected, even if the device is on the same physical LAN. A device
with its own Yggdrasil identity must announce under that identity, or use an
address from this router's derived subnet when advertised by this router.
Invalid local service addresses prevent startup and report the permitted node
address and subnet. Discovery advertises endpoints; it does not create
routes, port forwards, DNS records, or application proxies. Protocol is `tcp`,
`udp` or `tcp+udp` (both transports on the same port); names are scoped to the
announcing node's public key. Two publishers may
use the same name. Existing IPv6 applications can use the discovered endpoints.

`Enabled: true` accepts announcements from directly connected peers and publishes
the configured services to those peers. An empty service list allows listening
without publishing services. `Forward: true` additionally relays accepted foreign
announcements to other connected peers, excluding the incoming peer and publisher.
Forward has no effect while Enabled is false. Both settings default to false.
Peers running versions without discovery ignore the new messages.

Use `yggdrasilctl getServices` (or `yggdrasilctl -json getServices`) to list cached
services, including publisher public keys and expiration times. Names do not
resolve automatically. Configuration changes currently require a restart.

Announcement rules:

- Discovery must be enabled to publish or accept announcements. Incoming
  announcements are accepted only from directly connected peers.
- Every service address must equal the publisher's key-derived node address or
  fall within its key-derived `/64` subnet. This is checked both at local startup
  and when receiving announcements. For relayed announcements, the original
  publisher's key is checked, not the immediate peer's key. Announcements with an
  invalid endpoint are rejected in full and are not cached or forwarded.
- Each announcement contains the publisher's public key, a signed timestamp and
  its complete service list, authenticated with the publisher's Ed25519 signature.
- The node creates and sends its own announcements at `RefreshInterval`: by
  default every **15 minutes**, configurable from **5 to 60 minutes**. Omitting
  the setting or using an empty string selects the default.
- Peer connections are checked at least every five seconds. New peers receive
  the node's own announcement, retried during their first three checks. These
  initial sends are additional to the regular refresh interval.
- Each accepted foreign announcement is forwarded **once to each eligible
  connected peer**, only if `Forward: true`. The incoming peer and the original
  publisher are excluded. This is one send attempt per eligible peer, not a
  delivery guarantee.
- Foreign announcements are **not** included in the node's periodic announcements
  and are **not** replayed from the cache to newly connected peers.
- For each publisher, only the announcement with the newest signed timestamp is
  retained. Duplicate or older announcements are ignored and are not forwarded.
- An announcement with a **newer signed timestamp** is a new announcement and may
  be forwarded once again, even if the previous announcement has not yet expired.
- When a newer announcement contains an unchanged service list, the receiver
  preserves the cached service list and updates its timestamp and expiration.
  A changed list replaces the previous list; an empty list withdraws all services
  belonging to that publisher.
- Announcements expire **60 minutes after the publisher's signed timestamp**.
  Receiving or forwarding an announcement does not reset this lifetime. Expired
  announcements are rejected; expired cached entries are removed. A new, valid
  announcement received after expiration may be accepted and forwarded once again.
- Announcements more than 30 seconds into the future are rejected. Clocks should
  be synchronised. At a 60-minute refresh interval, delivery delays can briefly
  expire a service before its renewal arrives.

Configuration changes require a restart.

At most 32 services per publisher, 8 KiB per announcement and 1024 cached publishers
are accepted. A full cache rejects new publishers until entries expire. Signatures
authenticate the publisher; address validation binds advertised endpoints to its
key-derived address space. This does not prove that an application is running,
that a device is currently reachable, or that a service is trustworthy.
Only advertise services you intend to expose: any peer may relay an announcement
further, even if your own Forward setting is false. Announcements use encrypted
Yggdrasil sessions and follow the configured GroupPassword restrictions.
