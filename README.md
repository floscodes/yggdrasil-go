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
  Services: [
    {
      Name: "wiki"
      Address: "300:1234:5678:abcd::10"
      Port: 80
      Protocol: "tcp"
    }
    {
      Name: "ssh"
      Address: "200:1234:5678:abcd::1"
      Port: 22
      Protocol: "tcp"
    }
  ]
}
```

Replace these example addresses with your reachable service addresses. Services
behind the router need addresses from a routed Yggdrasil subnet and working IPv6
routing/firewall configuration. Discovery advertises endpoints; it does not create
routes, port forwards, DNS records, or application proxies. Protocol is `tcp` or
`udp`; names are scoped to the announcing node's public key. Two publishers may
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

Announcements carry the publisher's Ed25519 signature and a complete service
snapshot. Newer snapshots replace older ones; an empty snapshot withdraws the
publisher's services. Nodes refresh their own snapshots every two minutes; cached
snapshots expire after ten minutes. Peer changes are checked every five seconds,
and new peers receive eligible cached snapshots, retried during their first
three checks. Eligible snapshots are also resent every two minutes. Duplicate and older snapshots
are ignored, preventing repeated circulation in cyclic peer topologies. Clocks
should be synchronised: announcements more than 30 seconds into the future or
already expired are rejected. Offline publishers disappear when their snapshots
expire.

At most 32 services per publisher, 8 KiB per announcement and 1024 cached publishers
are accepted. A full cache rejects new publishers until entries expire. Signatures
authenticate the publisher, not endpoint ownership, availability or trustworthiness.
Only advertise services you intend to expose: any peer may relay an announcement
further, even if your own Forward setting is false. Announcements use encrypted
Yggdrasil sessions and follow the configured GroupPassword restrictions.
