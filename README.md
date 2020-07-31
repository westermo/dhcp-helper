dhcp-helper - DHCP relay agent w/ Option 82 support
===================================================
[![License Badge][]][License] [![Travis Status][]][Travis]

A DHCP relay agent is commonly used in routed networks with centralized
DHCP services.  The relay agent is a service typically configured on a
router where it converts all DHCP broadcast messages from clients into
unicast messages which it forwards to the central DHCP server(s).

dhcp-helper listens for DHCP and BOOTP broadcasts on all its configured
interfaces and relays them to DHCP or BOOTP servers elsewhere.  It also
relays replies from the remote servers back to the hosts.  Once hosts
are fully configured they can communicate directly with their servers
and no longer need the services of a relay.

In some setups it is preferred to always enforce communication via the
DHCP relay.  This usually coincides with requirements for DHCP Option
82, i.e., where the relay tucks on extra information for the server
regarding which port a host is connected to and from which relay the
request is forwarded from.  In Option 82 terms these are called the
circuit id and remote id, respectively.  For more information, see IETF
[RFC 3046](https://tools.ietf.org/html/rfc3046).

dhcp-helper is optimized to run on a VLAN aware bridge, but work as well
for a much simpler use case (see simple.json). If running with a bridge
nftables is required (kernel support and userspace binary). This to stop
DHCP packets that's already processed by the relay agent to be forwarded
by the bridge.

dhcp-helper requires a configuration file to operate correctly (default
read from `/etc/dhcphelper.json` or specified via the `-f`
option). The simplest configuration look like this:

```
{
    "server": [
        {
            "address": "198.19.10.2"
        }],
    "group": [
        {
            "giaddr": "198.19.20.1"
        }
    ]
}
```

This configuration will listen for DHCP request on the local interface
which has the IP address 198.19.20.1. An incoming DHCP request will
then be relayed to a DHCP server at IP address 198.19.10.2.


Building
--------

Requirements on an Ubuntu 16.04 system:
```
apt-get install libnl-3-dev libnl-route-3-dev libnl-genl-3-dev libjansson-dev libev-dev
```
Build dhcp-helper:
```
./configure && make && make install
```


Configuration
-------------

simple.json - A very simple case where you only run the relay agent on one interface and no bridge.
bridged.json - More advanced case with multiple servers and running on a VLAN aware bridge.

### Configuration file
**option82** - Should option 82 be enabled, optional
  * **remote-id** - remote ID settings, optional
    * **type** - remote id type can either be manual [string or hex values](#string-or-hex-values), hostname or giaddr
    * **data** - only applicable when using manual

**server** - array of servers, optional
  * **address** - IPv4 address of server, required
  * **port** - TCP port for the server, optional (default port 67)

**group** - array of objects, required
  * **giaddr** - Local address to use when communicate with server, required
  * **ifname** - interface to broadcast answers to, if not specified it is the interface with giaddr, optional
  * **iface** - array of objects, optional
    * **ifname** - the name of the interface, required
    * **circuit-id** - value to send to the server, see [String or hex values](#string-or-hex-values)
    * **server** - object of objects, optional if specified globally, override global configured servers
        * **address** - Where to send, required
        * **port** - TCP port for the server, optional (default port 67)

### String or hex values
Circuit-id and remote-id can be entered as hex values as well as string.

As raw hex values:
```
    "option82": {
        "remote-id": {
            "type": "manual",
            "data": [
                "0x5a",
                "0x5a",
                "0x5a",
                "0x5a"
            ]
        }
    },
```
as a string:
```
    "option82": {
        "remote-id": {
            "type": "manual",
            "data": "test"
        }
    },
```


Origin & References
-------------------

dhcp-helper was originally written by Simon Kelley <simon@thekelleys.org.uk>


[License]:         https://en.wikipedia.org/wiki/GPL_license
[License Badge]:   https://img.shields.io/badge/License-GPL%20v2-blue.svg
[Travis]:          https://travis-ci.org/westermo/dhcp-helper
[Travis Status]:   https://travis-ci.org/westermo/dhcp-helper.svg?branch=master
