# Hytale Relay - CGNAT/UPnP Bypass

They said it wasn't real. They said it couldn't be done. Bypass Hytale's UPnP LAN to play with friends when the host is behind CGNAT or when the router does not support UPnP.

## Quick Start

```bash
# On your VPS
./armadillo serve

# On your machine (after starting Hytale world and copying share code)
./armadillo tunnel --relay your.relay.com "<share code>"
# Outputs new share code or relayed address

# Or a server address if you have a dedicated one
./armadillo tunnel --relay your.relay.com 127.0.0.1
# Also generates a share code
```

The `ARMADILLO_PASS=<pass>` environment variable can be set on both server and client to enable authentication. The generated share code works for both worlds and dedicated servers.

## How It Works

Hytale share codes are Base64 encoded, flate compressed JSONs:

```json
{
  "HostName": "computer-name",
  "HostUuid": "<UUID-v4>",
  "ServerName": "New World",
  "Password": "123",
  "ExpiresAt": "2026-01-15T13:45:16Z",
  "Candidates": [
    {"Type": "Host", "Address": "192.168.0.1", "Port": 65472, "Priority": 1000},
    {"Type": "UPnP", "Address": "192.168.0.2", "Port": 65472, "Priority": 900}
  ]
}
```

The candidates list informs how the client can try connecting to the server. By connecting to a relay server, a new share code can be created with the relay as the sole candidate.

```
You (CGNAT) <--- Multiplexed QUIC datagrams ---> VPS Relay (Public) <---> Friend
```

This is called a [TURN]-style proxy. By initiating a transmission to a third party server, the CGNAT creates a mapping (using, for example, a 5-tuple) making it possible for traffic to flow between you and a relay, like making a web request. A dedicated port is allocated to your world and the relay client generates a new share code using the relay server address.

The QUIC datagrams between the host and the relay are prefixed by a 2-byte player ID. QUIC datagrams preserve boundaries, and streams and retransmissions are handled naturally by the underlying game QUIC protocol.

[TURN]: https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT
