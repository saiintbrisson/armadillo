# Armadillo Proxy

Armadillo is a QUIC, TLS-terminating, proxy that sits between Hytale clients and servers, handling authentication on behalf of the server. Allowing full visibility into the contents.

```mermaid
flowchart LR
    subgraph External
        Sessions[(sessions.hytale.com)]
    end

    Player <-->|TLS<br>Full Hytale Auth| Proxy
    Proxy <-->|TLS<br>Bypassed Auth| Server

    Proxy --> Analysis[Decrypted<br>Traffic Analysis]

    Player -.->|auth requests| Sessions
    Proxy -.->|auth requests| Sessions
```

<video src="https://github.com/user-attachments/assets/5bb292a4-e21b-4e46-9295-5a20fc911d77" controls preload></video>

## Quick Start

Build and install the server plugin:

```bash
cd plugin
./gradlew build
cp build/libs/offline-mode-0.1.0.jar /path/to/server/mods/
```

Run the proxy:

```bash
cargo build --release

cp /path/to/server/auth.enc . # we need a recent auth.enc to impersonate the server
./target/release/armadillo-proxy --listen 0.0.0.0:5520 --upstream 127.0.0.1:5521
```

Point your client to the proxy bind address. The server must listen on the upstream port with the plugin loaded. If you encounter issues like a 400 on proxy startup, refresh your `auth.enc` file by logging out (`/auth logout`) and logging in (`/auth login device`) again.

## Why and how?

First, because it's fun. Second, it's a good starting point for those looking into how to extend the server.

Hytale uses QUIC, which in turn uses TLS 1.3. This version of TLS comes with perfect forward secrecy out of the box, making it impossible to eavesdrop a communication
between peers without actively participating. If you try simply terminating the TLS, the Hytale server will notice your certificate does not match the player's you
are connecting on behalf.

Luckily, we are in Java-land. A simple mod (plugin) is enough to patch the server in a way to bypass the certificate validation. By using reflection in 3 specific
points, the server allows unauthenticated players to join:
* By overriding the logic in `JWTValidator`, we can still parse relevant token information without validatin the player's certificate
* A patch to `SessionServiceClient` allows us to avoid requests to Hytale's servers
* Inserting a fake game session to `ServerAuthManager` avoid a set of other requests

You can find more in [AuthBypass.java](./plugin/src/main/java/rs/luiz/hytale/offline_mode/AuthBypass.java).

### Player -> Proxy

The proxy validates JWT tokens using EdDSA (Ed25519) signatures. Public keys are fetched from the session service's JWKS endpoint and cached. This is the same process handled by the server JAR.

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Proxy
    participant S as Session Service

    C->>P: Connect packet (identity_token, uuid, username)
    P->>P: Validate identity_token signature (EdDSA)
    P->>S: POST /server-join/auth-grant
    S-->>P: authorization_grant
    P->>C: AuthGrant packet (authorization_grant, server_identity_token)
    C->>P: AuthToken packet (access_token, server_authorization_grant)
    P->>P: Validate access_token signature
    P->>S: POST /server-join/auth-token (exchange server_authorization_grant)
    S-->>P: server_access_token
    P->>C: ServerAuthToken packet (server_access_token)
```

### Proxy -> Server

The patched server ignores all validation and only extracts the necessary information from the client's token. After authentication is done, traffic can be relayed.

```mermaid
sequenceDiagram
    participant P as Proxy
    participant U as Upstream Server

    P->>U: Connect packet (original from client)
    U->>P: AuthGrant packet
    P->>U: AuthToken packet (client's access_token)
    U->>P: ServerAuthToken packet
    Note over P,U: Bidirectional relay begins
```

## The auth.enc file

Credentials are encrypted with AES-256-GCM. The key is derived from the machine's hardware UUID using PBKDF2-HMAC-SHA256 (100k iterations, salt: `HytaleAuthCredentialStore`).

#### Encrypted file format

| Offset | Size | Content |
|--------|------|---------|
| 0 | 12 | Nonce/IV |
| 12 | rest | Ciphertext + GCM tag |

#### Decrypted file format

| Offset | Size | Content |
|--------|------|---------|
| 0 | 4 | Header (zeros) |
| 4+ | var | Field entries (repeated) |

Each entry:

| Size | Content |
|------|---------|
| 1 | Separator (0x00) |
| var | Key name (null-terminated) |
| 4 | Value length (LE u32) |
| var | Value bytes |

And the fields: `AccessToken`, `RefreshToken`, `ExpiresAt`, `ProfileUuid`
