# WebRTC SDK for PHP

<p align="center">
  <a href="./README.cn.md"><strong>🇨🇳 中文</strong></a> •
  <a href="./README.md"><strong>🇬🇧 English</strong></a>
</p>

A lightweight WebRTC SFU (Selective Forwarding Unit) server built on PHP >= 7.3.9 native sockets.
It uses a single‑process asynchronous event loop, with built‑in WebSocket signaling, STUN, DTLS, SCTP (DataChannel) and SRTP audio/video forwarding; no third‑party Composer runtime packages are required.
Business logic can be extended non‑invasively through event callbacks – multi‑room, authentication, billing, chat broadcasting, custom signaling and more can be implemented without modifying the SDK core code.

---

## Features

| Capability | Description |
|---|---|
| WebSocket signaling service | Built‑in standalone HTTP/WS service (default port 8088) with static file hosting |
| STUN / ICE | Standalone STUN Binding service listens on 3478 by default; ICE Binding Responses on the WebRTC media port include MESSAGE‑INTEGRITY and FINGERPRINT |
| DTLS handshake | RFC 6347 / RFC 5764 (DTLS‑SRTP), built‑in certificate, automatic SRTP master key negotiation and derivation |
| SRTP protocol | AES‑128‑ICM encryption, HMAC‑SHA1‑80 authentication, ROC and replay protection |
| SCTP DataChannel | PPID=51 text / 53 binary / 56/57 partially reliable streams (onmessage callback) |
| SFU media forwarding | Automatic SSRC rewriting + multi‑subscriber distribution; one push stream → many play viewers |
| Event‑driven interface | Callbacks for connection, signaling, Publisher, Subscriber, RTP and DataChannel; selected pre‑events can take over the default behavior via `&$handled` |
| Metadata management | Client‑level KV metadata, freely extensible with fields such as room, role, concurrency limit |
| Zero runtime dependencies | Uses PHP extensions `openssl`, `json`, `sockets` |

---

## Requirements

- PHP **>= 7.3.9**
- PHP extensions:
  - `openssl`
  - `json`
  - `sockets`
- Composer
- Operating system: Windows / Linux / macOS

Install via Composer:

```bash
composer require xiaosongshu/webrtc
```

---

## Ports and network model

| Port | Protocol | Purpose | Public deployment |
|---|---|---|---|
| `8088` | TCP (HTTP/WS) | Pages, WebSocket signaling, WHIP/WHEP HTTP API | Service binds `0.0.0.0`; restrict with firewall so only Nginx can access it in production |
| `8089` | UDP | ICE, DTLS, SRTP/SRTCP, RTP/RTCP media | Must be directly reachable by clients; a regular Nginx HTTP proxy cannot forward it |
| `3478` | UDP | Optional standalone STUN Binding service | Open to the public when this service is used |

Browsers or OBS first complete signaling and SDP negotiation via HTTP/WebSocket, then connect directly to `serverIP:8089/UDP` based on the SDP candidates. A successful HTTPS proxy does **not** mean the media port is reachable.

---

## Local deployment

The repository root provides `start.php` together with demo pages `index.html`, `push.html`, `play.html`, `whip.html`, `whep.html`.  
When installing via Composer, you can copy the structure of `start.php` from the repo to create your own entry point; the server reads the sample static files from the SDK package root by default. Simply copying `start.php` does not change the static file directory.

### 1. Start the service
```bash
php start.php
```
A successful start will show output similar to:

```text
Using certificate: .../src/Core/certs/server.crt
WebSocket signaling server listening on ws://0.0.0.0:8088/
UDP media server listening on udp://0.0.0.0:8089
STUN server listening on udp://0.0.0.0:3478
```

### 2. Local publishing and playback

| Page / API | URL | Purpose |
|---|---|---|
| WebSocket publish | `http://127.0.0.1:8088/index.html` | Browser DataChannel demo |
| WebSocket publish | `http://127.0.0.1:8088/push.html` | Browser screen/window publishing |
| WebSocket playback | `http://127.0.0.1:8088/play.html` | Play media for the same `streamId` |
| WHIP publish | `http://127.0.0.1:8088/whip.html` | Browser publishing via WHIP |
| WHEP playback | `http://127.0.0.1:8088/whep.html` | Browser playback via WHEP |
| OBS WHIP | `http://127.0.0.1:8088/whip/stream_001` | WHIP service address for OBS |

The publisher and the subscriber must use the same `streamId`. The examples default to `stream_001`.

`push.html`, `play.html` and the home page automatically select `ws://` based on the current page URL; `whip.html` and `whep.html` use the same‑origin HTTP address of the current page, so no manual configuration is needed for local testing.

---

## WHIP / WHEP HTTP API

The project provides WHIP/WHEP‑style SDP POST and resource deletion endpoints, accompanied by demo pages in the repository, and can be used by OBS for WHIP publishing.  
The current Trickle ICE candidate endpoint uses a custom JSON POST path rather than the IETF standard SDP fragment PATCH; please check the request format before integrating other clients.

### WHIP publishing

**Create request**:

```http
POST /whip/<streamId> HTTP/1.1
Content-Type: application/sdp

<entire SDP offer text>
```

**Success response**:

```http
HTTP/1.1 201 Created
Location: /whip/<resourceId>
Content-Type: application/sdp

<server SDP answer>
```

- `streamId` is the business‑defined stream identifier, e.g. `stream_001`.
- Currently `resourceId` is the server‑generated numeric clientId.
- To stop publishing, send `DELETE` to the relative `Location` from the response; success returns `204 No Content`:

```http
DELETE /whip/<resourceId> HTTP/1.1
```

### WHEP playback

**Create request**:

```http
POST /whep/<streamId> HTTP/1.1
Content-Type: application/sdp

<entire SDP offer text>
```

**Success response**:

```http
HTTP/1.1 201 Created
Location: /whep/<resourceId>
Content-Type: application/sdp

<server SDP answer>
```

A Publisher with the same `streamId` must already exist; otherwise a `404 Not Found` is returned immediately with body `Stream not available`. Stop playback using:

```http
DELETE /whep/<resourceId> HTTP/1.1
```

### Trickle ICE candidates

The current candidate endpoint accepts the following custom request; success returns `204 No Content`:

```http
POST /whip/<resourceId>/candidate HTTP/1.1
Content-Type: application/json

{"candidate":"candidate:..."}
```

The WHEP path is `/whep/<resourceId>/candidate`; the server also accepts replacing the final segment `candidate` with `ice`. `whip.html` in the repository uses the JSON POST interface described above.

---

## Public online deployment (recommended: Nginx)

Keep responsibilities separated in production:

- **Nginx**: domain name, HTTPS certificate, WSS, static pages and WHIP/WHEP HTTP reverse proxy.
- **WebRTCServer**: SDP, ICE/STUN, DTLS, SRTP/SRTCP and RTP/RTCP forwarding.
- **UDP 8089**: clients connect directly to WebRTCServer; do **not** pass it through a regular Nginx `proxy_pass`.

### 1. Set the public IP announced in SDP

SDP candidates use the address returned by `WebRTCServer::getLocalIP()`. If the server NIC is directly bound to a public IPv4 address, usually no changes are needed. When a cloud host is behind NAT and uses a public IP, create a subclass of the server in your bootstrap file – no need to modify the SDK core:

```php
<?php

use Xiaosongshu\Webrtc\WebRTCServer;

require_once __DIR__ . '/vendor/autoload.php';

$server = new WebRTCServer(
    8088,
    8089,
    3478,
    __DIR__ . '/debug.log'
);
// Replace with your server's public IPv4 address. Not required for local testing.
$server->publicIp = '127.0.0.1';
// Enable debug mode (set to false in production)
$server->isDev = false;
// Start the service – code after this line will not execute
$server->start();
```

Public NAT must map `8089/UDP` to the same port on the server. The SDP currently announces port `8089` by default; if the public port differs from the internal port, adjust the server's UDP port configuration accordingly.

### 2. Configure domain name and HTTPS certificate

Commercial certificates are not required; you can use Let's Encrypt or any CA certificate trusted by browsers. Browsers usually require an HTTPS secure context for camera, microphone or screen capture.

Place the following configuration in the Nginx `http` block:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name webrtc.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name webrtc.example.com;

    ssl_certificate     /etc/letsencrypt/live/webrtc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/webrtc.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

This proxies pages, WebSocket, WHIP and WHEP to the local `8088/TCP`. The demo pages will automatically use:

```text
wss://webrtc.example.com
https://webrtc.example.com/whip/stream_001
https://webrtc.example.com/whep/stream_001
```

In OBS, choose WHIP as the service type and enter:

```text
https://webrtc.example.com/whip/stream_001
```

WHIP/WHEP responses use relative URLs for the `Location` header, so the same domain can be used for access and deletion.

### 3. Configure firewall and cloud security groups

At a minimum, allow:

| Rule | Source | Description |
|---|---|---|
| `80/TCP` | Public | Optional, only for HTTPS redirect |
| `443/TCP` | Public | HTTPS, WSS, WHIP, WHEP |
| `8089/UDP` | Public | WebRTC media – must be open |
| `3478/UDP` | Public | Only when using the built‑in standalone STUN service |
| `8088/TCP` | Localhost | Nginx → PHP service; do **not** expose directly to the public |

If the server sits behind a router, container or cloud NAT, you must also configure port mapping for `8089/UDP` and ensure `getLocalIP()` returns an IPv4 address that is actually reachable by external clients.

### 4. HTTPS certificate vs. DTLS certificate

The Nginx HTTPS certificate secures pages, WebSocket and WHIP/WHEP HTTP requests. The built‑in DTLS certificate is used for WebRTC media key negotiation; the server writes the SHA‑256 fingerprint of this certificate into the SDP, and the WebRTC client verifies the server certificate against that fingerprint. The two certificates serve different purposes – even when Nginx is used, the project's DTLS certificate and fingerprint logic must be preserved.

### 5. About TURN

Nginx is **not** a TURN service. When the server has a publicly reachable `8089/UDP`, most clients can establish a direct connection. If clients are behind strict enterprise firewalls, symmetric NAT, or networks that block UDP, you need to deploy a separate TURN server and configure its address in the `iceServers` of the client's `RTCPeerConnection`. A Nginx HTTP proxy cannot solve this.

---

## Default signaling protocol for publishing / playback

Both `push.html` and `play.html` communicate with the server via WebSocket JSON text messages.

### 1) join (enter a room)

Publisher:
```json
{ "type": "join", "role": "push", "streamId": "ROOM123" }
```
Subscriber:
```json
{ "type": "join", "role": "play", "streamId": "ROOM123" }
```

Server responds by default with:
```json
{ "type": "joined" }
```

### 2) offer (SDP negotiation)

- **push.html (publisher)**: browser offerer → server answerer
- **play.html (subscriber)**: server offerer → browser answerer (the default SFU automatically generates the offer via `makeSfuOfferForSubscriber()`)

### 3) candidate (ICE candidate addresses)

Default server behavior: forward the publisher's candidates to all play clients in the same `streamId`; forward a play client's candidates only to the corresponding publisher. No extra business code is required.

The current WebSocket signaling does not have a fixed path; any valid WebSocket Upgrade on `8088` reaches the same signaling handler.

---

## Event interface (non‑invasive extension)

**Core design idea**: extend business logic through callbacks. Selected signaling pre‑events support an optional `&$handled` reference parameter (see the event table for details):
- Do **not** set `$handled = true` in a callback that supports it → the SDK continues with its default behavior.
- Set `$handled = true` → the default handling for that event is skipped, and your business code takes full control.

### Event overview

| Event property | When it fires | Signature | Supports &$handled |
|---|---|---|---|
| `$onOpen` | When a TCP/HTTP connection is accepted; also fires again with the channel label after receiving a DataChannel CHANNEL_OPEN | `fn(mixed $label, int $clientId, WebRTCServer $srv):void` | No |
| `$onSignaling` | Any WebSocket signaling message arrives, global pre‑hook | `fn(int $id, array $msg, WebRTCServer $srv, &$handled):void` | **Yes** |
| `$onJoin` | A `join` message is received | `fn(int $id, array $msg, WebRTCServer $srv, &$handled):void` | **Yes** |
| `$onOffer` | An Answer has been generated for an Offer; already sent back in WS flow, not yet written to the response in HTTP flow | `fn(int $id, string $offerSdp, string $answerSdp, WebRTCServer $srv):void` | No |
| `$onPublisher` | After onOffer, if metadata.role==='push', Publisher is ready | `fn(int $id, array $ctx, WebRTCServer $srv):void` | No |
| `$onSubscriber` | WebSocket `role=play` client joined and a Publisher for the same stream was found; HTTP WHEP does not trigger this | `fn(int $id, array $ctx, WebRTCServer $srv):void` | No |
| `$onAnswer` | Client sends an answer (typically a play client) | `fn(int $id, string $answerSdp, WebRTCServer $srv, &$handled):void` | **Yes** |
| `$onCandidate` | An ICE candidate arrives | `fn(int $id, array $msg, WebRTCServer $srv, &$handled):void` | **Yes** |
| `$onMediaConnected` | The first SRTP RTP packet is successfully unprotected (first media frame landed) | `fn(int $id, array $rtpHeader, WebRTCServer $srv):void` | No |
| `$onRtp` | A plaintext RTP packet is received and decrypted successfully; when registered, the business handles the packet | `fn(int $id, string $plainRtp, array $header, WebRTCServer $srv):void` | No |
| `$onmessage` | SCTP DataChannel text or binary message received | `fn(string $data, int $clientId, WebRTCServer $srv):void` | No |
| `$onLeave` | Business leave callback inside `removeClient()` | `fn(int $clientId, WebRTCServer $srv):void` | No |
| `$onClose` | Underlying connection closed callback | `fn(int $clientId, WebRTCServer $srv):void` | No |

### Context `$ctx` field descriptions

- **onPublisher** `$ctx`:
  ```php
  [
      'streamId'   => (string),
      'localSsrc'  => ['video' => int, 'audio' => int],  // SSRCs sent by the SDK to the remote side
      'videoPTs'   => [int => array], // PT => rtpmap / codec / clock / fmtp, etc.
      'audioPTs'   => [int => array],
  ]
  ```
- **onSubscriber** `$ctx`:
  ```php
  [
      'streamId'     => (string),
      'pushClientId' => int  // clientId of the current publisher for this streamId; callback does not fire if none exists
  ]
  ```
- **onMediaConnected** `$rtpHeader`:
  ```php
  [
      'pt' => int,          // RTP Payload Type
      'seq' => int,         // Sequence number
      'ts' => int,          // RTP timestamp
      'ssrc' => int,        // Synchronization source
      'payloadLen' => int,  // RTP payload length (excluding header)
  ]
  ```

### Usage example: authentication before joining a room

`onJoin` supports preventing the default join flow via `$handled`, suitable for performing authentication before writing role, streamId and generating the Subscriber offer:

```php
$verifyToken = function (string $token): bool {
    // Replace with your own database, Redis, or JWT verification.
    return $token !== '';
};

$server->onJoin = function (
    int $clientId,
    array $msg,
    WebRTCServer $srv,
    &$handled
) use ($verifyToken) {
    if ($verifyToken((string)($msg['token'] ?? ''))) {
        return;
    }

    $handled = true;
    $srv->sendSignaling($clientId, [
        'type' => 'error',
        'msg' => 'Authentication failed',
    ]);
};
```

Concurrency limits should be configured by the business based on load testing results; the repository makes no capacity promise for a fixed number of subscribers.

### Usage example: private encrypted signaling

```php
$server->onSignaling = function (int $id, array $msg, WebRTCServer $srv, &$handled) {
    $raw = $msg['_enc'] ?? null;
    if ($raw === null) return; // Not a private encrypted message → use default JSON protocol

    $secret = my_get_secret_for_client($id); // Implemented by the business
    $plain = my_aes_decrypt(base64_decode($raw), $secret);
    $realMsg = json_decode($plain, true);

    // Business handles it → tell the SDK to skip the default
    $handled = true;
    my_business_dispatch($id, $realMsg, $srv);
};
```

---

## Common public API

### Client metadata

| Method | Purpose |
|---|---|
| `getClientIds(): array` | Return all current clientIds |
| `&getClientMeta(int $clientId, ?string $key=null, $default=null)` | Read a field; passing `null` for `$key` returns the entire metadata array by reference |
| `setClientMeta(int $clientId, string $key, $value): bool` | Write a business field; returns `false` if the clientId does not exist |
| `getClientsByMeta(string $key, $value=null): array` | Filter clientIds by metadata |
| `getPublisherIdByStreamId(string $streamId): ?int` | Find the clientId with role=push for the given streamId |
| `getClientTrackInfo(int $clientId): array` | Obtain client PT and local SSRC mappings |

### Signaling and DataChannel

| Method | Purpose |
|---|---|
| `sendSignaling(int $clientId, array $msg): bool` | Send a JSON signaling message to one client via WebSocket |
| `broadcastSignaling(array $clientIds, array $msg): int` | Broadcast a signaling message to multiple clients; returns number of successes |
| `sendDataChannel(int $clientId, string $message, int $ppid=51, int $sid=0)` | Send a DataChannel message; the current implementation returns bool but the return type is not declared |
| `getClientsWithDataChannel(array $excludeIds=[]): array` | Return a list of clients with an established SCTP association |
| `broadcastDataChannel(array $clientIds, string $message, int $ppid=51, int $sid=0): int` | Send a DataChannel message to multiple clients; returns number of successes |

### SFU subscriber offer and media forwarding

| Method | Purpose |
|---|---|
| `makeSfuOfferForSubscriber(int $subscriberId, int $publisherId, string $setup='passive'): ?string` | Generate an SFU Offer for a subscriber based on the Publisher's Offer; defaults to the server acting as DTLS passive |
| `forwardRtpToClient(int $targetClientId, string $plainRtp, bool $ssrcRewrite=true): bool` | Rewrite and encrypt a plaintext RTP packet, then send it to a specific client |
| `forwardRtpToAllSubscribers(string $streamId, string $plainRtp, int $excludeClientId=-1): int` | Distribute to all role=play clients in the same streamId; returns number of successes |

---

## Default SFU workflow (runs automatically with zero code)

1. **push.html** sends `join(role=push, streamId=X)` → server stores metadata
2. **push.html** → `createOffer()` → `setLocalDescription(offer)` → sends `{"type":"offer","sdp":...}`
3. **Server handleOffer()**
    - Extracts remote `ice-ufrag / ice-pwd / setup`
    - Calls `generateAnswerSDP()` to produce an answer, filling `serverVideoSsrc / serverAudioSsrc / PT table`
    - Sends back answer → fires `onOffer` → if role=push → fires `onPublisher`
4. **play.html** sends `join(role=play, streamId=X)` → `_fireSubscriberIfReady()`
    - If a pushClientId already exists → **automatically** calls `makeSfuOfferForSubscriber()` to generate an SFU offer
    - `sendSignaling(['type'=>'offer','sdp'=>...])` is sent to play.html
5. **play.html** receives the offer → `setRemoteDescription` → `createAnswer` → sends back answer
6. **Server handles answer** → extracts play's `ice-ufrag/pwd` for STUN / DTLS
7. **Both sides ICE connected → DTLS handshake → SRTP keys derived**
8. **Publisher UDP receives RTP**: successful unprotect → `onMediaConnected` fires → `forwardRtpToAllSubscribers(streamId)` → for each play client:
    - Rewrites SSRC to `serverVideoSsrc / serverAudioSsrc` according to the play client's PT (exactly matching the SSRC in the offer from step 4)
    - Protects with the play client's srtpTx → sends via UDP
9. **Play client SRTP decrypts** → browser renders video/audio tags automatically

---

## Frequently Asked Questions

### Q1. Browser `setRemoteDescription` fails with "Failed to set remote offer sdp: Session error code: ERROR_CONTENT"

First check the browser console for Offer/Answer messages and the `debug.log`. The current SFU Subscriber Offer uses the server's fixed support for H264/Opus and PT mapping. If your business requires other codecs, you should extend the SDP generation and RTP PT conversion logic, rather than only modifying the page SDP.

### Q2. Publishing works, but the viewer sees a black screen / stuck at "negotiating media"

Troubleshoot in this order:
1. Check `debug.log` for `SRTP-IN ok` entries (= push media has reached the server).
2. Look for `SFU forward streamId=xxx -> N subscriber(s)` (= subscriber forwarding is happening).
3. In the play.html browser console, check for SDP offer/answer logs and whether the ICE connection state becomes `connected`.
4. If play.html did not receive an offer → verify that the `streamId` used when joining matches the publisher's, and that `role` is `play`.

### Q3. How do I deploy with HTTPS?

Refer to the "Public online deployment (recommended: Nginx)" section above. The demo pages automatically choose `ws://` or `wss://` based on the current page protocol; you do not need to manually change JavaScript addresses. Important: Nginx only proxies `8088/TCP` – the media port `8089/UDP` must still be directly open to the public.

---

## Known issues

- **Codec fixed to H.264 + Opus**  
  For maximum compatibility with mainstream browsers, OBS, and common mobile devices, the server currently supports only H.264 video and Opus audio.  
  If your business needs VP8, VP9, H.265 or other codecs, you must extend the SDP negotiation logic and RTP forwarding rules yourself.

- **OBS publishing may occasionally drop unexpectedly**  
  Under high‑motion scenes or network fluctuations, OBS publishing may terminate.  
  This is related to libwebrtc’s strict requirements on ICE consent, RTCP feedback and bandwidth estimation. Future versions will continue to optimize the ICE keep‑alive mechanism and RTCP REMB feedback to improve stability.  
  **Temporary mitigation**: enable **CBR** rate control in OBS output settings and lower the video bitrate and resolution appropriately.

- **OBS encoder compatibility limitations**  
  The following OBS H.264 encoders have been verified to publish successfully:
    - `x264`
    - `QuickSync H.264`
    - `AMD HW H.264 (AVC)`  
      These encoders work correctly under the `baseline`, `main` and `high` profiles.  
      **Incompatible encoder**: `H264/AVC Encoder (AMD Advanced Media Framework)` – using this encoder may cause publishing failure or abnormal video.  
      If you encounter issues with other encoders, switching to one of the above verified encoders is recommended.

---

## Open source license & Disclaimer

This project is open sourced under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0). You are free to use, modify and distribute it (including for commercial purposes).  
The code is provided “AS IS”, without warranty of any kind, express or implied. The author shall not be liable for any damages arising from the use of this software.

## License

Apache License 2.0

---

## 📧 Contact

- 📬 Email: 2723659854@qq.com
- 🐙 GitHub: [2723659854](https://github.com/2723659854)