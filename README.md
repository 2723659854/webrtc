# WebRTC SDK for PHP

一个基于 PHP >= 7.3.9 原生 socket 实现的轻量级 WebRTC SFU（Selective Forwarding Unit）服务器。
采用单进程异步事件循环，内置 WebSocket 信令、STUN、DTLS、SCTP（DataChannel）和 SRTP 音视频转发；不依赖第三方 Composer 运行时包。
支持通过事件回调无侵入扩展业务逻辑，无需修改 SDK 核心代码即可实现多房间、鉴权、计费、聊天广播、自定义信令等能力。

---

## 特性

| 能力 | 说明                                                                                                |
|---|---------------------------------------------------------------------------------------------------|
| WebSocket 信令服务 | 内置独立的 HTTP/WS 服务 (默认 8088 端口)，自带静态文件托管                                                            |
| STUN / ICE | 独立 STUN Binding 服务默认监听 3478；WebRTC 媒体端口上的 ICE Binding Response 包含 MESSAGE-INTEGRITY 和 FINGERPRINT |
| DTLS 握手 | RFC 6347 / RFC 5764（DTLS-SRTP），内置证书，SRTP 主密钥自动协商派生                                                |
| SRTP 协议 | AES-128-ICM 加密、HMAC-SHA1-80 认证、ROC 和重复包防护                                                         |
| SCTP DataChannel | PPID=51 文本 / 53 二进制 / 56/57 部分可靠流 (onmessage 回调)                                                  |
| SFU 媒体转发 | SSRC 自动重写 + 多订阅者分发，push 端一路推流 -> 多路 play 端观看                                                      |
| 事件驱动接口 | 提供连接、信令、Publisher、Subscriber、RTP 和 DataChannel 等回调；部分前置事件可通过 `&$handled` 接管默认处理                   |
| 元数据管理 | Client 级 KV metadata，房间 / 角色 / 并发限制等业务字段自由扩展                                                      |
| 无第三方运行时包 | 使用 PHP 的 `openssl`、`json`、 `sockets` 扩展                                                           |


---

## 环境要求

- PHP **>= 7.3.9**
- PHP 扩展：
  - `openssl`
  - `json`
  - `sockets`
- Composer
- 操作系统：Windows / Linux / macOS

安装依赖：

```bash
composer require xiaosongshu/webrtc
```

---

## 端口与网络模型

| 端口 | 协议 | 作用 | 公网部署方式 |
|---|---|---|---|
| `8088` | TCP (HTTP/WS) | 页面、WebSocket 信令、WHIP/WHEP HTTP API | 服务当前绑定 `0.0.0.0`；公网部署时用防火墙限制，仅允许 Nginx 访问 |
| `8089` | UDP | ICE、DTLS、SRTP/SRTCP、RTP/RTCP 媒体 | 必须让客户端直接访问，普通 Nginx HTTP 代理不能转发 |
| `3478` | UDP | 可选的独立 STUN Binding 服务 | 使用该服务时直接开放 |

浏览器或 OBS 首先通过 HTTP/WebSocket 完成信令和 SDP 协商，随后根据 SDP candidate 直接连接 `服务器IP:8089/UDP`。HTTPS 代理成功并不代表媒体端口已经连通。

---

## 本地部署

源码仓库根目录提供 `start.php` 以及 `index.html`、`push.html`、`play.html`、`whip.html`、`whep.html` 示例页面。通过 Composer 安装时，可参考仓库中的 `start.php` 在业务项目创建启动入口；服务器默认读取 SDK 包根目录中的示例静态文件，仅复制 `start.php` 不会改变静态文件目录。

### 1. 启动服务
```powershell
php start.php
```
启动成功后会看到类似输出：

```text
Using certificate: .../src/Core/certs/server.crt
WebSocket signaling server listening on ws://0.0.0.0:8088/
UDP media server listening on udp://0.0.0.0:8089
STUN server listening on udp://0.0.0.0:3478
```

### 2. 本地推流和拉流

| 页面/API     | 地址                                      | 用途                  |
|------------|-----------------------------------------|---------------------|
| WebSocket 推流 | `http://127.0.0.1:8088/index.html`      | 浏览器datachannel演示    |
| WebSocket 推流 | `http://127.0.0.1:8088/push.html`       | 浏览器屏幕/窗口推流          |
| WebSocket 拉流 | `http://127.0.0.1:8088/play.html`       | 播放相同 `streamId` 的媒体 |
| WHIP 推流    | `http://127.0.0.1:8088/whip.html`       | 浏览器通过 WHIP 推流       |
| WHEP 拉流    | `http://127.0.0.1:8088/whep.html`       | 浏览器通过 WHEP 拉流       |
| OBS WHIP   | `http://127.0.0.1:8088/whip/stream_001` | OBS 的 WHIP 服务地址     |

推流端与拉流端必须使用相同的 `streamId`。示例默认使用 `stream_001`。

`push.html`、`play.html` 和首页会根据当前页面地址自动选择 `ws://`；`whip.html`、`whep.html` 会自动使用当前页面的同源 HTTP 地址，因此本地运行无需修改页面配置。

---

## WHIP / WHEP HTTP 接口

项目提供 WHIP/WHEP 风格的 SDP POST 和资源删除接口，已配套仓库示例页面，并可供 OBS 使用 WHIP 推流。当前 Trickle ICE 候选接口采用项目自定义的 JSON POST 路径，并非 IETF 标准的 SDP fragment PATCH；接入其他客户端前请核对其请求格式。

### WHIP 推流

**创建请求**：

```http
POST /whip/<streamId> HTTP/1.1
Content-Type: application/sdp

<整个 SDP offer 文本>
```

**成功响应**：

```http
HTTP/1.1 201 Created
Location: /whip/<resourceId>
Content-Type: application/sdp

<服务端 SDP answer>
```

- `streamId` 是业务定义的流标识，例如 `stream_001`。
- 当前 `resourceId` 是服务端生成的数字 clientId。
- 停止推流时向响应中的相对 `Location` 发送 `DELETE`，成功返回 `204 No Content`：

```http
DELETE /whip/<resourceId> HTTP/1.1
```

### WHEP 拉流

**创建请求**：

```http
POST /whep/<streamId> HTTP/1.1
Content-Type: application/sdp

<整个 SDP offer 文本>
```

**成功响应**：

```http
HTTP/1.1 201 Created
Location: /whep/<resourceId>
Content-Type: application/sdp

<服务端 SDP answer>
```

必须先存在相同 `streamId` 的 Publisher；否则立即返回 `404 Not Found`，响应正文为 `Stream not available`。停止拉流使用：

```http
DELETE /whep/<resourceId> HTTP/1.1
```

### Trickle ICE 候选

当前候选接口接受以下项目自定义请求，成功返回 `204 No Content`：

```http
POST /whip/<resourceId>/candidate HTTP/1.1
Content-Type: application/json

{"candidate":"candidate:..."}
```

WHEP 对应路径为 `/whep/<resourceId>/candidate`；服务端也接受将最后一段 `candidate` 写为 `ice`。仓库中的 `whip.html` 使用上述 JSON POST 接口。

## 公网线上部署（推荐 Nginx）

生产环境建议保持职责分离：

- **Nginx**：域名、HTTPS 证书、WSS、静态页面及 WHIP/WHEP HTTP 反向代理。
- **WebRTCServer**：SDP、ICE/STUN、DTLS、SRTP/SRTCP 和 RTP/RTCP 转发。
- **UDP 8089**：客户端直接连接 WebRTCServer，不经过普通 Nginx `proxy_pass`。

### 1. 设置 SDP 对外公布的公网 IP

SDP candidate 使用 `WebRTCServer::getLocalIP()` 返回的地址。服务器网卡直接绑定公网 IPv4 时通常无需处理；云主机通过 NAT 使用公网 IP 时，在业务启动文件中继承服务器类即可，无需修改 SDK 核心：

```php
<?php

use Xiaosongshu\Webrtc\WebRTCServer;

require_once __DIR__ . '/vendor/autoload.php';

class PublicWebRTCServer extends WebRTCServer
{
    public function getLocalIP()
    {
        // 替换为服务器公网 IPv4，也可贴合自己的业务需求自由实现
        return '203.0.113.10';
    }
}

$server = new PublicWebRTCServer(
    8088,
    8089,
    3478,
    __DIR__ . '/debug.log'
);

// 在这里注册 onJoin、onPublisher、onSubscriber 等业务回调。
$server->start();
```

公网 NAT 必须把 `8089/UDP` 映射到服务器同一端口。当前 SDP 默认公布端口 `8089`，如果公网端口与内网端口不同，需要同步调整服务端 UDP 端口配置。

### 2. 配置域名和 HTTPS 证书

不要求购买商业证书，可以使用 Let's Encrypt 或其他受浏览器信任的 CA 证书。公网浏览器采集摄像头、麦克风或屏幕通常要求 HTTPS 安全上下文。

以下配置放在 Nginx `http` 配置范围内：

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

该配置将页面、WebSocket、WHIP 和 WHEP 都代理到本机 `8088/TCP`。示例页面会自动使用：

```text
wss://webrtc.example.com
https://webrtc.example.com/whip/stream_001
https://webrtc.example.com/whep/stream_001
```

OBS 的服务类型选择 WHIP，服务地址填写：

```text
https://webrtc.example.com/whip/stream_001
```

WHIP/WHEP 返回的资源 `Location` 使用相对 URL，可继续通过同一域名访问和删除。

### 3. 配置防火墙和云安全组

至少放行：

| 规则 | 来源 | 说明 |
|---|---|---|
| `80/TCP` | 公网 | 可选，仅用于跳转 HTTPS |
| `443/TCP` | 公网 | HTTPS、WSS、WHIP、WHEP |
| `8089/UDP` | 公网 | WebRTC 媒体，必须开放 |
| `3478/UDP` | 公网 | 仅在使用内置独立 STUN 时开放 |
| `8088/TCP` | 本机 | Nginx 到 PHP 服务；不建议直接向公网开放 |

如果服务器位于路由器、容器或云 NAT 后面，还必须配置 `8089/UDP` 端口映射，并确保 `getLocalIP()` 返回外部客户端实际可达的 IPv4。

### 4. HTTPS 证书与 DTLS 证书的区别

Nginx HTTPS 证书用于保护页面、WebSocket 和 WHIP/WHEP HTTP 请求；项目内置 DTLS 证书用于 WebRTC 媒体密钥协商。服务端将该证书的 SHA-256 fingerprint 写入 SDP，由 WebRTC 客户端验证服务端证书。两者用途不同，使用 Nginx 后仍需保留项目的 DTLS 证书和指纹逻辑。

### 5. TURN 说明

Nginx 不是 TURN 服务。服务器拥有公网可达的 `8089/UDP` 时，多数客户端可以直接建立连接；如果客户端处于严格企业防火墙、对称 NAT 或禁止 UDP 的网络，需要另行部署 TURN，并在客户端 `RTCPeerConnection` 的 `iceServers` 中配置，不能依靠 Nginx HTTP 代理解决。

---

## 推流 / 拉流默认信令协议

`push.html` 与 `play.html` 均通过 WebSocket 发送 JSON 文本消息与服务端通信。

### 1) join（进入房间）

推流端：
```json
{ "type": "join", "role": "push", "streamId": "ROOM123" }
```
拉流端：
```json
{ "type": "join", "role": "play", "streamId": "ROOM123" }
```

服务端默认回：
```json
{ "type": "joined" }
```

### 2) offer（SDP 协商）

- **push.html（推流端）**：浏览器 offerer → 服务端 answerer
- **play.html（拉流端）**：服务端 offerer → 浏览器 answerer（缺省 SFU 自动由 `makeSfuOfferForSubscriber()` 生成）

### 3) candidate（ICE 候选地址）

服务端缺省：把 push 端的 candidate 转发给同 streamId 的所有 play 端；play 端的 candidate 只转发给对应的 push 端，无需额外业务代码。

当前 WebSocket 信令没有固定 path；`8088` 上任意 URL 的有效 WebSocket Upgrade 都进入同一信令处理器。

---

## 事件接口（无侵入扩展）

**核心设计思想**：通过回调扩展业务；其中部分信令前置事件支持可选的 `&$handled` 引用参数，具体以事件表为准：
- 支持 `&$handled` 的回调中不设置 `true` → 继续执行 SDK 的缺省处理
- 设置 `$handled=true` → 跳过该事件对应的缺省处理，由业务代码接管

### 事件总览

| 事件属性 | 触发时机 | 签名 | 是否支持 &$handled |
|---|---|---|---|
| `$onOpen` | TCP/HTTP 连接 accept 时触发；收到 DataChannel CHANNEL_OPEN 后还会以 channel label 再次触发 | `fn(mixed $label, int $clientId, WebRTCServer $srv):void` | 否 |
| `$onSignaling` | 任何 WebSocket 信令到达，全局前置钩子 | `fn(int $id, array $msg, WebRTCServer $srv, &$handled):void` | **是** |
| `$onJoin` | 收到 `join` 信令 | `fn(int $id, array $msg, WebRTCServer $srv, &$handled):void` | **是** |
| `$onOffer` | Offer 已生成 Answer；WS 流程中已回发，HTTP 流程中尚未写出响应 | `fn(int $id, string $offerSdp, string $answerSdp, WebRTCServer $srv):void` | 否 |
| `$onPublisher` | onOffer 后若 metadata.role==='push'，Publisher 就绪 | `fn(int $id, array $ctx, WebRTCServer $srv):void` | 否 |
| `$onSubscriber` | WebSocket `role=play` 客户端 join 且已找到同流 Publisher 后触发；HTTP WHEP 不触发 | `fn(int $id, array $ctx, WebRTCServer $srv):void` | 否 |
| `$onAnswer` | 客户端发来 answer（通常 play 端） | `fn(int $id, string $answerSdp, WebRTCServer $srv, &$handled):void` | **是** |
| `$onCandidate` | ICE candidate 到达 | `fn(int $id, array $msg, WebRTCServer $srv, &$handled):void` | **是** |
| `$onMediaConnected` | 首个 SRTP RTP 包成功 unprotect（媒体首帧落地） | `fn(int $id, array $rtpHeader, WebRTCServer $srv):void` | 否 |
| `$onRtp` | 收到并成功解密明文 RTP；注册后由业务处理该包 | `fn(int $id, string $plainRtp, array $header, WebRTCServer $srv):void` | 否 |
| `$onmessage` | 收到 SCTP DataChannel 文本或二进制消息 | `fn(string $data, int $clientId, WebRTCServer $srv):void` | 否 |
| `$onLeave` | `removeClient()` 中的业务离开回调 | `fn(int $clientId, WebRTCServer $srv):void` | 否 |
| `$onClose` | 底层连接关闭回调 | `fn(int $clientId, WebRTCServer $srv):void` | 否 |

### 上下文 $ctx 字段说明

- **onPublisher** `$ctx`:
  ```php
  [
      'streamId'   => (string),
      'localSsrc'  => ['video' => int, 'audio' => int],  // SDK 发给远端的 SSRC
      'videoPTs'   => [int => array], // PT => rtpmap/codec/clock/fmtp 等信息
      'audioPTs'   => [int => array],
  ]
  ```
- **onSubscriber** `$ctx`:
  ```php
  [
      'streamId'     => (string),
      'pushClientId' => int  // 同 streamId 当前 push 端 clientId；不存在时不触发回调
  ]
  ```
- **onMediaConnected** `$rtpHeader`:
  ```php
  [
      'pt' => int,          // RTP Payload Type
      'seq' => int,         // 序列号
      'ts' => int,          // RTP timestamp
      'ssrc' => int,        // 同步源
      'payloadLen' => int,  // RTP 载荷长度 (不含头)
  ]
  ```

### 使用示例：加入房间前鉴权

`onJoin` 支持通过 `$handled` 阻止默认 join 流程，适合在写入 role、streamId 和生成 Subscriber Offer 前完成鉴权：

```php
$verifyToken = function (string $token): bool {
    // 替换为业务自己的数据库、Redis 或 JWT 校验。
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
        'msg' => '鉴权失败',
    ]);
};
```

并发上限应由业务根据压测结果配置；仓库不对固定订阅者数量作容量承诺。

### 使用示例：私有加密信令

```php
$server->onSignaling = function (int $id, array $msg, WebRTCServer $srv, &$handled) {
    $raw = $msg['_enc'] ?? null;
    if ($raw === null) return; // 不是私有加密消息 → 走默认 JSON 协议

    $secret = my_get_secret_for_client($id); // 业务自行实现
    $plain = my_aes_decrypt(base64_decode($raw), $secret);
    $realMsg = json_decode($plain, true);

    // 业务自己处理 → 告诉 SDK 跳过默认
    $handled = true;
    my_business_dispatch($id, $realMsg, $srv);
};
```

---

## 常用公共 API

### 客户端元数据

| 方法 | 作用 |
|---|---|
| `getClientIds(): array` | 返回当前所有 clientId |
| `&getClientMeta(int $clientId, ?string $key=null, $default=null)` | 读取字段；`$key=null` 时按引用返回整个 metadata 数组 |
| `setClientMeta(int $clientId, string $key, $value): bool` | 写入业务字段；clientId 不存在时返回 `false` |
| `getClientsByMeta(string $key, $value=null): array` | 根据 metadata 筛选 clientId |
| `getPublisherIdByStreamId(string $streamId): ?int` | 查找指定 streamId 下 role=push 的 clientId |
| `getClientTrackInfo(int $clientId): array` | 获取客户端 PT 和本地 SSRC 映射 |

### 信令和 DataChannel

| 方法 | 作用 |
|---|---|
| `sendSignaling(int $clientId, array $msg): bool` | WebSocket 发送 JSON 信令给一个客户端 |
| `broadcastSignaling(array $clientIds, array $msg): int` | WebSocket 广播给多个客户端，返回成功数 |
| `sendDataChannel(int $clientId, string $message, int $ppid=51, int $sid=0)` | 发送 DataChannel 消息；当前实现返回 bool，但未声明返回类型 |
| `getClientsWithDataChannel(array $excludeIds=[]): array` | 返回 SCTP 已建立的客户端列表 |
| `broadcastDataChannel(array $clientIds, string $message, int $ppid=51, int $sid=0): int` | 批量发送 DataChannel 消息，返回成功数 |

### SFU 订阅者 Offer 和媒体转发

| 方法 | 作用 |
|---|---|
| `makeSfuOfferForSubscriber(int $subscriberId, int $publisherId, string $setup='passive'): ?string` | 基于 Publisher Offer 生成 Subscriber 的 SFU Offer，默认让服务器作为 DTLS passive 端 |
| `forwardRtpToClient(int $targetClientId, string $plainRtp, bool $ssrcRewrite=true): bool` | 将明文 RTP 重写并加密后发给指定客户端 |
| `forwardRtpToAllSubscribers(string $streamId, string $plainRtp, int $excludeClientId=-1): int` | 给同 streamId 的所有 role=play 客户端分发，返回成功数 |

---

## 缺省 SFU 工作流程（零代码自动跑通）

1. **push.html** 发送 `join(role=push, streamId=X)` → 服务端存 metadata
2. **push.html** → `createOffer()` → `setLocalDescription(offer)` → 发送 `{"type":"offer","sdp":...}`
3. **服务端 handleOffer()**
   - 提取远端 `ice-ufrag / ice-pwd / setup`
   - 调 `generateAnswerSDP()` 生成 answer，填好 `serverVideoSsrc / serverAudioSsrc / PT 表`
   - 回发 answer → 触发 `onOffer` → 若 role=push → 触发 `onPublisher`
4. **play.html** 发送 `join(role=play, streamId=X)` → `_fireSubscriberIfReady()`
   - 若已有 pushClientId → **自动**调 `makeSfuOfferForSubscriber()` 生成 SFU offer
   - `sendSignaling(['type'=>'offer','sdp'=>...])` 发送给 play.html
5. **play.html** 收到 offer → `setRemoteDescription` → `createAnswer` → 回发 answer
6. **服务端 handle answer** → 提取 play 的 `ice-ufrag/pwd` 给 STUN / DTLS
7. **两端 ICE 连通 → DTLS 握手 → SRTP keys 导出**
8. **push 端 UDP 收 RTP**：unprotect 成功 → `onMediaConnected` 触发 → `forwardRtpToAllSubscribers(streamId)` → 对每个 play 端：
   - 按 play 端 PT 重写 SSRC 为 `serverVideoSsrc / serverAudioSsrc`（与步骤 4 发的 offer 中的 SSRC 严格一致）
   - 用 play 端的 srtpTx protect → UDP send
9. **play 端 SRTP 解密** → 浏览器 video/audio tag 自动渲染

---

## 常见问题

### Q1. 浏览器 `setRemoteDescription` 报错 "Failed to set remote offer sdp: Session error code: ERROR_CONTENT"

先检查浏览器控制台中的 Offer/Answer 和 `debug.log`。当前 SFU Subscriber Offer 使用服务端固定支持的 H264/Opus 和 PT 映射；如果业务需要其他编解码器，应先扩展 SDP 生成与 RTP PT 转换逻辑，而不是只改页面 SDP。

### Q2. 推流正常，观众端黑屏 / 一直 "协商媒体中"

按以下步骤排查：
1. 看 `debug.log` 是否有 `SRTP-IN ok` 日志（= push 端媒体已到服务端）
2. 看是否有 `SFU forward streamId=xxx -> N subscriber(s)`（= 订阅者转发）
3. 看浏览器 play.html console 是否有 SDP offer / answer 日志，以及 ICE 连接状态是否变成 `connected`
4. play.html 若未收到 offer → 检查 join 时 `streamId` 是否与 push 端一致，`role` 是否为 `play`

### Q3. 如何用 HTTPS 部署？

参见前文“公网线上部署（推荐 Nginx）”。示例页面已经根据当前页面协议自动选择同源 `ws://` 或 `wss://`，不需要手动修改 JavaScript 地址。需要特别注意：Nginx 只代理 `8088/TCP`，媒体 `8089/UDP` 仍须直接对公网开放。

---

## License

Apache License 2.0
