<?php

namespace Xiaosongshu\Webrtc\Core;


/**
 * @purpose stun 地址查询服务
 * @author yanglong
 */
trait STUN
{

    /**
     * 启动stun服务器
     * @return void
     * @note NAT 地址探测助手，公网上两个客户端通过路由器探测对方的位置，这里构建服务器，本服务器成为一个大型路由器。
     * 客户端通过访问本stun服务器获取自己的公网地址，然后使用WS 信令服务器广播给其他客户端，其他客户端一样需要获取自己的公网ip广播出去，
     * 当两个客户端都拿到对方的公网ip之后，就可以建立连接通信了。两个客户端之间需要使用dtls握手。
     */
    private function startSTUNServer()
    {
        $this->stunSocket = @stream_socket_server("udp://0.0.0.0:" . $this->stunPort, $errno, $errstr, STREAM_SERVER_BIND);
        if (!$this->stunSocket) {
            echo "Failed to create STUN socket: {$errstr}\n";
            exit(1);
        }
        stream_set_blocking($this->stunSocket, false);
        echo "STUN server listening on udp://0.0.0.0:" . $this->stunPort . "\n";
    }


    /**
     * 处理STUN消息 （路由表）
     * @param $clientId
     * @param $data
     * @param $from
     * @return void
     */
    private function handleSTUNMessage($clientId, $data, $from)
    {
        if (strlen($data) < 20) return;

        $msgType = unpack('n', substr($data, 0, 2))[1];
        $msgLen = unpack('n', substr($data, 2, 2))[1];
        $transactionId = substr($data, 8, 12);
        $magicCookie = "\x21\x12\xA4\x42";

        if ($msgType === 0x0001) {
            $icePwd = $this->clients[$clientId]['icePwd'] ?? '';

            $fromParts = explode(':', $from);
            $clientIP = $fromParts[0];
            $clientPort = (int)$fromParts[1];

            $xorPort = $clientPort ^ 0x2112;
            $xorIP = ip2long($clientIP) ^ 0x2112A442;
            $xorAttr = "\x00\x20\x00\x08\x00\x01";
            $xorAttr .= pack('n', $xorPort);
            $xorAttr .= pack('N', $xorIP);

            $headerForMI = pack('n', 0x0101) . pack('n', 36) . $magicCookie . $transactionId;
            $msgForHmac = $headerForMI . $xorAttr;
            $hmac = hash_hmac('sha1', $msgForHmac, $icePwd, true);
            $miAttr = "\x00\x08\x00\x14" . $hmac;
            $headerForFP = pack('n', 0x0101) . pack('n', 44) . $magicCookie . $transactionId;
            $msgForCrc = $headerForFP . $xorAttr . $miAttr;
            $crc = crc32($msgForCrc) ^ 0x5354554E;
            $fpAttr = "\x80\x28\x00\x04" . pack('N', $crc);

            $response = $headerForFP . $xorAttr . $miAttr . $fpAttr;

            $sent = @stream_socket_sendto($this->udpSocket, $response, 0, $from);

            static $_stunTrace = [];
            $traceNow = microtime(true);
            $txHex = bin2hex($transactionId);
            $traceKey = $clientId . ':' . $txHex;
            $previousAt = (float)($_stunTrace[$traceKey] ?? 0.0);
            $_stunTrace[$traceKey] = $traceNow;
            $username = '';
            $hasRequestIntegrity = false;
            $hasRequestFingerprint = false;
            $useCandidate = false;
            for ($offset = 20, $end = min(20 + $msgLen, strlen($data)); ($offset + 4) <= $end;) {
                $attributeType = unpack('n', substr($data, $offset, 2))[1];
                $attributeLength = unpack('n', substr($data, $offset + 2, 2))[1];
                if (($offset + 4 + $attributeLength) > $end) break;
                if ($attributeType === 0x0006) $username = substr($data, $offset + 4, $attributeLength);
                if ($attributeType === 0x0008) $hasRequestIntegrity = true;
                if ($attributeType === 0x8028) $hasRequestFingerprint = true;
                if ($attributeType === 0x0025) $useCandidate = true;
                $offset += 4 + (($attributeLength + 3) & ~3);
            }
            $meta = is_array($this->clients[$clientId]['meta'] ?? null) ? $this->clients[$clientId]['meta'] : [];
            $payload = json_encode([
                'sessionId' => 'obs-dynamic-scene-disconnect',
                'runId' => 'pre-fix-consent-trace',
                'hypothesisId' => 'ice-consent-integrity',
                'location' => 'src/Core/STUN.php:handleSTUNMessage',
                'msg' => '[DEBUG] STUN consent transaction',
                'data' => [
                    'clientId' => (int)$clientId,
                    'role' => (string)($meta['role'] ?? ''),
                    'streamId' => (string)($meta['streamId'] ?? ''),
                    'from' => $from,
                    'transactionId' => $txHex,
                    'retransmission' => $previousAt > 0.0,
                    'retransmitAfterMs' => $previousAt > 0.0 ? (int)(($traceNow - $previousAt) * 1000) : null,
                    'requestLength' => strlen($data),
                    'declaredAttributeLength' => $msgLen,
                    'username' => $username,
                    'requestHasIntegrity' => $hasRequestIntegrity,
                    'requestHasFingerprint' => $hasRequestFingerprint,
                    'useCandidate' => $useCandidate,
                    'icePasswordPresent' => $icePwd !== '',
                    'responseLength' => strlen($response),
                    'sentBytes' => $sent === false ? -1 : (int)$sent,
                    'responseHeaderHex' => bin2hex(substr($response, 0, 20)),
                ],
                'ts' => (int)($traceNow * 1000),
            ]);
            $this->_udpDbgHttpPost($payload, 'obs-dynamic-scene-disconnect');
            if (count($_stunTrace) > 256) $_stunTrace = array_slice($_stunTrace, -128, null, true);

            static $_stunSummary = [];
            $now = microtime(true);
            if (!isset($_stunSummary[$clientId])) {
                $_stunSummary[$clientId] = ['requests' => 0, 'responses' => 0, 'failed' => 0, 'lastResponseLen' => 0, 'lastLog' => 0.0];
            }
            $_stunSummary[$clientId]['requests']++;
            if ($sent === strlen($response)) {
                $_stunSummary[$clientId]['responses']++;
            } else {
                $_stunSummary[$clientId]['failed']++;
            }
            $_stunSummary[$clientId]['lastResponseLen'] = strlen($response);
            if ($_stunSummary[$clientId]['lastLog'] === 0.0 || ($now - $_stunSummary[$clientId]['lastLog']) >= 60.0) {
                $this->_log_std("Client {$clientId} STUN summary requests={$_stunSummary[$clientId]['requests']} responses={$_stunSummary[$clientId]['responses']} failed={$_stunSummary[$clientId]['failed']} lastResponseLen={$_stunSummary[$clientId]['lastResponseLen']}\n");
                $_stunSummary[$clientId]['requests'] = 0;
                $_stunSummary[$clientId]['responses'] = 0;
                $_stunSummary[$clientId]['failed'] = 0;
                $_stunSummary[$clientId]['lastLog'] = $now;
            }
        }
    }




    /**
     * 处理stun连接
     * @return void
     */
    private function handleSTUN()
    {
        $from = '';
        $data = @stream_socket_recvfrom($this->stunSocket, 65536, 0, $from);

        if ($data === false || strlen($data) === 0) return;

        if (strlen($data) >= 20) {
            $msgType = unpack('n', substr($data, 0, 2))[1];

            if ($msgType === 0x0001) {
                $transactionId = substr($data, 8, 12);
                $fromParts = explode(':', $from);
                $clientIP = $fromParts[0];
                $clientPort = (int)$fromParts[1];

                $xorPort = $clientPort ^ 0x2112;
                $xorIP = ip2long($clientIP) ^ 0x2112A442;

                $xorMappedAddress = "\x00\x20\x00\x08\x00\x01";
                $xorMappedAddress .= pack('n', $xorPort);
                $xorMappedAddress .= pack('N', $xorIP);

                $response = pack('n', 0x0101);
                $response .= pack('n', 12);
                $response .= "\x21\x12\xA4\x42";
                $response .= $transactionId;
                $response .= $xorMappedAddress;

                stream_socket_sendto($this->stunSocket, $response, 0, $from);
            }
        }
    }
}