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

            $responseUsername = '';
            $useCandidate = false;
            $attributesEnd = min(strlen($data), 20 + $msgLen);
            for ($offset = 20; ($offset + 4) <= $attributesEnd;) {
                $attribute = unpack('ntype/nlength', substr($data, $offset, 4));
                $attributeLength = (int)$attribute['length'];
                if (($offset + 4 + $attributeLength) > $attributesEnd) break;

                if ((int)$attribute['type'] === 0x0006) {
                    $responseUsername = substr($data, $offset + 4, $attributeLength);
                } elseif ((int)$attribute['type'] === 0x0025) {
                    $useCandidate = true;
                }
                $offset += 4 + (($attributeLength + 3) & ~3);
            }

            if ($responseUsername === '') return;

            if ($useCandidate) {
                $previous = $this->clients[$clientId]['remoteCandidate'] ?? null;
                $previousAddress = is_array($previous)
                    ? (string)$previous['ip'] . ':' . (int)$previous['port']
                    : 'none';
                $newAddress = $clientIP . ':' . $clientPort;
                $this->clients[$clientId]['remoteCandidate'] = [
                    'ip' => $clientIP,
                    'port' => $clientPort,
                ];
                $this->clients[$clientId]['remoteCandidateValidated'] = true;
                $this->clients[$clientId]['remoteCandidateTentativeLocked'] = true;
                if ($previousAddress !== $newAddress) {
                    $this->_log_std("[ICE nominated candidate] Client {$clientId}: {$previousAddress} -> {$newAddress}\n");
                }
            }

            $usernamePadding = (4 - (strlen($responseUsername) % 4)) % 4;
            $usernameAttr = pack('nn', 0x0006, strlen($responseUsername))
                . $responseUsername
                . str_repeat("\x00", $usernamePadding);

            $xorPort = $clientPort ^ 0x2112;
            $xorIP = ip2long($clientIP) ^ 0x2112A442;
            $xorAttr = "\x00\x20\x00\x08\x00\x01";
            $xorAttr .= pack('n', $xorPort);
            $xorAttr .= pack('N', $xorIP);

            $attributesBeforeIntegrity = $usernameAttr . $xorAttr;
            $integrityLength = strlen($attributesBeforeIntegrity) + 24;
            $headerForMI = pack('n', 0x0101) . pack('n', $integrityLength) . $magicCookie . $transactionId;
            $hmac = hash_hmac('sha1', $headerForMI . $attributesBeforeIntegrity, $icePwd, true);
            $miAttr = "\x00\x08\x00\x14" . $hmac;

            $attributesBeforeFingerprint = $attributesBeforeIntegrity . $miAttr;
            $responseLength = strlen($attributesBeforeFingerprint) + 8;
            $headerForFP = pack('n', 0x0101) . pack('n', $responseLength) . $magicCookie . $transactionId;
            $crc = crc32($headerForFP . $attributesBeforeFingerprint) ^ 0x5354554E;
            $fpAttr = "\x80\x28\x00\x04" . pack('N', $crc);

            $response = $headerForFP . $attributesBeforeFingerprint . $fpAttr;

            $sent = @stream_socket_sendto($this->udpSocket, $response, 0, $from);

            static $_stunSummary = [], $_stunTransactions = [];
            $now = microtime(true);
            if (!isset($_stunSummary[$clientId])) {
                $_stunSummary[$clientId] = ['requests' => 0, 'responses' => 0, 'failed' => 0, 'lastResponseLen' => 0, 'lastLog' => 0.0, 'lastRequestAt' => 0.0];
            }
            $_stunSummary[$clientId]['requests']++;
            if ($sent === strlen($response)) {
                $_stunSummary[$clientId]['responses']++;
            } else {
                $_stunSummary[$clientId]['failed']++;
            }
            $_stunSummary[$clientId]['lastResponseLen'] = strlen($response);

            $transactionHex = bin2hex($transactionId);
            $transactionKey = $clientId . ':' . $transactionHex;
            $previousTransactionAt = (float)($_stunTransactions[$transactionKey] ?? 0.0);
            $requestIntervalMs = $_stunSummary[$clientId]['lastRequestAt'] > 0.0
                ? (int)(($now - $_stunSummary[$clientId]['lastRequestAt']) * 1000)
                : null;
            $_stunTransactions[$transactionKey] = $now;
            $_stunSummary[$clientId]['lastRequestAt'] = $now;
            if (($this->clients[$clientId]['meta']['role'] ?? '') === 'push') {
                $this->_log_std("[DEBUG ICE consent] client={$clientId} tx={$transactionHex}"
                    . " intervalMs=" . ($requestIntervalMs === null ? '-' : $requestIntervalMs)
                    . " retrans=" . ($previousTransactionAt > 0.0 ? 'yes' : 'no')
                    . " retransAfterMs=" . ($previousTransactionAt > 0.0 ? (int)(($now - $previousTransactionAt) * 1000) : '-')
                    . " sent=" . ($sent === false ? '-1' : $sent) . "/" . strlen($response) . "\n");
            }

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