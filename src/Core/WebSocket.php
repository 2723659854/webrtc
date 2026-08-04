<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose websocket服务
 * @author  yanglong
 * @note 主要提供http+ws服务,信令服务器,作为两个客户端之间的中介或者桥梁
 */
trait WebSocket
{

    /**
     * 启动ws服务器
     * @return void
     * @note 传的是 SDP（会话描述） 和 ICE 候选地址（Candidate）
     */
    private function startWebSocketServer()
    {
        $this->wsServer = @stream_socket_server("tcp://0.0.0.0:" . $this->wsPort, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        if (!$this->wsServer) {
            echo "Failed to start WebSocket server: {$errstr}\n";
            exit(1);
        }
        /** 设置为非阻塞 */
        stream_set_blocking($this->wsServer, false);
        echo"WebSocket signaling server listening on ws://0.0.0.0:" . $this->wsPort . "/\n";
    }

    /**
     * 解析http请求的header
     * @param $raw
     * @return array
     */
    private function parseHttpHeaders($raw)
    {
        $lines = preg_split('/\r\n/', $raw);
        $requestLine = array_shift($lines);
        $headers = [];
        foreach ($lines as $line) {
            if (strpos($line, ':') === false) continue;
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))] = trim($value);
        }
        return ['requestLine' => $requestLine, 'headers' => $headers];
    }

    /**
     * 发送ws文本消息(ws信息编码)
     * @param $socket
     * @param $payload
     * @return bool
     */
    private function sendWebSocketText($socket, $payload)
    {
        if (!is_resource($socket)) return false;

        $frame = '';
        $frame .= chr(0x81);

        /** 这个ws加密规则 */
        $len = strlen($payload);
        if ($len < 126) {
            $frame .= chr($len);
        } elseif ($len < 65536) {
            $frame .= chr(126);
            $frame .= chr(($len >> 8) & 0xFF);
            $frame .= chr($len & 0xFF);
        } else {
            $frame .= chr(127);
            for ($i = 7; $i >= 0; $i--) {
                $frame .= chr(($len >> ($i * 8)) & 0xFF);
            }
        }

        $frame .= $payload;

        return $this->writeAll($socket, $frame);
    }

    /**
     * 真实发送数据给客户端
     * @param $socket
     * @param $data
     * @return bool
     */
    private function writeAll($socket, $data)
    {
        if (!is_resource($socket)) return false;

        $total = strlen($data);
        $sent = 0;

        /** 强制发送完毕才结束 */
        while ($sent < $total) {
            $result = @fwrite($socket, substr($data, $sent));
            if ($result === false) {
                return false;
            }
            $sent += $result;
        }

        /** 立即刷新暂存区 ，立即推送出去 */
        @fflush($socket);
        return true;
    }

    /**
     * ws信息解码
     * @param $data
     * @return array
     */
    private function decodeWebSocketPayload($data)
    {
        if (strlen($data) < 2) return ['complete' => false, 'payload' => '', 'remaining' => $data];
        $byte1 = ord($data[0]);
        $byte2 = ord($data[1]);
        $opcode = $byte1 & 0x0F;
        $masked = ($byte2 & 0x80) !== 0;
        $length = $byte2 & 0x7F;
        $offset = 2;

        if ($opcode === 8) return ['complete' => true, 'opcode' => 'close', 'payload' => '', 'remaining' => ''];

        if ($length === 126) {
            if (strlen($data) < 4) return ['complete' => false, 'payload' => '', 'remaining' => $data];
            $length = unpack('n', substr($data, 2, 2))[1];
            $offset = 4;
        } elseif ($length === 127) {
            if (strlen($data) < 10) return ['complete' => false, 'payload' => '', 'remaining' => $data];
            $length = unpack('J', substr($data, 2, 8))[1];
            $offset = 10;
        }

        $totalLength = $offset + ($masked ? 4 : 0) + $length;
        if (strlen($data) < $totalLength) return ['complete' => false, 'payload' => '', 'remaining' => $data];

        if ($masked) {
            $maskKey = substr($data, $offset, 4);
            $offset += 4;
            $payload = substr($data, $offset, $length);
            $decoded = '';
            for ($i = 0; $i < $length; $i++) {
                $decoded .= chr(ord($payload[$i]) ^ ord($maskKey[$i % 4]));
            }
            return ['complete' => true, 'opcode' => 'text', 'payload' => $decoded, 'remaining' => substr($data, $totalLength)];
        }
        return ['complete' => true, 'opcode' => 'text', 'payload' => substr($data, $offset, $length), 'remaining' => substr($data, $totalLength)];
    }
}