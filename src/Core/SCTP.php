<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose sctp多流可靠传输
 * @author yanglong
 * @note datachannel传输协议
 */
trait SCTP
{

    /**
     * 处理sctp应用消息
     * @param $clientId
     * @param $payload
     * @return void
     */
    private function handleSCTP($clientId, $payload)
    {
        if (strlen($payload) < 12) return;
        /** 整包 hex 只在调试模式构造，生产路径零开销 */
        if ($this->isDev) {
            $this->_log_std("Client {$clientId} SCTP IN (len=" . strlen($payload) . "): " . bin2hex($payload) . "\n");
        }

        $srcPort = (ord($payload[0]) << 8) | ord($payload[1]);
        $dstPort = (ord($payload[2]) << 8) | ord($payload[3]);
        $verifTag = (ord($payload[4]) << 24) | (ord($payload[5]) << 16) | (ord($payload[6]) << 8) | ord($payload[7]);

        /** 如果没有获取到这个客户端的sctp配置 */
        if (!isset($this->clients[$clientId]['sctp'])) {
            $this->clients[$clientId]['sctp'] = [
                'state' => 'INIT_WAIT',
                'peer_port' => $srcPort,
                'my_port' => $dstPort,
                'send_vtag' => 0,
                'my_vtag' => mt_rand(1, 0x7FFFFFFF),
                'peer_initiate_tag' => 0,
                'my_next_tsn' => mt_rand(1, 0x3FFFFFFF),
                'peer_next_tsn' => 1,
                'peer_tsn_seen' => [],
                'stream_to_dc' => [],
                'my_stream_id' => 0,
                'tsn_lastack' => 0,
                'tsn_reorder_queued' => [],
                'peer_rwnd' => 0,
                'my_rwnd' => 4194304,
                /** DataChannel 分片重组 / 限流 / 背压状态 */
                'dc_rx' => [],
                'dc_rx_dropped' => 0,
                'dc_in_rate' => null,
                'dc_in_rate_ts' => 0.0,
                'dc_in_msg' => null,
                'dc_in_msg_ts' => 0.0,
                'dc_out_rate' => null,
                'dc_out_rate_ts' => 0.0,
                'dc_tx_unacked_bytes' => 0,
                'dc_tx_last_send_at' => 0.0,
                'peer_cum_ack' => 0,
                'dc_sack_sent_at' => 0.0,
                'dc_rl_log_at' => 0.0,
            ];
        }
        $s = &$this->clients[$clientId]['sctp'];

        $this->_log_std("Client {$clientId} SCTP common-hdr src=$srcPort dst=$dstPort vtag_rx=$verifTag (state={$s['state']} send_vtag={$s['send_vtag']} my_vtag={$s['my_vtag']} peer_itag={$s['peer_initiate_tag']}) payload_len=" . strlen($payload) . "\n");

        $needVtagValidation = !in_array($s['state'], ['INIT_WAIT', 'OPEN_WAIT'], true);
        if ($needVtagValidation && $s['my_vtag'] !== 0 && $verifTag !== (int)$s['my_vtag']) {
            $this->_log_std("Client {$clientId} SCTP DROP: bad vtag_rx=$verifTag expected={$s['my_vtag']} (state={$s['state']})\n");
            return;
        }

        $offset = 12;
        $replies = [];
        $sackNeeded = false;

        /** sctp拆包 */
        while ($offset + 4 <= strlen($payload)) {
            $chunkType = ord($payload[$offset]);
            $chunkFlags = ord($payload[$offset + 1]);
            $chunkLen = (ord($payload[$offset + 2]) << 8) | ord($payload[$offset + 3]);
            if ($chunkLen < 4) break;
            $chunkPad = ((($chunkLen + 3) >> 2) << 2) - $chunkLen;
            $chunkBody = substr($payload, $offset + 4, $chunkLen - 4);
            $offset += 4 + ($chunkLen - 4) + $chunkPad;

            $this->_log_std("Client {$clientId} SCTP CHUNK: type=$chunkType flags=$chunkFlags len=$chunkLen bodylen=" . strlen($chunkBody) . "\n");
            switch ($chunkType) {
                /** sctp初始化 */
                case 1: // INIT (browser → server)
                    $initAck = $this->handleSCTP_INIT($clientId, $s, $chunkBody);
                    if ($initAck !== false) $replies[] = $initAck;
                    break;

                /** cookie-echo 浏览器并不会处理cookie，而是原样返回给服务器 */
                case 10: // COOKIE-ECHO (after INIT-ACK, browser sends back the cookie we gave)
                    $ack = $this->handleSCTP_COOKIE_ECHO($clientId, $s);
                    if ($ack !== false) $replies[] = $ack;
                    $sackNeeded = true;
                    break;
                /** 处理sctp数据 */
                case 0: // DATA chunk
                    $this->handleSCTP_DATA($clientId, $s, $chunkBody, $chunkFlags);
                    /**
                     * 每个 DATA 包都回 SACK：Chrome 初始拥塞窗口很小（约 10 个 MTU），
                     * 延迟确认会让 100KB 消息在中途卡死并触发重传。
                     * 单个 SACK 只有 28 字节 SCTP（加密后 ~65 字节），成本远低于一次媒体帧。
                     */
                    $sackNeeded = true;
                    break;
                /** 处理浏览器的ack消息 */
                case 3: // SACK (browser acknowledges our DATA) — log and ignore for now
                    $this->handleSCTP_SACK($clientId, $s, $chunkBody);
                    break;
                /** 处理浏览器的心跳 */
                case 4: // HEARTBEAT
                    $hbAck = $this->handleSCTP_HEARTBEAT($clientId, $s, $chunkBody);
                    if ($hbAck !== false) $replies[] = $hbAck;
                    break;
                /** 处理浏览器关闭连接 */
                case 7: // SHUTDOWN
                    $shutAck = $this->handleSCTP_SHUTDOWN($clientId, $s);
                    if ($shutAck !== false) $replies[] = $shutAck;
                    break;
                /** 更新连接状态 */
                case 15: // SHUTDOWN-COMPLETE
                    $s['state'] = 'CLOSED';
                    break;
                /** 更新连接状态 */
                case 6: // ABORT
                    $s['state'] = 'CLOSED';
                    $this->_log_std("Client {$clientId} SCTP ABORT received.\n");
                    break;
                /** 忽略其他类型消息 */
                default:
                    $this->_log_std("Client {$clientId} SCTP chunk type=$chunkType ignored.\n");
                    break;
            }
        }

        /** 回应客户端ack */
        if ($sackNeeded) {
            $sack = $this->buildSCTP_SACK($s);
            if ($sack !== false) {
                /** 把ack放到队列最前面，防止疯狂重发 */
                array_unshift($replies, $sack);
                $s['dc_sack_sent_at'] = microtime(true);
            }
        }

        if (!empty($replies)) {
            /** 将待发送数据打包 */
            $outPacket = $this->joinSCTPChunksIntoPacket($s, $replies);
            if (strlen($outPacket) > 0) {
                /** 使用dtls加密然后发送 */
                $this->sendSCTPOverDTLS($clientId, $outPacket);
            }
        }
    }

    /**
     * gcm加密
     * @param $ivf
     * @param $nonceExplicit
     * @param $mode
     * @return string
     */
    private function buildGcmNonceByMode($ivf, $nonceExplicit, $mode)
    {
        $ivfLen = strlen($ivf);
        switch ($mode) {
            case 'fix_exp':    // RFC 5288 standard: iv_fixed || nonce_explicit → exactly 12
                $nv = $ivf . $nonceExplicit;
                return (strlen($nv) === 12) ? $nv : str_pad(substr($nv, 0, 12), 12, "\0");
            case 'exp_fix':    // reversed: nonce_explicit || iv_fixed
                $nv = $nonceExplicit . $ivf;
                return (strlen($nv) === 12) ? $nv : str_pad(substr($nv, 0, 12), 12, "\0");
            case 'split_iv_2_2':
                if ($ivfLen >= 4) $nv = substr($ivf, 0, 2) . $nonceExplicit . substr($ivf, 2, 2);
                else $nv = $ivf . $nonceExplicit;
                return (strlen($nv) === 12) ? $nv : str_pad(substr($nv, 0, 12), 12, "\0");
            case 'fix_exp_noepoch':  // iv_fixed || nonce_explicit[2..9] (skip epoch bytes)
                $nv = $ivf . substr($nonceExplicit, 2, 8);
                return (strlen($nv) === 12) ? $nv : str_pad(substr($nv, 0, 12), 12, "\0");
            case 'xor8pad':  // only used when ivfLen=8: (ivf ^ nonceExplicit) pad right → 12
                if ($ivfLen === 8) return str_pad($ivf ^ $nonceExplicit, 12, "\0", STR_PAD_RIGHT);
                return str_pad(substr($ivf . $nonceExplicit, 0, 12), 12, "\0");
            case 'xor8padL':
                if ($ivfLen === 8) return str_pad($ivf ^ $nonceExplicit, 12, "\0", STR_PAD_LEFT);
                return str_pad(substr($ivf . $nonceExplicit, 0, 12), 12, "\0");
            case 'fix_xor_exp_plus_fix':  // only for ivfLen=4
                if ($ivfLen === 4) return $ivf . ($nonceExplicit ^ str_repeat($ivf, 2));
                return str_pad(substr($ivf . $nonceExplicit, 0, 12), 12, "\0");
            default:  // RFC 5288
                $nv = $ivf . $nonceExplicit;
                return (strlen($nv) === 12) ? $nv : str_pad(substr($nv, 0, 12), 12, "\0");
        }
    }

    /**
     * 发送dtls消息
     * Encrypt + send SCTP packet as DTLS Application Data (type=23).
     */
    private function sendSCTPOverDTLS($clientId, $sctpPacket)
    {
        /** 没有完成握手，不可发送消息 */
        if (!isset($this->clients[$clientId]['encryption'])) {
            $this->_log_std("Client {$clientId} Cannot send SCTP: no DTLS encryption material.\n");
            return;
        }
        $enc = $this->clients[$clientId]['encryption'];
        if (!isset($this->clients[$clientId]['dtlsEpoch'])) {
            $this->clients[$clientId]['dtlsEpoch'] = 1;
        }
        if (!isset($this->clients[$clientId]['dtlsSeq'])) {
            $this->clients[$clientId]['dtlsSeq'] = 1;
        }

        $epoch = (int)$this->clients[$clientId]['dtlsEpoch'];
        $seq = (int)$this->clients[$clientId]['dtlsSeq'];
        $cipherAlgo = $enc['cipherAlgo'];
        $ptLen = strlen($sctpPacket);

        $key = $enc['serverWriteKey'];
        $ivFix = $enc['serverWriteIV'];
        if (!is_string($key) || strlen($key) !== 16 || !is_string($ivFix) || strlen($ivFix) < 4) {
            $this->_log_std("Client {$clientId} Cannot send SCTP: serverWriteKey/IV invalid\n");
            return;
        }

        $nonceMode = !empty($enc['nonceMode']) ? $enc['nonceMode'] : 'fix_exp';
        $aadVersion = !empty($enc['aadVersion']) ? $enc['aadVersion'] : "\xFE\xFD";

        $epochBE = pack('n', $epoch);
        $seqBytes = '';
        for ($i = 5; $i >= 0; $i--) $seqBytes .= chr(($seq >> ($i * 8)) & 0xFF);
        $headerES = $epochBE . $seqBytes;
        $nonceExplicit = $headerES;
        $fragmentNe = $nonceExplicit;

        $nonce = $this->buildGcmNonceByMode($ivFix, $nonceExplicit, $nonceMode);
        if (!is_string($nonce) || strlen($nonce) !== 12) {
            $nonce = str_pad(substr($ivFix . $nonceExplicit, 0, 12), 12, "\0");
        }
        $ad = $headerES . chr(0x17) . $aadVersion . pack('n', $ptLen);

        $tag = '';
        while (openssl_error_string() !== false) {
        }
        $ciphertext = openssl_encrypt($sctpPacket, $cipherAlgo, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
        if ($ciphertext === false || strlen($tag) !== 16) {
            $this->_log_std("Client {$clientId} sendSCTPOverDTLS: openssl_encrypt FAILED\n");
            return;
        }
        $fragment = $fragmentNe . $ciphertext . $tag;
        $record = chr(0x17) . "\xFE\xFD" . $epochBE . $seqBytes . pack('n', strlen($fragment)) . $fragment;

        $svPass = false;
        /** 只有调试模式才自检 */
        if ($this->isDev){
            try {
                $svTag = substr($fragment, -16);
                $svCt = substr($fragment, strlen($fragmentNe), -16);
                $svNe = substr($fragment, 0, 8);
                $svNonce = $this->buildGcmNonceByMode($ivFix, $svNe, $nonceMode);
                if (!is_string($svNonce) || strlen($svNonce) !== 12) {
                    $svNonce = str_pad(substr($ivFix . $svNe, 0, 12), 12, "\0");
                }
                $svAAD = $headerES . chr(0x17) . $aadVersion . pack('n', $ptLen);
                $svPt = openssl_decrypt($svCt, $cipherAlgo, $key, OPENSSL_RAW_DATA, $svNonce, $svTag, $svAAD);
                if (is_string($svPt) && hash_equals($svPt, $sctpPacket)) $svPass = true;
            } catch (\Throwable $e) {
                $svPass = false;
            }
        }
        while (openssl_error_string() !== false) {
        }

        $this->sendUDP($clientId, $record);
        $this->clients[$clientId]['dtlsSeq'] = $seq + 1;

        /** 整包明文 / 密钥 / nonce / aad / tag 的 hex 只在调试模式构造 */
        if ($this->isDev) {
            $this->_log_std("Client {$clientId} sendSCTPOverDTLS: 1 RECORD ONLY keyDir=sRFC nonceMode=$nonceMode aadVer=" . bin2hex($aadVersion) .
                " epoch=$epoch seq=$seq recLen=" . strlen($record) . " pt=$ptLen" . ($svPass ? ' ✓SELFT' : ' ⚠FAIL_SELFTEST') . "\n");
            $this->_log_std("  plaintext=" . bin2hex($sctpPacket) . "\n");
            $this->_log_std("  key=" . bin2hex($key) . " iv(" . strlen($ivFix) . ")=" . bin2hex($ivFix) . " nonce(12)=" . bin2hex($nonce) . "\n");
            $this->_log_std("  aad(13)=" . bin2hex($ad) . " tag=" . bin2hex($tag) . "\n");
        }
    }

    /**
     * 将stcp分块的数据写入数据包
     * @param $s
     * @param $chunks
     * @return string
     */
    private function joinSCTPChunksIntoPacket(&$s, $chunks)
    {
        $useZeroCrc = !empty($s['zero_checksum_ok']);

        $hdrNoChk = pack('nnN', (int)$s['my_port'], (int)$s['peer_port'], (int)$s['send_vtag']);
        $body = '';
        foreach ($chunks as $c) {
            $body .= $c;
        }

        if ($useZeroCrc) {
            $packet = $hdrNoChk . "\x00\x00\x00\x00" . $body;
        } else {
            $forCrc = $hdrNoChk . "\x00\x00\x00\x00" . $body;
            $crc = $this->crc32c_fallback($forCrc);
            $packet = $hdrNoChk . pack('V', $crc) . $body;
        }
        return $packet;
    }

    /**
     * 加密
     * Pure-PHP CRC-32c (Castagnoli) — RFC 3309 SCTP checksum.
     *   poly   = 0x1EDC6F41 (reflected form)
     *   init   = 0xFFFFFFFF
     *   refin  = true  (reflect input bytes before processing)
     *   refout = true  (reflect final CRC before xor-out)
     *   xorout = 0xFFFFFFFF
     * This is identical to iSCSI, Btrfs, ext4, SCTP CRC-32c.
     */
    private function crc32c_fallback($data)
    {
        static $table = null;
        if ($table === null) {
            $table = [];
            for ($i = 0; $i < 256; $i++) {
                $crc = $i;
                for ($k = 0; $k < 8; $k++) {
                    if ($crc & 1) {
                        $crc = (($crc >> 1) & 0x7FFFFFFF) ^ 0x82F63B78;
                    } else {
                        $crc = ($crc >> 1) & 0x7FFFFFFF;
                    }
                }
                $table[$i] = $crc;
            }
        }
        $crc = 0xFFFFFFFF;
        $n = strlen($data);
        for ($i = 0; $i < $n; $i++) {
            $crc = (($crc >> 8) & 0x00FFFFFF) ^ $table[($crc ^ ord($data[$i])) & 0xFF];
        }
        return ($crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
    }


    /**
     * 处理sctp协议初始化
     * @param $clientId
     * @param $s
     * @param $body
     * @return false|string
     */
    private function handleSCTP_INIT($clientId, &$s, $body)
    {
        if (strlen($body) < 16) return false;
        $initiateTag = (ord($body[0]) << 24) | (ord($body[1]) << 16) | (ord($body[2]) << 8) | ord($body[3]);
        $aRwnd = (ord($body[4]) << 24) | (ord($body[5]) << 16) | (ord($body[6]) << 8) | ord($body[7]);
        $outStreams = (ord($body[8]) << 8) | ord($body[9]);
        $inStreams = (ord($body[10]) << 8) | ord($body[11]);
        $initialTSN = (ord($body[12]) << 24) | (ord($body[13]) << 16) | (ord($body[14]) << 8) | ord($body[15]);

        $s['peer_initiate_tag'] = $initiateTag;
        $s['peer_next_tsn'] = $initialTSN;
        $s['peer_rwnd'] = $aRwnd;
        $s['peer_out_streams'] = $outStreams;
        $s['peer_in_streams'] = $inStreams;
        $s['my_out_streams'] = $inStreams;
        $s['my_in_streams'] = 65535;
        $s['send_vtag'] = $initiateTag;
        $s['state'] = 'OPEN_WAIT';

        $pp = 16;
        $saw_fwdtsn_init = false;
        $saw_zero_chksum_init = false;
        $rcv_edmid_from_init = 0;
        $echo_supported_chunks = '';
        $initParamIdx = 0;
        while ($pp + 4 <= strlen($body)) {
            $ptype = (ord($body[$pp]) << 8) | ord($body[$pp + 1]);
            $plen = (ord($body[$pp + 2]) << 8) | ord($body[$pp + 3]);
            if ($plen < 4) break;
            if ($pp + $plen > strlen($body)) break;
            $pbody = substr($body, $pp + 4, $plen - 4);
            $this->_log_std("  INIT param[$initParamIdx]: type=0x" . sprintf('%04x', $ptype) . " len=$plen\n");
            switch ($ptype) {
                case 0xC000:
                    $saw_fwdtsn_init = true;
                    break;
                case 0x8001:
                    if (strlen($pbody) >= 4) {
                        $rcv_edmid_from_init = unpack('N', substr($pbody, 0, 4))[1];
                        $saw_zero_chksum_init = ($rcv_edmid_from_init !== 0);
                        $this->_log_std("    => ZCA edmid=0x" . sprintf('%08x', $rcv_edmid_from_init) . "\n");
                    }
                    break;
                case 0x8008:
                    $echo_supported_chunks = $pbody;
                    break;
            }
            $pad = ((4 - ($plen % 4)) % 4);
            $pp += $plen + $pad;
            $initParamIdx++;
        }

        $INP_RCV_EDMID = 0x00000033;
        $INP_PRSCTP_SUPPORTED = true;
        $INP_ECN_SUPPORTED = false;
        $INP_ALI_PROVIDED = false;
        $INP_AUTH_SUPPORTED = false;
        $INP_ASCONF_SUPPORTED = false;
        $INP_RECONFIG_SUPPORTED = false;
        $INP_IDATA_SUPPORTED = false;
        $INP_NRSACK_SUPPORTED = false;
        $INP_PKTDROP_SUPPORTED = false;

        $use_zero_crc_initack = ($INP_RCV_EDMID !== 0) && ($INP_RCV_EDMID === $rcv_edmid_from_init);
        $s['zero_checksum_ok'] = $use_zero_crc_initack;

        $this->_log_std("Client {$clientId} SCTP INIT: peer_it=$initiateTag TSN=$initialTSN os=$outStreams mis=$inStreams rwnd=$aRwnd\n");
        $this->_log_std("  ZCA: inp_rcv_edmid=0x" . sprintf('%08x', $INP_RCV_EDMID) . " init_edmid=0x" . sprintf('%08x', $rcv_edmid_from_init) . " → use_zero_crc_initack=" . ($use_zero_crc_initack ? 'YES' : 'NO') . "\n");

        $initAckBody = pack('NNnnN',
            (int)$s['my_vtag'],
            max((int)$s['my_rwnd'], 65535),
            (int)$s['my_out_streams'],
            (int)$s['my_in_streams'],
            (int)$s['my_next_tsn']
        );

        $chunk_len = 20;
        $padding_len = 0;
        $paramsBlob = '';

        if ($INP_PRSCTP_SUPPORTED) {
            if ($padding_len > 0) {
                $paramsBlob .= str_repeat("\x00", $padding_len);
                $chunk_len += $padding_len;
                $padding_len = 0;
            }
            $parameter_len = 4;
            $paramsBlob .= pack('nn', 0xC000, $parameter_len);
            $chunk_len += $parameter_len;
        }

        if ($use_zero_crc_initack) {
            if ($padding_len > 0) {
                $paramsBlob .= str_repeat("\x00", $padding_len);
                $chunk_len += $padding_len;
                $padding_len = 0;
            }
            $parameter_len = 8;
            $paramsBlob .= pack('nnN', 0x8001, $parameter_len, $INP_RCV_EDMID);
            $chunk_len += $parameter_len;
        }

        $num_ext = 0;
        $ext_list = '';
        if ($INP_PRSCTP_SUPPORTED) {
            $ext_list .= "\xC0";
            $num_ext++;
        }
        if ($num_ext > 0) {
            if ($padding_len > 0) {
                $paramsBlob .= str_repeat("\x00", $padding_len);
                $chunk_len += $padding_len;
                $padding_len = 0;
            }
            $parameter_len = 4 + $num_ext;
            $paramsBlob .= pack('nn', 0x8008, $parameter_len) . $ext_list;

            $padding_len = ((($parameter_len + 3) & ~3) - $parameter_len);
            $chunk_len += $parameter_len;
        }

        $INP_SUPPORT_V4 = true;
        $INP_SUPPORT_V6 = false;
        $localIP = $this->getLocalIP();
        $ipv4Long = ip2long($localIP);
        if (!$ipv4Long || ($ipv4Long === ip2long('127.0.0.1'))) {
            $useAddr = '127.0.0.1';
        } else {
            $useAddr = $localIP;
        }
        $addr_val = ip2long($useAddr);

        if ($INP_SUPPORT_V4 || $INP_SUPPORT_V6) {

            $sup_types = '';
            if ($INP_SUPPORT_V4) $sup_types .= pack('n', 0x0005);
            if ($INP_SUPPORT_V6) $sup_types .= pack('n', 0x0006);
            $sup_count = strlen($sup_types) / 2;
            if ($sup_count > 0) {
                if ($padding_len > 0) {
                    $paramsBlob .= str_repeat("\x00", $padding_len);
                    $chunk_len += $padding_len;
                    $padding_len = 0;
                }
                $parameter_len = 4 + (2 * $sup_count);
                $paramsBlob .= pack('nn', 0x000C, $parameter_len) . $sup_types;
                $padding_len = ((($parameter_len + 3) & ~3) - $parameter_len);
                $chunk_len += $parameter_len;
            }

            if ($INP_SUPPORT_V4) {
                if ($padding_len > 0) {
                    $paramsBlob .= str_repeat("\x00", $padding_len);
                    $chunk_len += $padding_len;
                    $padding_len = 0;
                }
                $parameter_len = 8;
                $paramsBlob .= pack('nnN', 0x0005, $parameter_len, (int)$addr_val);

                $padding_len = 0;
                $chunk_len += $parameter_len;
            }
        }

        if ($padding_len > 0) {
            $paramsBlob .= str_repeat("\x00", $padding_len);
            $chunk_len += $padding_len;
            $padding_len = 0;
        }

        $mt = microtime(true);
        $tv_sec = (int)$mt;
        $tv_usec = (int)(($mt - $tv_sec) * 1000000);
        $INP_COOKIE_LIFE_SEC = 60;
        $_s = '';
        $_s .= pack('a16', "PHP-SCTP-v1\x00\x00\x00\x00\x00");
        $_s .= pack('NN', $tv_sec, $tv_usec);
        $_s .= pack('N', (int)($INP_COOKIE_LIFE_SEC * 1000));
        $_s .= pack('NN', 0, 0);
        $_s .= pack('N', (int)$initiateTag);
        $_s .= pack('N', (int)$s['my_vtag']);
        $peerIPLong = 0;
        if (isset($s['udp_peer_ip'])) {
            $l = ip2long($s['udp_peer_ip']);
            if ($l !== false) $peerIPLong = $l;
        }
        $_s .= pack('NNNN', $peerIPLong, 0, 0, 0);
        $_s .= pack('N', 5);
        $_s .= pack('NNNN', $addr_val, 0, 0, 0);
        $_s .= pack('N', 5);
        $_s .= pack('N', 0);
        $_s .= pack('nn', (int)$s['peer_port'], (int)$s['my_port']);
        $_s .= chr(1);
        $_s .= chr(0);
        $_s .= chr(1);
        $_s .= chr(0);
        $_s .= chr(0);
        $_s .= chr(0);
        $_s .= chr(($addr_val === ip2long('127.0.0.1')) ? 1 : 0);
        $_s .= chr($INP_RCV_EDMID & 0xFF);
        $_s .= "\x00\x00\x00\x00";
        if (strlen($_s) !== 104) {
            $this->_log_std("  !!! Cookie sizeof BUG: strlen(_s)=" . strlen($_s) . " != 104, abort\n");
        }
        $_s .= pack('NNNN', (int)$clientId, $tv_sec, 0, 0);
        $cookie_raw = $_s;
        $cookie_raw_len = strlen($cookie_raw);
        $pad_content = ((4 - ($cookie_raw_len % 4)) % 4);
        if ($pad_content > 0) $cookie_raw .= str_repeat("\x00", $pad_content);

        if ($padding_len > 0) {
            $paramsBlob .= str_repeat("\x00", $padding_len);
            $chunk_len += $padding_len;
            $padding_len = 0;
        }
        $parameter_len = 4 + strlen($cookie_raw);
        $paramsBlob .= pack('nn', 0x0007, $parameter_len) . $cookie_raw;
        $final_cookie_padding = ((($parameter_len + 3) & ~3) - $parameter_len);
        $chunk_len += $parameter_len;
        $chunk_len_excl_final_pad = $chunk_len;
        $final_padding_bytes = $final_cookie_padding;

        $chunk_body = $initAckBody . $paramsBlob;
        $chunk_header = "\x02\x00" . pack('n', $chunk_len_excl_final_pad);
        $full_chunk = $chunk_header . $chunk_body;
        $wire_pad = ((4 - (strlen($full_chunk) % 4)) % 4);
        if ($wire_pad > 0) $full_chunk .= str_repeat("\x00", $wire_pad);

        $this->_log_std("Client {$clientId} INIT-ACK: chunk_len(on-wire header)=" . $chunk_len_excl_final_pad . " strlen(body_after_header)=" . strlen($chunk_body) . " wire_pad=" . $wire_pad . " params_bytes=" . strlen($paramsBlob) . "\n");
        return $full_chunk;
    }

    /**
     * SCTP_COOKIE_ECHO
     * @param $clientId
     * @param $s
     * @return string
     */
    private function handleSCTP_COOKIE_ECHO($clientId, &$s)
    {

        $s['send_vtag'] = (int)$s['peer_initiate_tag'];
        $s['state'] = 'ESTABLISHED';
        $this->_log_std("Client {$clientId} SCTP COOKIE-ECHO received -> ESTABLISHED (send_vtag upgraded to peer_initiate_tag={$s['send_vtag']}, my_vtag={$s['my_vtag']}, my_next_tsn={$s['my_next_tsn']}, peer_first_tsn={$s['peer_next_tsn']})\n");
        return "\x0B\x00\x00\x04";
    }

    /**
     * SCTP_HEARTBEAT
     * @param $clientId
     * @param $s
     * @param $body
     * @return string
     */
    private function handleSCTP_HEARTBEAT($clientId, &$s, $body)
    {
        $paramType = (ord($body[0]) << 8) | ord($body[1]);
        $paramLen = (ord($body[2]) << 8) | ord($body[3]);
        $hbInfo = substr($body, 0, $paramLen);
        $hbAckBody = $hbInfo;
        $chunkLen = 4 + strlen($hbAckBody);
        $chunk = "\x05\x00" . pack('n', $chunkLen) . $hbAckBody;
        return $this->padTo4($chunk);
    }

    /**
     * SCTP_SHUTDOWN
     * @param $clientId
     * @param $s
     * @return string
     */
    private function handleSCTP_SHUTDOWN($clientId, &$s)
    {
        $s['state'] = 'SHUTDOWN_SENT';
        return "\x08\x00\x00\x04";
    }

    /**
     * SCTP_SACK
     * @param $clientId
     * @param $s
     * @param $body
     * @return void
     */
    private function handleSCTP_SACK($clientId, &$s, $body)
    {
        /** SACK 固定体长 12 字节：cumTSN(4) + rwnd(4) + numGap(2) + numDup(2) */
        if (strlen($body) < 12) return;
        $cumTSN = (ord($body[0]) << 24) | (ord($body[1]) << 16) | (ord($body[2]) << 8) | ord($body[3]);
        $advRwnd = (ord($body[4]) << 24) | (ord($body[5]) << 16) | (ord($body[6]) << 8) | ord($body[7]);
        $gaps = (ord($body[8]) << 8) | ord($body[9]);
        $dups = (ord($body[10]) << 8) | ord($body[11]);
        $cumTSN++;
        $this->_log_std("Client {$clientId} SCTP SACK: cum_ack=" . ($cumTSN - 1) . " next_expected=$cumTSN rwnd=$advRwnd gaps=$gaps dups=$dups\n");
        $s['peer_rwnd'] = $advRwnd;
        /** 累积确认前进 => 之前发出的数据都已被对端收下，释放背压计数 */
        if ($cumTSN > (int)($s['peer_cum_ack'] ?? 0)) {
            $s['peer_cum_ack'] = $cumTSN;
            $s['dc_tx_unacked_bytes'] = 0;
        }
    }

    /**
     * SCTP_SACK
     * @param $s
     * @return string
     */
    private function buildSCTP_SACK(&$s)
    {
        $cumTSN = $s['peer_next_tsn'] - 1;
        $advRwnd = (int)$s['my_rwnd'];
        $gapsBlocks = '';
        $dupTSNs = '';
        $body = pack('NNnn', $cumTSN, $advRwnd, 0, 0) . $gapsBlocks . $dupTSNs;
        $chunkLen = 4 + strlen($body);
        return "\x03\x00" . pack('n', $chunkLen) . $body;
    }

    /**
     * SCTP_DATA
     * 按 B/E 标志重组分片；一条大消息只在完整收齐后投递一次。
     * @return bool true = 本条消息已完成（或已判定丢弃），需要回 SACK
     */
    private function handleSCTP_DATA($clientId, &$s, $body, $chunkFlags)
    {
        if (strlen($body) < 12) return false;
        $tsn = (ord($body[0]) << 24) | (ord($body[1]) << 16) | (ord($body[2]) << 8) | ord($body[3]);
        $sid = (ord($body[4]) << 8) | ord($body[5]);
        $ssn = (ord($body[6]) << 8) | ord($body[7]);
        $ppid = (ord($body[8]) << 24) | (ord($body[9]) << 16) | (ord($body[10]) << 8) | ord($body[11]);
        $userData = substr($body, 12);

        $this->_log_std("Client {$clientId} SCTP DATA: tsn=$tsn sid=$sid ssn=$ssn ppid=$ppid flags=$chunkFlags len=" . strlen($userData) . "\n");

        $expected = $s['peer_next_tsn'];
        if ($tsn === $expected) {
            $s['peer_next_tsn']++;
        } elseif ($this->tsnGreater($tsn, $expected)) {
            $s['peer_next_tsn'] = $tsn + 1;
        } else {
            $this->_log_std("Client {$clientId} SCTP DATA dup tsn=$tsn (expected=$expected); skip delivery.\n");
            return false;
        }

        $isBegin = ($chunkFlags & 0x02) !== 0;
        $isEnd   = ($chunkFlags & 0x01) !== 0;

        /** 清理超时的半包，避免异常客户端长期占用内存 */
        $this->_dcPurgeStaleReassembly($s);

        /** 完整单包消息（绝大多数聊天消息走这里） */
        if ($isBegin && $isEnd) {
            $this->_dcDispatchMessage($clientId, $s, $sid, $ppid, $userData);
            return true;
        }

        /** 分片起点 */
        if ($isBegin) {
            if (strlen($userData) > (int)$this->dcMaxMessageBytes) {
                $this->_dcLogSampled($s, "Client {$clientId} DC DROP sid=$sid reason=single_fragment_too_large len=" . strlen($userData) . "\n");
                return true;
            }
            $s['dc_rx'][$sid] = [
                'data' => $userData,
                'ppid' => $ppid,
                'ssn'  => $ssn,
                'ts'   => microtime(true),
            ];
            return false;
        }

        /** 中间片 / 结束片：必须有匹配的起点 */
        if (!isset($s['dc_rx'][$sid]) || (int)$s['dc_rx'][$sid]['ssn'] !== (int)$ssn) {
            $s['dc_rx_dropped'] = (int)($s['dc_rx_dropped'] ?? 0) + 1;
            $this->_dcLogSampled($s, "Client {$clientId} DC DROP sid=$sid ssn=$ssn reason=orphan_fragment\n");
            return $isEnd;
        }

        if (strlen($s['dc_rx'][$sid]['data']) + strlen($userData) > (int)$this->dcMaxMessageBytes) {
            unset($s['dc_rx'][$sid]);
            $s['dc_rx_dropped'] = (int)($s['dc_rx_dropped'] ?? 0) + 1;
            $this->_dcLogSampled($s, "Client {$clientId} DC DROP sid=$sid reason=message_too_large\n");
            return true;
        }

        $s['dc_rx'][$sid]['data'] .= $userData;
        if (!$isEnd) return false;

        $message = $s['dc_rx'][$sid]['data'];
        $messagePpid = (int)$s['dc_rx'][$sid]['ppid'];
        unset($s['dc_rx'][$sid]);

        $this->_dcDispatchMessage($clientId, $s, $sid, $messagePpid, $message);
        return true;
    }

    /**
     * 将一条完整 DataChannel 消息分发给业务回调（含限流）
     */
    private function _dcDispatchMessage($clientId, &$s, $sid, $ppid, $payload)
    {
        $len = strlen($payload);
        if ($len > (int)$this->dcMaxMessageBytes) {
            $s['dc_rx_dropped'] = (int)($s['dc_rx_dropped'] ?? 0) + 1;
            $this->_dcLogSampled($s, "Client {$clientId} DC DROP sid=$sid reason=message_too_large len=$len\n");
            return;
        }

        /** 应用层限流：字节令牌桶 + 条数令牌桶 */
        if (!$this->_dcBucketTake($s, 'dc_in_rate', (float)$this->dcInMaxBytesPerSec, max($len, (int)$this->dcInMaxBytesPerSec), $len)) {
            $s['dc_rx_dropped'] = (int)($s['dc_rx_dropped'] ?? 0) + 1;
            $this->_dcLogSampled($s, "Client {$clientId} DC DROP sid=$sid reason=in_rate_bytes len=$len\n");
            return;
        }
        if (!$this->_dcBucketTake($s, 'dc_in_msg', (float)$this->dcInMaxMessagesPerSec, max(1.0, (float)$this->dcInMaxMessagesPerSec), 1)) {
            $s['dc_rx_dropped'] = (int)($s['dc_rx_dropped'] ?? 0) + 1;
            $this->_dcLogSampled($s, "Client {$clientId} DC DROP sid=$sid reason=in_rate_msgs\n");
            return;
        }

        switch ($ppid) {
            case 50: // WebRTC DCEP
                $this->handleDCEP($clientId, $s, $sid, $payload);
                break;
            case 51: // WebRTC String (UTF-8)
            case 56: // WebRTC String partial reliable
                $this->deliverDataChannelMessage($clientId, $sid, $payload, false);
                break;
            case 52: // Deprecated: string with empty "channel" framing
                $this->deliverDataChannelMessage($clientId, $sid, substr($payload, 2), false);
                break;
            case 53: // binary
            case 57: // binary PR
                $this->deliverDataChannelMessage($clientId, $sid, $payload, true);
                break;
            default:
                $this->_log_std("Client {$clientId} SCTP DATA unknown PPID=$ppid; skip.\n");
                break;
        }
    }

    /**
     * 清理超时未收齐的重组缓冲
     */
    private function _dcPurgeStaleReassembly(&$s)
    {
        if (empty($s['dc_rx'])) return;
        $timeout = (float)$this->dcReassemblyTimeoutSec;
        if ($timeout <= 0.0) $timeout = 10.0;
        $now = microtime(true);
        foreach ($s['dc_rx'] as $sid => $buf) {
            if (($now - (float)($buf['ts'] ?? 0.0)) > $timeout) {
                unset($s['dc_rx'][$sid]);
                $s['dc_rx_dropped'] = (int)($s['dc_rx_dropped'] ?? 0) + 1;
            }
        }
    }

    /**
     * 通用令牌桶（速率<=0 表示不限制）
     */
    private function _dcBucketTake(&$s, string $key, float $rate, float $burst, float $cost): bool
    {
        if ($rate <= 0.0) return true;
        if ($burst < $cost) $burst = $cost;
        $tk = $key;
        $ts = $key . '_ts';
        $now = microtime(true);
        if (!isset($s[$tk]) || $s[$tk] === null) {
            $s[$tk] = $burst;
            $s[$ts] = $now;
        }
        $elapsed = $now - (float)$s[$ts];
        if ($elapsed > 0.0) {
            $s[$tk] = min($burst, (float)$s[$tk] + $elapsed * $rate);
            $s[$ts] = $now;
        }
        if ((float)$s[$tk] + 1e-9 < $cost) return false;
        $s[$tk] = (float)$s[$tk] - $cost;
        return true;
    }

    /**
     * 限流/背压日志采样：每个客户端最多 1 条/秒，避免日志本身成为负担
     */
    private function _dcLogSampled(&$s, string $msg): void
    {
        $now = microtime(true);
        if (($now - (float)($s['dc_rl_log_at'] ?? 0.0)) < 1.0) return;
        $s['dc_rl_log_at'] = $now;
        $this->_log_std($msg);
    }

    /**
     * SCTP比较tsn传输序号
     * @param $a
     * @param $b
     * @return bool
     * tsnGreater 是你的 SCTP 协议栈的 “时钟指针校准器”。它确保即使序列号绕回零，你的服务器也能精准识别出哪个 SCTP 数据包是最新到达的，从而正确重组 DataChannel 的消息流，避免乱序和丢包。
     */
    private function tsnGreater($a, $b)
    {
        $diff = ($a - $b) & 0xFFFFFFFF;
        return $diff > 0 && $diff < 0x80000000;
    }

    /**
     * 使用sctp协议发送数据
     * 按 MTU 分片，每个 DATA chunk 的 16 位长度字段都保证 < 65536；
     * 同时做消息大小 / 速率限制与最小背压。
     * @param $clientId
     * @param $sid
     * @param $userData
     * @param $ppid
     * @return bool true=已全部发出；false=被大小/限流/背压拦截
     */
    private function sendDataOverSCTP($clientId, $sid, $userData, $ppid)
    {
        if (!isset($this->clients[$clientId]['sctp'])) return false;
        $s = &$this->clients[$clientId]['sctp'];

        $len = strlen($userData);
        $maxMsg = (int)$this->dcMaxMessageBytes;
        if ($maxMsg > 0 && $len > $maxMsg) {
            $this->_dcLogSampled($s, "Client {$clientId} DC SEND DROP reason=message_too_large len=$len\n");
            return false;
        }

        /** 最小背压：未确认字节超过上限时丢弃新消息（无出站队列，不累积内存） */
        $now = microtime(true);
        $lastSendAt = (float)($s['dc_tx_last_send_at'] ?? 0.0);
        if ($lastSendAt > 0.0 && ($now - $lastSendAt) > 5.0) {
            $s['dc_tx_unacked_bytes'] = 0;
        }
        $pending = (int)($s['dc_tx_unacked_bytes'] ?? 0);
        $cap = (int)$this->dcOutMaxBufferedBytes;
        if ($cap > 0 && $pending > $cap) {
            $this->_dcLogSampled($s, "Client {$clientId} DC SEND DROP reason=tx_backpressure pending=$pending cap=$cap\n");
            return false;
        }

        if (!$this->_dcBucketTake($s, 'dc_out_rate', (float)$this->dcOutMaxBytesPerSec, max($len, (int)$this->dcOutMaxBytesPerSec), $len)) {
            $this->_dcLogSampled($s, "Client {$clientId} DC SEND DROP reason=out_rate_bytes len=$len\n");
            return false;
        }

        $fragBytes = (int)$this->sctpMaxFragmentBytes;
        if ($fragBytes < 256) $fragBytes = 256;
        if ($fragBytes > 60000) $fragBytes = 60000;

        if (!isset($s['my_stream_ssn'][$sid])) $s['my_stream_ssn'][$sid] = 0;
        $ssn = (int)$s['my_stream_ssn'][$sid];
        $s['my_stream_ssn'][$sid] = ($ssn + 1) & 0xFFFF;

        $sack = $this->buildSCTP_SACK($s);
        $sackChunk = ($sack !== false) ? $this->padTo4($sack) : null;

        $offset = 0;
        $first = true;
        do {
            $piece = substr($userData, $offset, $fragBytes);
            $pieceLen = strlen($piece);
            $offset += $pieceLen;
            $isEnd = ($offset >= $len);
            $flags = ($first ? 0x02 : 0x00) | ($isEnd ? 0x01 : 0x00);

            $tsn = (int)$s['my_next_tsn'];
            $s['my_next_tsn'] = ($tsn + 1) & 0xFFFFFFFF;

            $body = pack('NnnN', $tsn, $sid, $ssn, $ppid) . $piece;
            $chunkLen = 4 + strlen($body);
            if ($chunkLen > 65535) {
                /** 理论上不会发生（fragBytes 已封顶 60000），保留保险 */
                $this->_log_std("Client {$clientId} DC SEND ABORT reason=chunk_len_overflow len=$chunkLen\n");
                return false;
            }
            $chunk = $this->padTo4("\x00" . chr($flags) . pack('n', $chunkLen) . $body);

            $chunks = [];
            /** SACK 只随第一个分片发一次，避免每个分片都带一遍 */
            if ($first && $sackChunk !== null) $chunks[] = $sackChunk;
            $chunks[] = $chunk;

            $packet = $this->joinSCTPChunksIntoPacket($s, $chunks);
            if (strlen($packet) === 0) return false;
            if ($this->isDev) {
                $this->_log_std("Client {$clientId} SCTP SEND DATA: tsn=$tsn sid=$sid ssn=$ssn ppid=$ppid flags=$flags len=$pieceLen totallen=" . strlen($packet) . "\n");
            }
            $this->sendSCTPOverDTLS($clientId, $packet);
            $first = false;
        } while ($offset < $len);

        $s['dc_tx_unacked_bytes'] = $pending + $len;
        $s['dc_tx_last_send_at'] = microtime(true);
        return true;
    }

    /**
     * 填充
     * @param $data
     * @return string
     */
    private function padTo4($data)
    {
        $len = strlen($data);
        $pad = (4 - ($len & 3)) & 3;
        return $data . str_repeat("\x00", $pad);
    }

    /**
     * 逻辑通道建立握手协议（DCEP协议，属于应用层协议）处理器
     * @param $clientId
     * @param $s
     * @param $sid
     * @param $userData
     * @return void
     */
    private function handleDCEP($clientId, &$s, $sid, $userData)
    {
        if (strlen($userData) < 1) return;
        $msgType = ord($userData[0]);
        if ($msgType === 0x03) {
            if (strlen($userData) < 13) return;
            $channelType = ord($userData[1]);
            $priority = ord($userData[2]);
            $reliability = (ord($userData[5]) << 24) | (ord($userData[6]) << 16) | (ord($userData[7]) << 8) | ord($userData[8]);
            $labelLen = (ord($userData[9]) << 8) | ord($userData[10]);
            $protocolLen = (ord($userData[11]) << 8) | ord($userData[12]);
            $label = $labelLen > 0 ? substr($userData, 13, $labelLen) : '';
            $protocol = $protocolLen > 0 ? substr($userData, 13 + $labelLen, $protocolLen) : '';
            $s['stream_to_dc'][$sid] = [
                'label' => $label,
                'protocol' => $protocol,
                'channel_type' => $channelType,
                'priority' => $priority,
                'reliability' => $reliability,
                'opened' => true,
            ];
            $this->_log_std("Client {$clientId} DCEP CHANNEL_OPEN sid=$sid type=$channelType prio=$priority rel=$reliability label=$label protocol=$protocol\n");
            $ackPayload = "\x02";
            $this->sendDataOverSCTP($clientId, $sid, $ackPayload, 50);
            if (is_callable($this->onOpen)) {
                try{
                    call_user_func($this->onOpen, $label,$clientId, $this);
                } catch (\Throwable $e) {
                    $this->_log_std("Client {$clientId} onopen callback ERROR: " . $e->getMessage() . "\n");
                }
            }
            $this->_log_std("Client {$clientId} DataChannel ESTABLISHED sid=$sid label=$label.\n");
        } elseif ($msgType === 0x02) {
            $this->_log_std("Client {$clientId} DCEP CHANNEL_ACK sid=$sid.\n");
            if (isset($s['stream_to_dc'][$sid])) $s['stream_to_dc'][$sid]['opened'] = true;
        }
    }

    /**
     * 处理datachannel的数据
     * @param $clientId
     * @param $sid
     * @param $payload
     * @param $isBinary
     * @return void
     */
    private function deliverDataChannelMessage($clientId, $sid, $payload, $isBinary)
    {
        /** 只做有界预览，避免 100KB 消息被整段拼进日志 */
        if ($this->isDev) {
            if ($isBinary) {
                $preview = "binary(" . strlen($payload) . "B) " . bin2hex(substr($payload, 0, min(16, strlen($payload))));
            } else {
                $preview = "text(" . strlen($payload) . "B): " . substr($payload, 0, 128);
            }
            $this->_log_std("Client {$clientId} DataChannel RECV sid=$sid $preview\n");
        }

        if (is_callable($this->onmessage)) {
            try {
                call_user_func($this->onmessage, $payload, $clientId, $this);
            } catch (\Throwable $e) {
                $this->_log_std("Client {$clientId} onmessage callback ERROR: " . $e->getMessage() . "\n");
            }
        } else {
            $echo = $isBinary ? $payload : ("[Server echo] " . $payload);
            $this->sendDataChannel($clientId, $echo, $isBinary ? 53 : 51, $sid);
        }
    }

}