<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose udp协议处理
 * @author yanglong
 * @note 只发送，不校验，快速发送协议
 */
trait UDP
{

    /**
     * 启动upp服务器
     * @return void
     */
    private function startUDPServer()
    {
        $this->udpSocket = @stream_socket_server("udp://0.0.0.0:" . $this->udpPort, $errno, $errstr, STREAM_SERVER_BIND);
        if (!$this->udpSocket) {
            echo "Failed to create UDP socket: {$errstr}\n";
            exit(1);
        }
        /** 设置为非阻塞 */
        stream_set_blocking($this->udpSocket, false);
        if (function_exists('socket_import_stream') && function_exists('socket_set_option')) {
            try {
                $socket = @socket_import_stream($this->udpSocket);
                if ($socket !== false) {
                    $requested = 4 * 1024 * 1024;
                    @socket_set_option($socket, SOL_SOCKET, SO_RCVBUF, $requested);
                    $actual = function_exists('socket_get_option') ? @socket_get_option($socket, SOL_SOCKET, SO_RCVBUF) : null;
                    $this->_log_std("[UDP SO_RCVBUF] requested={$requested} actual=" . ($actual === false || $actual === null ? 'unknown' : $actual) . "\n");
                }
            } catch (\Throwable $e) {
            }
        }

        echo "UDP media server listening on udp://0.0.0.0:" . $this->udpPort . "\n";
    }


    /**
     * 发送udp数据
     * @param $clientId
     * @param $data
     * @return bool
     */
    private function sendUDP($clientId, $data)
    {
        $client = $this->clients[$clientId] ?? null;
        if (!$client || !isset($client['remoteCandidate'])) return false;

        $ip = $client['remoteCandidate']['ip'];
        $port = $client['remoteCandidate']['port'];

        $bytes = @stream_socket_sendto($this->udpSocket, $data, 0, "{$ip}:{$port}");
        if ($bytes === false) {
            $this->_log_std("Client {$clientId} UDP send FAILED to {$ip}:{$port}\n");
            return false;
        }
        return true;
    }

    /**
     * 公共 API：将明文 RTP 包 protect 后发送给指定客户端
     * - 若 $ssrcRewrite === true 且 clients[$id] 中有 serverVideoSsrc / serverAudioSsrc，
     *   则按 PT 查表改写 RTP SSRC 后再 protect（同默认转发逻辑）。
     * - 若已知包的 kind('video'/'audio')，则**优先按 kind 做 PT 翻译和 SSRC 重写**（SFU 核心能力）：
     *   因为每个 WebRTC 会话独立协商 payload type 编号，push 端的视频 PT 与 play 端的视频 PT
     *   大概率不相同，必须从 kind 维度映射到订阅者自己的 primaryPT + 对应 SSRC。
     * @param int    $clientId
     * @param string $rtp        明文 RTP (>=12B，含完整 RTP 头)
     * @param bool   $ssrcRewrite 是否启用 SSRC+PT 改写（默认 true）
     * @param string $kind       包的音视频类型：'video' | 'audio' | 'unknown'（由 publisher 端查表得出，最可信）
     * @param int    $origPT     原始包 PT（仅用于日志）
     * @return bool true=已通过 UDP 实际发出；false=任意前置检查失败或未发出（调用方可按此决定是否计入转发成功数）
     */
    public function protectAndSendRtp(int $clientId, string $rtp, bool $ssrcRewrite = true, string $kind = 'unknown', int $origPT = -1)
    {
        if (!is_string($rtp) || strlen($rtp) < 12) {
            $this->_log_std("Client {$clientId} protectAndSendRtp FAIL: bad RTP len (need >=12)\n");
            return false;
        }
        $c = $this->clients[$clientId] ?? null;
        if (!$c) {
            $this->_log_std("Client {$clientId} protectAndSendRtp FAIL: clientId not in clients table\n");
            return false;
        }

        $now = microtime(true);
        $lastSeen = (float)($c['lastSeenAt'] ?? 0.0);
        if ($lastSeen > 0.0 && ($now - $lastSeen) > 15.0) {
            static $_warnedZombie = [];
            if (empty($_warnedZombie[$clientId])) {
                $_warnedZombie[$clientId] = true;
                $this->_log_std("[protectAndSendRtp STALE WARNING] client={$clientId} lastSeen=" . number_format($now - $lastSeen, 1) . "s; keep forwarding until lifecycle cleanup\n");
            }
        }
        if (in_array((string)($c['state'] ?? ''), ['closed', 'deleted'], true)
            || (string)($c['dtlsState'] ?? '') === 'closed') {
            return false;
        }

        $hasSrtpTx = !empty($c['srtpTx']);
        $hasRc     = !empty($c['remoteCandidate']);
        $lastTx = isset($c['_pasr_lastHasSrtpTx']) ? (bool)$c['_pasr_lastHasSrtpTx'] : null;
        $lastRc = isset($c['_pasr_lastHasRc'])     ? (bool)$c['_pasr_lastHasRc']     : null;
        if ($lastTx !== $hasSrtpTx || $lastRc !== $hasRc) {
            unset($c['_warnedNoSrtpTx'], $c['_warnedSendUdp']);
            $c['_pasr_lastHasSrtpTx'] = $hasSrtpTx;
            $c['_pasr_lastHasRc']     = $hasRc;
        }

        $srtpTx = $c['srtpTx'] ?? null;
        if (!$srtpTx) {
            if (empty($c['_warnedNoSrtpTx'])) {
                $c['_warnedNoSrtpTx'] = true;
                $this->clients[$clientId] = $c;
                $this->_log_std("Client {$clientId} protectAndSendRtp FAIL: srtpTx not ready (DTLS not finished? hasRc=" . ($hasRc?'yes':'no') . "). Suppress until srtpTx/rc state change.\n");
            } else {
                $this->clients[$clientId] = $c;
            }
            return false;
        }


        $fwRtp = $rtp;
        $publisherTimestamp = substr($rtp, 4, 4);
        $origSsrc = 0;
        $newSsrc  = 0;
        $pt       = 0;
        $ptHit    = 'none';
        $newPT    = -1;
        if ($ssrcRewrite) {
            $b1 = ord($rtp[1]);
            $pt = $b1 & 0x7F;
            if ($origPT < 0) $origPT = $pt;
            $origSsrc = unpack('N', substr($rtp, 8, 4))[1];
            $videoPTs = isset($c['videoPTs']) && is_array($c['videoPTs']) ? $c['videoPTs'] : [];
            $audioPTs = isset($c['audioPTs']) && is_array($c['audioPTs']) ? $c['audioPTs'] : [];

            $FORCE_VIDEO_PT = (int)($c['outVideoPT'] ?? $c['primaryVideoPT'] ?? 0);
            $FORCE_AUDIO_PT = (int)($c['outAudioPT'] ?? $c['primaryAudioPT'] ?? 0);

            if ($kind === 'video' || $kind === 'audio') {
                if ($kind === 'audio') {
                    $newSsrc = (int)($c['serverAudioSsrc'] ?? 3741943039);
                    $newPT   = $FORCE_AUDIO_PT > 0 ? $FORCE_AUDIO_PT : -1;
                    $ptHit   = 'audio(kind, subscriber target PT)';
                } else {
                    $newSsrc = (int)($c['serverVideoSsrc'] ?? 4147483647);
                    $newPT   = $FORCE_VIDEO_PT > 0 ? $FORCE_VIDEO_PT : -1;
                    $ptHit   = 'video(kind, subscriber target PT)';
                }
            }

            else {
                $_b0 = ord($rtp[0]);
                $_cc = $_b0 & 0xF;
                $_hdrLen = 12 + 4 * $_cc;

                if (($_b0 >> 4) & 0x1) {
                    if (strlen($rtp) >= $_hdrLen + 4) {
                        $_extLen = unpack('n', substr($rtp, $_hdrLen + 2, 2))[1];
                        $_hdrLen += 4 + 4 * $_extLen;
                    }
                }
                $_pLen = strlen($rtp) - $_hdrLen;
                $_probeKind = '';

                if (isset($audioPTs[$pt])) {
                    $_probeKind = 'audio';
                } elseif (isset($videoPTs[$pt])) {
                    $_probeKind = 'video';
                } elseif ($_pLen > 0) {
                    $_p0 = ord($rtp[$_hdrLen] ?? "\x00");
                    $_t = $_p0 & 0x1F;
                    if (in_array($_t, [1,2,3,4,5,6,7,8,9,24,25,26,27,28,29,30,31], true)) {
                        $_probeKind = 'video';
                    } elseif (($pt >= 100 && $pt <= 127) || $pt === 0 || $pt === 8) {
                        $_probeKind = 'audio';
                    }
                }

                if ($_probeKind === 'video') {
                    $newSsrc = (int)($c['serverVideoSsrc'] ?? 4147483647);
                    $newPT   = $FORCE_VIDEO_PT > 0 ? $FORCE_VIDEO_PT : -1;
                    $ptHit   = 'video(unknown-kind, subscriber target PT)';
                } elseif ($_probeKind === 'audio') {
                    $newSsrc = (int)($c['serverAudioSsrc'] ?? 3741943039);
                    $newPT   = $FORCE_AUDIO_PT > 0 ? $FORCE_AUDIO_PT : -1;
                    $ptHit   = 'audio(unknown-kind, subscriber target PT)';
                }
            }

            if ($newSsrc > 0) {
                $fwRtp[8]  = chr(($newSsrc >> 24) & 0xFF);
                $fwRtp[9]  = chr(($newSsrc >> 16) & 0xFF);
                $fwRtp[10] = chr(($newSsrc >> 8)  & 0xFF);
                $fwRtp[11] = chr( $newSsrc        & 0xFF);
            }

            if ($newPT >= 0) {
                $marker = ($b1 & 0x80);
                $fwRtp[1] = chr($marker | ($newPT & 0x7F));
                $pt = $newPT;
            }
        }

        if ($newSsrc > 0) {
            if (!isset($c['_outSeq'][$newSsrc])) {
                $c['_outSeq'][$newSsrc] = ((ord($fwRtp[2]) << 8) | ord($fwRtp[3])) & 0xFFFF;
            } else {
                $c['_outSeq'][$newSsrc] = ($c['_outSeq'][$newSsrc] + 1) & 0xFFFF;
            }
            $_seq = $c['_outSeq'][$newSsrc];
            $fwRtp[2] = chr(($_seq >> 8) & 0xFF);
            $fwRtp[3] = chr( $_seq       & 0xFF);

        }
        $fwRtp[4] = $publisherTimestamp[0];
        $fwRtp[5] = $publisherTimestamp[1];
        $fwRtp[6] = $publisherTimestamp[2];
        $fwRtp[7] = $publisherTimestamp[3];

        try {
            $srtpOut = $srtpTx->protect($fwRtp);
        } catch (\Throwable $e) {
            $this->_log_std(
                "Client {$clientId} protectAndSendRtp protect() FAIL: "
                . $e->getMessage()
                . "\n"
            );
            return false;
        }

        if (!is_string($srtpOut) || strlen($srtpOut) === 0) {
            $this->_log_std(
                "Client {$clientId} protectAndSendRtp protect() FAIL: empty output\n"
            );
            return false;
        }

        $sent = $this->sendUDP($clientId, $srtpOut);

        if (!$sent) {
            if (empty($c['_warnedSendUdp'])) {
                $c['_warnedSendUdp'] = true;
                $this->clients[$clientId] = $c;
                $rc = isset($c['remoteCandidate']) ? "{$c['remoteCandidate']['ip']}:{$c['remoteCandidate']['port']}" : 'null';
                $this->_log_std("Client {$clientId} protectAndSendRtp FAIL: sendUDP cannot deliver (remoteCandidate={$rc}). PT={$origPT}->{$pt} hit={$ptHit} ssrc:{$origSsrc}=>" . ($newSsrc>0?$newSsrc:'(no-change)') . "). Suppress until srtpTx/rc state change.\n");
            } else {
                $this->clients[$clientId] = $c;
            }
            return false;
        }

        $counter = (int)($c['_srtpOutCounter'] ?? 0);
        if (($counter % 3000) === 0) {
            $rc = isset($c['remoteCandidate']) ? "{$c['remoteCandidate']['ip']}:{$c['remoteCandidate']['port']}" : 'null';
            $ptTag = ($origPT >= 0 && $origPT !== $pt) ? "{$origPT}->{$pt}" : (string)$pt;
            $this->_log_std("Client {$clientId} SRTP-OUT ok PT={$ptTag} hit={$ptHit} kind={$kind} ssrc:{$origSsrc}=>" . ($newSsrc>0?$newSsrc:$origSsrc) . " len=" . strlen($srtpOut) . " rc={$rc} (this line every 3000 pkts)\n");
        }
        $c['_srtpOutCounter'] = $counter + 1;
        $this->clients[$clientId] = $c;
        return true;
    }

    /**
     * 公共 API：将明文 RTCP 包 SRTCP protect 后发送给指定客户端。
     *   - 用于 SFU 主动向 publisher 发 PLI/FIR（强制出关键帧），或 relay subscriber 发来的 RTCP feedback
     * @param int    $clientId
     * @param string $rtcp       明文 RTCP (>=8B，含完整 common header + payload)
     * @return bool
     */
    public function protectAndSendRtcp(int $clientId, string $rtcp): bool
    {

        static $_dbgOnce = [];
        $logOnce = function (string $tag, string $detail = '') use ($clientId, &$_dbgOnce) {
            $k = $clientId . '_' . $tag;
            if (empty($_dbgOnce[$k])) {
                $_dbgOnce[$k] = true;
                $this->_log_std("Client {$clientId} protectAndSendRtcp {$tag} " . ($detail !== '' ? "detail={$detail} " : '') . "(subsequent suppressed per client)\n");
            }
        };

        if (!is_string($rtcp) || strlen($rtcp) < 8) {
            $logOnce('BAD_RTCP_LEN', 'len=' . (is_string($rtcp) ? strlen($rtcp) : gettype($rtcp)));
            return false;
        }
        $c = $this->clients[$clientId] ?? null;
        if (!$c) {
            $logOnce('NO_CLIENT');
            return false;
        }
        if (empty($c['remoteCandidate'])) {
            $logOnce('NO_RC');
            return false;
        }
        if (!is_array($c['remoteCandidate']) || !isset($c['remoteCandidate']['ip'], $c['remoteCandidate']['port'])) {
            $logOnce('RC_FORMAT_BAD', 'type=' . gettype($c['remoteCandidate']));
            return false;
        }
        $candidate = $c['remoteCandidate'];
        $ip   = $candidate['ip'];
        $port = (int)$candidate['port'];
        if ($ip === '' || $port <= 0 || $port > 65535) {
            $logOnce('RC_BAD_VALUES', "ip={$ip} port={$port}");
            return false;
        }

        $srtpTx = $c['srtpTx'] ?? null;
        if (!$srtpTx) {
            $logOnce('NO_SRTP_TX', 'srtpTx not ready (DTLS not keyed?)');
            return false;
        }
        $srtcp = $srtpTx->protectRtcp($rtcp);
        if (!is_string($srtcp) || strlen($srtcp) === 0) {
            $logOnce('PROTECT_RTCP_FAIL', 'protectRtcp() returned empty');
            return false;
        }

        static $_dbgFirst = [];
        if (empty($_dbgFirst[$clientId])) {
            $_dbgFirst[$clientId] = true;
            $this->_log_std("Client {$clientId} protectAndSendRtcp FIRST CALL → SRTCP protect+sendUDP {$ip}:{$port} plainLen=" . strlen($rtcp) . " srtcpLen=" . strlen($srtcp) . " hex=" . bin2hex(substr($srtcp, 0, 8)) . "\n");
        }
        $ok = $this->sendUDP($clientId, $srtcp);
        if ($ok) {
            if (($_dbgFirst[$clientId] ?? null) === true) {
                $_dbgFirst[$clientId] = 'ok';
                $this->_log_std("Client {$clientId} protectAndSendRtcp SENT OK via sendUDP ({$ip}:{$port}, len=" . strlen($rtcp) . ")  → PLI/FIR 已送达，浏览器编码器 100~300ms 内将输出新 IDR 关键帧\n");
            }
        } else {
            static $_dbgFail = [];
            if (empty($_dbgFail[$clientId])) {
                $_dbgFail[$clientId] = true;
                $err = error_get_last();
                $this->_log_std("Client {$clientId} protectAndSendRtcp FINAL FAIL via sendUDP ({$ip}:{$port}) err=" . (is_array($err) ? json_encode($err, JSON_UNESCAPED_SLASHES) : 'null') . "\n");
            }
        }
        return $ok;
    }

    /**
     * 处理UDP连接
     * - 优先级：STUN -> DTLS -> SRTP(media)
     * - RFC 5764 demux：首字节高 2 位 = 10 (0x80..0xBF) 即 RTP v2，非 STUN(0x0001/0x0101 等 msgType) 且非 DTLS(20..23)
     * - 若 $this->onRtp 可调用，投递 (clientId, plainRtp, parsedHeader)；否则走默认 SSRC 改写 echo
     * @return bool true if one non-empty datagram was read; false otherwise
     */
    private function handleUDP(): bool
    {
        $from = '';
        $data = @stream_socket_recvfrom($this->udpSocket, 65536, 0, $from);

        if ($data === false || strlen($data) === 0) return false;

        $fromParts = explode(':', $from);
        $fromIP = $fromParts[0];
        $fromPort = isset($fromParts[1]) ? (int)$fromParts[1] : 0;

        $fromKey = "{$fromIP}:{$fromPort}";
        $targetClientId = null;

        if (isset($this->udpAddrMap[$fromKey])) {
            $targetClientId = $this->udpAddrMap[$fromKey];
        }

        if ($targetClientId === null && strlen($data) >= 20) {
            $magicCookie = substr($data, 4, 4);
            if ($magicCookie === "\x21\x12\xA4\x42") {
                $msgLen = unpack('n', substr($data, 2, 2))[1];
                $attrOffset = 20;
                $attrsEnd = min(20 + $msgLen, strlen($data));
                $username = '';
                while ($attrOffset + 4 <= $attrsEnd) {
                    $atype = unpack('n', substr($data, $attrOffset, 2))[1];
                    $alen = unpack('n', substr($data, $attrOffset + 2, 2))[1];
                    if ($attrOffset + 4 + $alen > $attrsEnd) break;
                    if ($atype === 0x0006) {
                        $username = substr($data, $attrOffset + 4, $alen);
                        break;
                    }
                    $attrOffset += 4 + ($alen + 3 & ~3);
                }
                if ($username !== '') {
                    $parts = explode(':', $username, 2);
                    $serverUfrag = $parts[0] ?? '';
                    if ($serverUfrag !== '') {
                        foreach ($this->clients as $id => $client) {
                            $cUfrag = $client['iceUfrag'] ?? ($client['localIceUfrag'] ?? '');
                            if ($cUfrag === $serverUfrag) {
                                $targetClientId = $id;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if ($targetClientId === null) {
            static $_dropLog = ['cnt' => 0, 'lastTs' => 0];
            $_dropLog['cnt']++;
            $now = time();
            if ($_dropLog['cnt'] === 1 || ($now - $_dropLog['lastTs']) >= 5) {
                $_dropLog['lastTs'] = $now;
                $registered = [];
                foreach ($this->clients as $cid => $cl) {
                    $uf = $cl['iceUfrag'] ?? ($cl['localIceUfrag'] ?? '');
                    $st = $cl['state'] ?? '?';
                    $rc = isset($cl['remoteCandidate']) ? "{$cl['remoteCandidate']['ip']}:{$cl['remoteCandidate']['port']}" : 'none';
                    $role = isset($cl['meta']) && is_array($cl['meta']) ? ($cl['meta']['role'] ?? '?') : '?';
                    $registered[] = "#{$cid}[role={$role} state={$st} ufrag={$uf} rc={$rc}]";
                }
                $fb = substr($data, 0, 32);
                $hex = unpack('H*', $fb)[1];
                $this->_log_std("[handleUDP] DROP unknown src={$fromKey} (total drops: {$_dropLog['cnt']}). first32B hex={$hex}. registered clients: " . implode(', ', $registered) . "\n");
            }
            return true;
        }

        $isValidated = !empty($this->clients[$targetClientId]['remoteCandidateValidated']);
        $pktIsEpochGte1 = false;
        if (strlen($data) > 3) {
            $firstByte = ord($data[0]);
            if ($firstByte >= 20 && $firstByte <= 23) {
                $epoch = (ord($data[3]) << 8) | ord($data[4]);
                if ($epoch >= 1) $pktIsEpochGte1 = true;
            }
        }

        if ($isValidated) {
            if (!isset($this->udpAddrMap[$fromKey])) {
                $this->udpAddrMap[$fromKey] = $targetClientId;
            }
        } elseif ($pktIsEpochGte1) {
            $prevRc = $this->clients[$targetClientId]['remoteCandidate'] ?? null;
            $prevAddr = $prevRc ? "{$prevRc['ip']}:{$prevRc['port']}" : "none";
            $this->clients[$targetClientId]['remoteCandidate'] = ['ip' => $fromIP, 'port' => $fromPort];
            $this->clients[$targetClientId]['remoteCandidateValidated'] = true;
            $this->clients[$targetClientId]['remoteCandidateTentativeLocked'] = true;
            $this->_log_std("[remoteCandidate LOCKED] Client {$targetClientId}: {$prevAddr} -> {$fromIP}:{$fromPort} (epoch>=1 DTLS, PERMANENT)\n");
            if (!isset($this->udpAddrMap[$fromKey])) {
                $this->udpAddrMap[$fromKey] = $targetClientId;
            }

            if (method_exists($this, 'kickFaststartForSubscriber')) {
                try { $this->kickFaststartForSubscriber($targetClientId); }
                catch (\Throwable $e) {
                    if (method_exists($this, '_log_std')) {
                        $this->_log_std("Client {$targetClientId} kickFaststartForSubscriber exception: " . $e->getMessage() . "\n");
                    }
                }
            }
        } else {

            $tentative = !empty($this->clients[$targetClientId]['remoteCandidateTentativeLocked']);
            $prevRc = $this->clients[$targetClientId]['remoteCandidate'] ?? null;
            $prevAddr = $prevRc ? "{$prevRc['ip']}:{$prevRc['port']}" : "none";
            if (!$tentative) {
                $this->clients[$targetClientId]['remoteCandidate'] = ['ip' => $fromIP, 'port' => $fromPort];
                $this->clients[$targetClientId]['remoteCandidateTentativeLocked'] = true;
                $this->_log_std("[remoteCandidate SET] Client {$targetClientId}: {$prevAddr} -> {$fromIP}:{$fromPort} (first UDP packet, TENTATIVE lock until epoch>=1 DTLS)\n");
            }
            if (!isset($this->udpAddrMap[$fromKey])) {
                $this->udpAddrMap[$fromKey] = $targetClientId;
            }
        }

        $firstByte = ord($data[0]);

        if ($targetClientId !== null && isset($this->clients[$targetClientId])) {
            $this->clients[$targetClientId]['lastSeenAt'] = microtime(true);
        }

        if (strlen($data) >= 20) {
            $msgType = unpack('n', substr($data, 0, 2))[1];
            $magicCookie = substr($data, 4, 4);
            if ($magicCookie === "\x21\x12\xA4\x42" && ($msgType & 0xC000) === 0) {
                $this->clients[$targetClientId]['state'] = 'connecting';
                $this->handleSTUNMessage($targetClientId, $data, $from);
                return true;
            }
        }

        if ($firstByte >= 20 && $firstByte <= 23) {
            $this->clients[$targetClientId]['state'] = 'connecting';
            $this->handleDTLS($targetClientId, $data);
            return true;
        }

        if (($firstByte & 0xC0) === 0x80) {
            $c = &$this->clients[$targetClientId];
            $srtpRx = $c['srtpRx'] ?? null;
            $srtpTx = $c['srtpTx'] ?? null;

            if ($srtpRx === null || $srtpTx === null) {

                if (!empty($c['clientHasUseSrtp']) && empty($c['srtpKeyed'])) {
                    $this->_log_std("Client {$targetClientId} SRTP ctx not ready, attempting on-demand RFC5764 derive...\n");
                    if ($this->deriveSrtpKeysRfc5764($targetClientId)) {
                        $srtpRx = $c['srtpRx'] ?? null;
                        $srtpTx = $c['srtpTx'] ?? null;
                    }
                }
                if ($srtpRx === null || $srtpTx === null) {
                    if (empty($c['_warnedSrtpNoCtx'])) {
                        $c['_warnedSrtpNoCtx'] = true;
                        $hasExt = !empty($c['clientHasUseSrtp']) ? 'yes' : 'no';
                        $this->_log_std("Client {$targetClientId} WARNING: SRTP packet received but srtpRx/srtpTx NOT ready (use_srtp=$hasExt). firstByte=0x" . dechex($firstByte) . " len=" . strlen($data) . " (subsequent warnings suppressed)\n");
                    }
                    return true;
                }
            }

            $isRtcp = (strlen($data) >= 2) && \Xiaosongshu\Webrtc\Core\SRTP::isRtcpPt(ord($data[1]));

            $plainRtp = null;
            $plainRtcp = null;
            if ($isRtcp) {
                $plainRtcp = $srtpRx->unprotectRtcp($data);
                if (is_string($plainRtcp) && strlen($plainRtcp) >= 8
                    && (string)(($c['meta']['role'] ?? '')) === 'push') {
                    for ($_srOffset = 0, $_srCompoundLen = strlen($plainRtcp); ($_srOffset + 4) <= $_srCompoundLen;) {
                        $_srPacketLen = (unpack('n', substr($plainRtcp, $_srOffset + 2, 2))[1] + 1) * 4;
                        if ($_srPacketLen < 4 || ($_srOffset + $_srPacketLen) > $_srCompoundLen) break;
                        if (ord($plainRtcp[$_srOffset + 1]) === 200 && $_srPacketLen >= 28) {
                            $_srSenderSsrc = unpack('N', substr($plainRtcp, $_srOffset + 4, 4))[1];
                            $_srNtpSec = unpack('N', substr($plainRtcp, $_srOffset + 8, 4))[1];
                            $_srNtpFraction = unpack('N', substr($plainRtcp, $_srOffset + 12, 4))[1];
                            if (!isset($c['_publisherRtcpSr']) || !is_array($c['_publisherRtcpSr'])) $c['_publisherRtcpSr'] = [];
                            $c['_publisherRtcpSr'][$_srSenderSsrc] = [
                                'lsr' => (($_srNtpSec & 0xFFFF) << 16) | (($_srNtpFraction >> 16) & 0xFFFF),
                                'receivedAt' => microtime(true),
                            ];
                        }
                        $_srOffset += $_srPacketLen;
                    }
                    $this->clients[$targetClientId] = $c;
                }

                if ($plainRtcp === null || $plainRtcp === false || !is_string($plainRtcp) || strlen($plainRtcp) < 8) {
                    static $_wFb = [];
                    if (empty($_wFb[$targetClientId])) {
                        $_wFb[$targetClientId] = true;
                        $this->_log_std("Client {$targetClientId} SRTCP decrypt FAIL → packet dropped len=" . strlen($data) . " (subsequent suppressed per client)\n");
                    }
                    return true;
                }
            }

            if (!$isRtcp) {
                $plainRtp = $srtpRx->unprotect($data);
            }

            if ($plainRtcp !== null && $plainRtcp !== false && is_string($plainRtcp) && strlen($plainRtcp) >= 8) {
                $meta    = isset($c['meta'])    && is_array($c['meta'])    ? $c['meta']    : [];
                $role    = (string)($meta['role']     ?? '');
                $sid     = (string)($meta['streamId'] ?? '');
                $_rtcpOffset = 0;
                $_plainRtcpLen = strlen($plainRtcp);
                while (($_rtcpOffset + 4) <= $_plainRtcpLen) {
                    $_rtcpWords = unpack('n', substr($plainRtcp, $_rtcpOffset + 2, 2))[1];
                    $_rtcpPacketLen = ($_rtcpWords + 1) * 4;
                    if ($_rtcpPacketLen < 4 || ($_rtcpOffset + $_rtcpPacketLen) > $_plainRtcpLen) break;
                    $_rtcpPacket = substr($plainRtcp, $_rtcpOffset, $_rtcpPacketLen);
                    $rtcpPT = ord($_rtcpPacket[1]);
                    $fmt = ord($_rtcpPacket[0]) & 0x1F;
                    $_ok_rtcp = "Client {$targetClientId} SRTCP-IN ok pt={$rtcpPT} fmt={$fmt} role={$role} sid={$sid} len={$_rtcpPacketLen}";
                    $typeName = null;
                    if ($rtcpPT === 206 && $fmt === 1) $typeName = 'PLI';
                    elseif ($rtcpPT === 206 && $fmt === 4) $typeName = 'FIR';

                    if ($typeName !== null) {
                        $this->_log_std("{$_ok_rtcp} → {$typeName} FROM subscriber\n");
                        if ($sid !== '' && $role === 'play' && method_exists($this, 'sendPliToPublisher')) {
                            try {
                                $forwarded = $this->sendPliToPublisher($sid, true);
                                if ($forwarded) {
                                    $this->_log_std("  ↪ {$typeName} mapped to rebuilt PLI for publisher of streamId={$sid}\n");
                                } else {
                                    $this->_log_std("  ↪ {$typeName} rebuilt PLI SKIP (throttled or no publisher for streamId={$sid})\n");
                                }
                            } catch (\Throwable $e) {
                                $this->_log_std("  ↪ {$typeName} rebuilt PLI EXCEPTION: " . $e->getMessage() . "\n");
                            }
                        }
                    } elseif ($rtcpPT === 205 && $fmt === 1) {
                        static $_nackSummary = [];
                        $_nackNow = microtime(true);
                        if (!isset($_nackSummary[$targetClientId])) $_nackSummary[$targetClientId] = ['count'=>0, 'lastLog'=>0.0];
                        $_nackSummary[$targetClientId]['count']++;
                        if (($_nackNow - $_nackSummary[$targetClientId]['lastLog']) >= 1.0) {
                            $this->_log_std("Client {$targetClientId} Generic NACK summary count={$_nackSummary[$targetClientId]['count']} role={$role} sid={$sid} (no retransmission cache, max once/1s)\n");
                            $_nackSummary[$targetClientId] = ['count'=>0, 'lastLog'=>$_nackNow];
                        }
                    } elseif ($rtcpPT === 201) {
                        static $_rrSample = 0;
                        if ((++$_rrSample % 100) === 1) $this->_log_std("{$_ok_rtcp} → RR (every 100)\n");
                    } else {
                        static $_rtcpSample = 0;
                        if ((++$_rtcpSample % 100) === 1) $this->_log_std("{$_ok_rtcp} (every 100)\n");
                    }
                    $_rtcpOffset += $_rtcpPacketLen;
                }
                return true;
            }

            if ($plainRtp === false || !is_string($plainRtp) || strlen($plainRtp) < 12) {
                if ($srtpRx->rxPackets === 0) {
                    if (!empty($c['clientHasUseSrtp']) && empty($c['srtpKeyed'])) {
                        $this->_log_std("Client {$targetClientId} SRTP-IN  FAIL unprotect, use_srtp=yes but srtpKeyed=false — retrying on-demand RFC5764 derive...\n");
                        if ($this->deriveSrtpKeysRfc5764($targetClientId)) {
                            $freshRx = $c['srtpRx'] ?? null;
                            if ($freshRx) {
                                $retry = $freshRx->unprotect($data);
                                if (is_string($retry) && strlen($retry) >= 12) {
                                    $plainRtp = $retry;
                                }
                            }
                        }
                    }
                }
                if ($plainRtp === false || !is_string($plainRtp) || strlen($plainRtp) < 12) {
                    if (empty($c['_warnedSrtpUnprotFail'])) {
                        $c['_warnedSrtpUnprotFail'] = true;
                        $this->_log_std("Client {$targetClientId} SRTP unprotect() FAIL (auth/bad len). first 32B hex: " . bin2hex(substr($data, 0, min(32, strlen($data)))) . " rxPackets=" . ($srtpRx->rxPackets) . " (subsequent suppressed)\n");
                    }
                    return true;
                }
            }

            $b0 = ord($plainRtp[0]);
            $b1 = ord($plainRtp[1]);
            $v  = ($b0 >> 6) & 0x3;
            $cc = $b0 & 0xF;
            $pt = $b1 & 0x7F;
            $seq = unpack('n', substr($plainRtp, 2, 2))[1];
            $ts  = unpack('N', substr($plainRtp, 4, 4))[1];
            $ssrcVal = unpack('N', substr($plainRtp, 8, 4))[1];
            $hdrLen = 12 + 4 * $cc;

            if ((string)(($c['meta']['role'] ?? '')) === 'push') {
                $videoPtMap = is_array($c['videoPTs'] ?? null) ? $c['videoPTs'] : [];
                $audioPtMap = is_array($c['audioPTs'] ?? null) ? $c['audioPTs'] : [];
                $ptInfo = isset($videoPtMap[$pt]) && is_array($videoPtMap[$pt])
                    ? $videoPtMap[$pt]
                    : (isset($audioPtMap[$pt]) && is_array($audioPtMap[$pt]) ? $audioPtMap[$pt] : []);
                $clockRate = (int)($ptInfo['clock'] ?? 0);
                if ($clockRate <= 0) $clockRate = isset($videoPtMap[$pt]) ? 90000 : 48000;
                if (!isset($c['_publisherRtpRx']) || !is_array($c['_publisherRtpRx'])) $c['_publisherRtpRx'] = [];
                $arrival = microtime(true) * $clockRate;
                if (!isset($c['_publisherRtpRx'][$ssrcVal])) {
                    $c['_publisherRtpRx'][$ssrcVal] = [
                        'baseSeq' => $seq, 'maxSeq' => $seq, 'cycles' => 0, 'received' => 1,
                        'expectedPrior' => 0, 'receivedPrior' => 0, 'jitter' => 0.0,
                        'transit' => $arrival - $ts, 'clockRate' => $clockRate,
                    ];
                } else {
                    $rx = &$c['_publisherRtpRx'][$ssrcVal];
                    $delta = ($seq - (int)$rx['maxSeq']) & 0xFFFF;
                    if ($delta !== 0 && $delta < 0x8000) {
                        if ($seq < (int)$rx['maxSeq']) $rx['cycles'] = (int)$rx['cycles'] + 0x10000;
                        $rx['maxSeq'] = $seq;
                    }
                    $rx['received'] = (int)$rx['received'] + 1;
                    $transit = $arrival - $ts;
                    $distance = abs($transit - (float)$rx['transit']);
                    $rx['transit'] = $transit;
                    $rx['jitter'] = (float)$rx['jitter'] + ($distance - (float)$rx['jitter']) / 16.0;
                    $rx['clockRate'] = $clockRate;
                    unset($rx);
                }
            }

            if (!isset($c['incomingSsrcByPt']) || !is_array($c['incomingSsrcByPt'])) {
                $c['incomingSsrcByPt'] = [];
            }
            $c['incomingSsrcByPt'][$pt] = $ssrcVal;

            $h = [
                'v'=>$v,'pt'=>$pt,'seq'=>$seq,'ts'=>$ts,'ssrc'=>$ssrcVal,
                'hdrLen'=>$hdrLen,'payloadLen'=>strlen($plainRtp)-$hdrLen,
            ];

            $srtpInCounter = (int)($c['_srtpInCounter'] ?? 0);
            if (($srtpInCounter % 3000) === 0) {
                $this->_log_std("Client {$targetClientId} SRTP-IN ok pt={$pt} ssrc={$ssrcVal} seq={$seq} ts={$ts} len=" . strlen($plainRtp) . " (this line every 3000 pkts)\n");
            }
            $c['_srtpInCounter'] = $srtpInCounter + 1;
            $this->clients[$targetClientId] = $c;

            $_metaForRefresh = isset($c['meta']) && is_array($c['meta']) ? $c['meta'] : [];
            $_hasMetaForRefresh = !empty($_metaForRefresh);

            if ($_hasMetaForRefresh && ($_metaForRefresh['role'] ?? '') === 'push' && !empty($_metaForRefresh['streamId'])
                && method_exists($this, '_refreshPrimaryFromActualPacket')) {
                try {
                    $videoPTMap = isset($c['videoPTs']) && is_array($c['videoPTs']) ? $c['videoPTs'] : [];
                    $audioPTMap = isset($c['audioPTs']) && is_array($c['audioPTs']) ? $c['audioPTs'] : [];
                    $_kind = '';
                    if (isset($videoPTMap[$pt])) $_kind = 'video';
                    elseif (isset($audioPTMap[$pt])) $_kind = 'audio';
                    if ($_kind !== '') {
                        $this->_refreshPrimaryFromActualPacket((int)$targetClientId, (string)$_metaForRefresh['streamId'], (int)$pt, $_kind, $_kind === 'video' ? $videoPTMap : $audioPTMap, (int)$ssrcVal);
                    }
                } catch (\Throwable $_e) {
                    if (method_exists($this, '_log_std')) {
                        $this->_log_std("[refreshPrimary] client={$targetClientId} exception: {$_e->getMessage()}\n");
                    }
                }
            }

            if (method_exists($this, '_notifyMediaConnectedIfFirst')) {
                try {
                    $this->_notifyMediaConnectedIfFirst($targetClientId, $h);
                } catch (\Throwable $e) {
                    if (method_exists($this, '_log_std')) {
                        $this->_log_std("Client {$targetClientId} _notifyMediaConnectedIfFirst exception: " . $e->getMessage() . "\n");
                    }
                }
            }

            if (isset($this->onRtp) && is_callable($this->onRtp)) {
                try {
                    call_user_func($this->onRtp, $targetClientId, $plainRtp, $h, $this);
                } catch (\Throwable $e) {
                    $this->_log_std("Client {$targetClientId} onRtp callback EXCEPTION: " . $e->getMessage() . "\n");
                }
                return true;
            }

            $meta = [];
            $hasMeta = false;
            if (isset($this->clients[$targetClientId]['meta']) && is_array($this->clients[$targetClientId]['meta'])) {
                $meta    = $this->clients[$targetClientId]['meta'];
                $hasMeta = true;
            }
            if ($hasMeta && ($meta['role'] ?? '') === 'push' && !empty($meta['streamId']) && method_exists($this, 'forwardRtpToAllSubscribers')) {
                $n = $this->forwardRtpToAllSubscribers((string)$meta['streamId'],$plainRtp,$targetClientId);

                $sfuFwdCounter = (int)($c['_sfuFwdCounter'] ?? 0);
                if ($n > 0 && ($sfuFwdCounter % 3000) === 0) {
                    $this->_log_std("Client {$targetClientId} SFU forward streamId={$meta['streamId']} -> {$n} subscriber(s) (this line every 3000 pkts)\n");
                }
                $c['_sfuFwdCounter'] = $sfuFwdCounter + 1;
                $this->clients[$targetClientId] = $c;
                return true;
            }

            $videoPTs = isset($c['videoPTs']) && is_array($c['videoPTs']) ? $c['videoPTs'] : [];
            $audioPTs = isset($c['audioPTs']) && is_array($c['audioPTs']) ? $c['audioPTs'] : [];
            $newSsrc = 0;
            $kind = '';
            if (isset($audioPTs[$pt])) {
                $kind = 'audio';
                $newSsrc = (int)($c['serverAudioSsrc'] ?? 3741943039);
            } elseif (isset($videoPTs[$pt])) {
                $kind = 'video';
                $newSsrc = (int)($c['serverVideoSsrc'] ?? 4147483647);
            }
            if ($newSsrc <= 0) {
                $newSsrc = $ssrcVal;
            }
            $fwRtp = $plainRtp;
            $fwRtp[8]  = chr(($newSsrc >> 24) & 0xFF);
            $fwRtp[9]  = chr(($newSsrc >> 16) & 0xFF);
            $fwRtp[10] = chr(($newSsrc >> 8)  & 0xFF);
            $fwRtp[11] = chr( $newSsrc        & 0xFF);

            try {
                $srtpOut = $srtpTx->protect($fwRtp);
            } catch (\Throwable $e) {
                $this->_log_std("Client {$targetClientId} SRTP protect() FAIL: " . $e->getMessage() . "\n");
                return true;
            }
            if (!is_string($srtpOut) || strlen($srtpOut) === 0) return true;

            $echoOutCounter = (int)($c['_echoSrtpOutCounter'] ?? 0);
            if (($echoOutCounter % 3000) === 0) {
                $this->_log_std("Client {$targetClientId} SRTP-OUT kind={$kind} pt={$pt} new_ssrc={$newSsrc} len=" . strlen($srtpOut) . " (this line every 3000 pkts)\n");
            }
            $c['_echoSrtpOutCounter'] = $echoOutCounter + 1;
            $this->clients[$targetClientId] = $c;
            $this->sendUDP($targetClientId, $srtpOut);
            return true;
        }
        return true;
    }

    private function drainUdpBurst(int $maxPackets = 64, float $maxSeconds = 0.002): int
    {
        $count = 0;
        $startedAt = microtime(true);
        do {
            if (!$this->handleUDP()) break;
            $count++;
        } while ($count < $maxPackets && (microtime(true) - $startedAt) < $maxSeconds);
        return $count;
    }
}
