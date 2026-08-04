<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose udp协议处理
 * @author yanglong
 * @note 只发送，不校验，快速发送协议
 */
trait UDP
{

    private function _udpDbgHttpPost(string $payload, string $sessionId = 'whep-zero-video'): ?bool
    {
        static $urls = [], $failures = [], $openUntil = [];
        $now = microtime(true);
        if (($openUntil[$sessionId] ?? 0.0) > $now) return null;
        if (!isset($urls[$sessionId])) {
            $env = @file_get_contents(dirname(__DIR__, 2) . '/.dbg/' . $sessionId . '.env');
            preg_match('/^DEBUG_SERVER_URL=(.+)$/m', (string)$env, $match);
            $urls[$sessionId] = trim($match[1] ?? 'http://127.0.0.1:7777/event');
        }
        $result = @file_get_contents($urls[$sessionId], false, stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\nConnection: close\r\n",'content'=>$payload,'timeout'=>0.005,'ignore_errors'=>true]]));
        if ($result !== false) {
            $failures[$sessionId] = 0;
            $openUntil[$sessionId] = 0.0;
            return true;
        }
        $failures[$sessionId] = (int)($failures[$sessionId] ?? 0) + 1;
        if ($failures[$sessionId] >= 2) {
            $failures[$sessionId] = 0;
            $openUntil[$sessionId] = $now + 30.0;
        }
        return false;
    }


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
     * @return void
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

        $_dbgRewriteStarted = $kind === 'video' ? hrtime(true) : 0;
        $_dbgRewriteNs = 0;
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

                    if ($FORCE_AUDIO_PT > 0 && !isset($audioPTs[$FORCE_AUDIO_PT])) {
                        $audioPTs[$FORCE_AUDIO_PT] = [
                            'rtpmap' => 'opus/48000/2', 'codec' => 'opus', 'clock' => 48000,
                            'fmtp' => 'minptime=10;useinbandfec=1',
                        ];
                    }
                } else {
                    $newSsrc = (int)($c['serverVideoSsrc'] ?? 4147483647);
                    $newPT   = $FORCE_VIDEO_PT > 0 ? $FORCE_VIDEO_PT : -1;
                    $ptHit   = 'video(kind, subscriber target PT)';
                    if ($FORCE_VIDEO_PT > 0 && !isset($videoPTs[$FORCE_VIDEO_PT])) {
                        $videoPTs[$FORCE_VIDEO_PT] = [
                            'rtpmap' => 'H264/90000', 'codec' => 'H264', 'clock' => 90000,
                            'fmtp' => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f',
                        ];
                    }
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

        if ($kind === 'video') $_dbgRewriteNs = (int)(hrtime(true) - $_dbgRewriteStarted);

        if ($kind === 'video') {
            static $_dbgVideoTimeline = [];
            if (!isset($_dbgVideoTimeline[$clientId])) {
                $_dbgVideoTimeline[$clientId] = ['packets'=>0,'markers'=>0,'prevTs'=>null,'prevOutSeq'=>null];
            }
            $_dbgTimeline = &$_dbgVideoTimeline[$clientId];
            $_dbgTimeline['packets']++;
            $_dbgOrigSeq = unpack('n', substr($rtp, 2, 2))[1];
            $_dbgOutSeq = unpack('n', substr($fwRtp, 2, 2))[1];
            $_dbgTimestamp = unpack('N', substr($fwRtp, 4, 4))[1];
            $_dbgOrigSsrc = unpack('N', substr($rtp, 8, 4))[1];
            $_dbgNewSsrc = unpack('N', substr($fwRtp, 8, 4))[1];
            $_dbgMarker = (ord($fwRtp[1]) >> 7) & 0x01;
            if ($_dbgMarker === 1) $_dbgTimeline['markers']++;
            $_dbgUnsignedDelta = $_dbgTimeline['prevTs'] === null ? null : (($_dbgTimestamp - $_dbgTimeline['prevTs']) & 0xFFFFFFFF);
            $_dbgSignedDelta = $_dbgUnsignedDelta === null ? null : ($_dbgUnsignedDelta > 0x7FFFFFFF ? $_dbgUnsignedDelta - 0x100000000 : $_dbgUnsignedDelta);
            $_dbgTimestampBackwards = $_dbgUnsignedDelta !== null && $_dbgUnsignedDelta > 0x80000000;
            $_dbgOutSeqExpected = $_dbgTimeline['prevOutSeq'] === null ? null : $_dbgOutSeq === (($_dbgTimeline['prevOutSeq'] + 1) & 0xFFFF);
            $_dbgB0 = ord($fwRtp[0]);
            $_dbgCc = $_dbgB0 & 0x0F;
            $_dbgPayloadOffset = 12 + (4 * $_dbgCc);
            $_dbgExtensionLength = 0;
            if (($_dbgB0 & 0x10) !== 0 && strlen($fwRtp) >= $_dbgPayloadOffset + 4) {
                $_dbgExtensionWords = unpack('n', substr($fwRtp, $_dbgPayloadOffset + 2, 2))[1];
                $_dbgExtensionLength = 4 * $_dbgExtensionWords;
                $_dbgPayloadOffset += 4 + $_dbgExtensionLength;
            }
            $_dbgPayloadLen = max(0, strlen($fwRtp) - $_dbgPayloadOffset);
            $_dbgNalType = $_dbgPayloadLen > 0 ? (ord($fwRtp[$_dbgPayloadOffset]) & 0x1F) : null;
            $_dbgFuType = null;
            $_dbgFuStart = null;
            $_dbgFuEnd = null;
            if ($_dbgNalType === 28 && $_dbgPayloadLen >= 2) {
                $_dbgFuHeader = ord($fwRtp[$_dbgPayloadOffset + 1]);
                $_dbgFuType = $_dbgFuHeader & 0x1F;
                $_dbgFuStart = (($_dbgFuHeader & 0x80) !== 0);
                $_dbgFuEnd = (($_dbgFuHeader & 0x40) !== 0);
            }
            $_dbgShouldReport = $_dbgTimeline['packets'] <= 3 || ($_dbgMarker === 1 && $_dbgTimeline['markers'] <= 3);
            if ($_dbgShouldReport) {
                $_dbgPayload = json_encode(['sessionId'=>'whep-zero-video','runId'=>'frozen-first-frame','hypothesisId'=>'G','location'=>'src/Core/UDP.php:protectAndSendRtp-before-protect','msg'=>'[DEBUG] Video RTP frame timeline','data'=>['clientId'=>$clientId,'sample'=>(int)$_dbgTimeline['packets'],'origSeq'=>(int)$_dbgOrigSeq,'outSeq'=>(int)$_dbgOutSeq,'timestamp'=>(int)$_dbgTimestamp,'timestampDeltaSigned'=>$_dbgSignedDelta,'timestampDeltaUnsigned'=>$_dbgUnsignedDelta,'marker'=>(int)$_dbgMarker,'originalSsrc'=>(int)$_dbgOrigSsrc,'newSsrc'=>(int)$_dbgNewSsrc,'extensionLength'=>(int)$_dbgExtensionLength,'payloadOffset'=>(int)$_dbgPayloadOffset,'payloadLen'=>(int)$_dbgPayloadLen,'nalType'=>$_dbgNalType,'fuType'=>$_dbgFuType,'fuStart'=>$_dbgFuStart,'fuEnd'=>$_dbgFuEnd,'timestampBackwards'=>$_dbgTimestampBackwards,'outSeqExpected'=>$_dbgOutSeqExpected],'ts'=>(int)(microtime(true)*1000)]);
                $this->_udpDbgHttpPost($_dbgPayload);
            }
            $_dbgTimeline['prevTs'] = $_dbgTimestamp;
            $_dbgTimeline['prevOutSeq'] = $_dbgOutSeq;
            unset($_dbgTimeline);
        }

        if ($kind === 'video') {
            static $_dbgVideoSummary = [];
            if (!isset($_dbgVideoSummary[$clientId])) {
                $_dbgVideoSummary[$clientId] = ['packets'=>0,'timestamps'=>[],'markers'=>0,'timestampBackwards'=>0,'seqGaps'=>0,'firstTs'=>null,'lastTs'=>null,'prevTs'=>null,'prevOutSeq'=>null];
            }
            $_dbgSummary = &$_dbgVideoSummary[$clientId];
            $_dbgSummaryTs = unpack('N', substr($fwRtp, 4, 4))[1];
            $_dbgSummaryOutSeq = unpack('n', substr($fwRtp, 2, 2))[1];
            $_dbgSummaryMarker = (ord($fwRtp[1]) >> 7) & 0x01;
            $_dbgSummary['packets']++;
            $_dbgSummary['timestamps'][(string)$_dbgSummaryTs] = true;
            $_dbgSummary['markers'] += $_dbgSummaryMarker;
            if ($_dbgSummary['firstTs'] === null) $_dbgSummary['firstTs'] = $_dbgSummaryTs;
            if ($_dbgSummary['prevTs'] !== null && ((($_dbgSummaryTs - $_dbgSummary['prevTs']) & 0xFFFFFFFF) > 0x80000000)) $_dbgSummary['timestampBackwards']++;
            if ($_dbgSummary['prevOutSeq'] !== null && $_dbgSummaryOutSeq !== (($_dbgSummary['prevOutSeq'] + 1) & 0xFFFF)) $_dbgSummary['seqGaps']++;
            $_dbgSummary['lastTs'] = $_dbgSummaryTs;
            $_dbgSummary['prevTs'] = $_dbgSummaryTs;
            $_dbgSummary['prevOutSeq'] = $_dbgSummaryOutSeq;
            if ($_dbgSummary['packets'] === 500) {
                $_dbgPayload = json_encode(['sessionId'=>'whep-zero-video','runId'=>'frozen-first-frame','hypothesisId'=>'H','location'=>'src/Core/UDP.php:protectAndSendRtp-before-protect','msg'=>'[DEBUG] Video RTP frame summary','data'=>['clientId'=>$clientId,'packetCount'=>(int)$_dbgSummary['packets'],'distinctTimestampCount'=>count($_dbgSummary['timestamps']),'markerCount'=>(int)$_dbgSummary['markers'],'timestampBackwardsCount'=>(int)$_dbgSummary['timestampBackwards'],'seqGapCount'=>(int)$_dbgSummary['seqGaps'],'firstTs'=>(int)$_dbgSummary['firstTs'],'lastTs'=>(int)$_dbgSummary['lastTs']],'ts'=>(int)(microtime(true)*1000)]);
                $this->_udpDbgHttpPost($_dbgPayload);
                $_dbgVideoSummary[$clientId] = ['packets'=>0,'timestamps'=>[],'markers'=>0,'timestampBackwards'=>0,'seqGaps'=>0,'firstTs'=>null,'lastTs'=>null,'prevTs'=>$_dbgSummaryTs,'prevOutSeq'=>$_dbgSummaryOutSeq];
            }
            unset($_dbgSummary);
        }

        if ($kind === 'audio' || $kind === 'video') {
            static $_dbgRtpExtmapRouteCount = [];
            $_dbgRouteKey = $clientId . ':' . $kind;
            $_dbgRtpExtmapRouteCount[$_dbgRouteKey] = (int)($_dbgRtpExtmapRouteCount[$_dbgRouteKey] ?? 0);
            if ($_dbgRtpExtmapRouteCount[$_dbgRouteKey] < 1) {
                $_dbgRtpExtmapRouteCount[$_dbgRouteKey]++;
                $_dbgB0 = ord($fwRtp[0]);
                $_dbgCc = $_dbgB0 & 0x0F;
                $_dbgHasExtension = (($_dbgB0 & 0x10) !== 0);
                $_dbgExtOffset = 12 + (4 * $_dbgCc);
                $_dbgProfile = null;
                $_dbgWordLength = null;
                $_dbgElements = [];
                if ($_dbgHasExtension && strlen($fwRtp) >= $_dbgExtOffset + 4) {
                    $_dbgProfile = unpack('n', substr($fwRtp, $_dbgExtOffset, 2))[1];
                    $_dbgWordLength = unpack('n', substr($fwRtp, $_dbgExtOffset + 2, 2))[1];
                    $_dbgExtData = substr($fwRtp, $_dbgExtOffset + 4, $_dbgWordLength * 4);
                    if ($_dbgProfile === 0xBEDE) {
                        $_dbgElementOffset = 0;
                        $_dbgExtDataLen = strlen($_dbgExtData);
                        while ($_dbgElementOffset < $_dbgExtDataLen) {
                            $_dbgElementHeader = ord($_dbgExtData[$_dbgElementOffset++]);
                            if ($_dbgElementHeader === 0) continue;
                            $_dbgElementId = ($_dbgElementHeader >> 4) & 0x0F;
                            if ($_dbgElementId === 15) break;
                            $_dbgElementLen = ($_dbgElementHeader & 0x0F) + 1;
                            $_dbgElementData = substr($_dbgExtData, $_dbgElementOffset, $_dbgElementLen);
                            $_dbgElementOffset += $_dbgElementLen;
                            $_dbgAscii = '';
                            for ($_dbgAsciiOffset = 0; $_dbgAsciiOffset < strlen($_dbgElementData); $_dbgAsciiOffset++) {
                                $_dbgAsciiByte = ord($_dbgElementData[$_dbgAsciiOffset]);
                                $_dbgAscii .= ($_dbgAsciiByte >= 0x20 && $_dbgAsciiByte <= 0x7E) ? chr($_dbgAsciiByte) : '.';
                            }
                            $_dbgElements[] = ['id'=>$_dbgElementId,'len'=>strlen($_dbgElementData),'dataHex'=>bin2hex($_dbgElementData),'ascii'=>$_dbgAscii];
                            if (strlen($_dbgElementData) < $_dbgElementLen) break;
                        }
                    }
                }

                $_dbgTargetMid = '';
                $_dbgTargetDirection = '';
                $_dbgExtmaps = [];
                $_dbgMidExtmaps = [];
                $_dbgRemoteOfferSdp = (string)($c['remoteOfferSdp'] ?? '');
                $_dbgSections = preg_split('/(?=^m=)/m', $_dbgRemoteOfferSdp, -1, PREG_SPLIT_NO_EMPTY);
                foreach ($_dbgSections as $_dbgSection) {
                    if (!preg_match('/^m=' . preg_quote($kind, '/') . '\\s+/m', $_dbgSection)) continue;
                    preg_match('/^a=(sendonly|recvonly|sendrecv|inactive)\\s*$/m', $_dbgSection, $_dbgDirectionMatch);
                    $_dbgDirection = $_dbgDirectionMatch[1] ?? 'sendrecv';
                    if ($_dbgDirection !== 'recvonly' && $_dbgDirection !== 'sendrecv') continue;
                    preg_match('/^a=mid:([^\\r\\n]+)$/m', $_dbgSection, $_dbgMidMatch);
                    $_dbgTargetMid = trim($_dbgMidMatch[1] ?? '');
                    $_dbgTargetDirection = $_dbgDirection;
                    if (preg_match_all('/^a=extmap:(\\d+)(?:\\/([^\\s]+))?\\s+([^\\s\\r\\n]+)/m', $_dbgSection, $_dbgExtmapMatches, PREG_SET_ORDER)) {
                        foreach ($_dbgExtmapMatches as $_dbgExtmapMatch) {
                            $_dbgExtmap = ['id'=>(int)$_dbgExtmapMatch[1],'uri'=>(string)$_dbgExtmapMatch[3]];
                            if (!empty($_dbgExtmapMatch[2])) $_dbgExtmap['direction'] = (string)$_dbgExtmapMatch[2];
                            $_dbgExtmaps[] = $_dbgExtmap;
                            if (stripos($_dbgExtmap['uri'], 'urn:ietf:params:rtp-hdrext:sdes:mid') !== false) $_dbgMidExtmaps[] = $_dbgExtmap;
                        }
                    }
                    break;
                }

                $_dbgPayload = json_encode(['sessionId'=>'whep-zero-video','runId'=>'post-timestamp-fix','hypothesisId'=>'F','location'=>'src/Core/UDP.php:protectAndSendRtp-before-protect','msg'=>'[DEBUG] RTP extension and WHEP extmap route','data'=>['clientId'=>$clientId,'kind'=>$kind,'sample'=>(int)$_dbgRtpExtmapRouteCount[$_dbgRouteKey],'hasExtension'=>$_dbgHasExtension,'profile'=>$_dbgProfile,'profileHex'=>$_dbgProfile === null ? null : sprintf('0x%04X', $_dbgProfile),'wordLength'=>$_dbgWordLength,'elements'=>$_dbgElements,'targetMid'=>$_dbgTargetMid,'targetDirection'=>$_dbgTargetDirection,'extmaps'=>$_dbgExtmaps,'sdesMidExtmaps'=>$_dbgMidExtmaps],'ts'=>(int)(microtime(true)*1000)]);
                $this->_udpDbgHttpPost($_dbgPayload);
            }
        }

        try {
            $_dbgPaddingB0 = ord($fwRtp[0]);
            $_dbgPaddingPBit = ($_dbgPaddingB0 >> 5) & 0x1;
            $_dbgPaddingCc = $_dbgPaddingB0 & 0x0F;
            $_dbgPaddingHdrLen = 12 + (4 * $_dbgPaddingCc);
            if ((($_dbgPaddingB0 >> 4) & 0x1) === 1 && strlen($fwRtp) >= $_dbgPaddingHdrLen + 4) {
                $_dbgPaddingExtWords = unpack('n', substr($fwRtp, $_dbgPaddingHdrLen + 2, 2))[1];
                $_dbgPaddingHdrLen += 4 + (4 * $_dbgPaddingExtWords);
            }
            $_dbgPaddingPktLen = strlen($fwRtp);
            $_dbgPaddingRawPayloadLen = $_dbgPaddingPktLen - $_dbgPaddingHdrLen;
            $_dbgPaddingLastByte = $_dbgPaddingPktLen > 0 ? ord($fwRtp[$_dbgPaddingPktLen - 1]) : null;
            $_dbgPaddingCount = $_dbgPaddingPBit === 1 ? $_dbgPaddingLastByte : 0;
            $_dbgPaddingValid = $_dbgPaddingPBit === 0 || ($_dbgPaddingCount !== null && $_dbgPaddingCount > 0 && $_dbgPaddingCount <= $_dbgPaddingRawPayloadLen);
            $_dbgPaddingEffectivePayloadLen = $_dbgPaddingValid ? ($_dbgPaddingRawPayloadLen - ($_dbgPaddingPBit === 1 ? $_dbgPaddingCount : 0)) : $_dbgPaddingRawPayloadLen;
            $_dbgPaddingRawNalType = $_dbgPaddingRawPayloadLen > 0 && $_dbgPaddingHdrLen >= 0 && $_dbgPaddingHdrLen < $_dbgPaddingPktLen ? (ord($fwRtp[$_dbgPaddingHdrLen]) & 0x1F) : null;
            if ($_dbgPaddingPBit === 1 && $_dbgPaddingValid && $_dbgPaddingEffectivePayloadLen === 0) {
                static $_dbgPurePaddingJ = [];
                $_dbgPaddingNow = microtime(true);
                if (!isset($_dbgPurePaddingJ[$clientId])) $_dbgPurePaddingJ[$clientId] = ['count'=>0,'immediate'=>0,'lastReport'=>$_dbgPaddingNow];
                $_dbgPurePaddingJ[$clientId]['count']++;
                $_dbgPaddingImmediate = $_dbgPurePaddingJ[$clientId]['immediate'] < 3;
                $_dbgPaddingPeriodic = !$_dbgPaddingImmediate && ($_dbgPaddingNow - $_dbgPurePaddingJ[$clientId]['lastReport']) >= 1.0;
                if ($_dbgPaddingImmediate || $_dbgPaddingPeriodic) {
                if ($_dbgPaddingImmediate) $_dbgPurePaddingJ[$clientId]['immediate']++;
                $_dbgPaddingOrigSeq = unpack('n', substr($rtp, 2, 2))[1];
                $_dbgPaddingOutSeq = unpack('n', substr($fwRtp, 2, 2))[1];
                $_dbgPaddingTimestamp = unpack('N', substr($fwRtp, 4, 4))[1];
                $_dbgPayload = json_encode(['sessionId'=>'whep-zero-video','runId'=>'post-srtcp-feedback-fix','hypothesisId'=>'J','location'=>'src/Core/UDP.php:subscriber-pure-padding','msg'=>'[DEBUG] Subscriber pure RTP padding sampled/aggregated','data'=>['clientId'=>$clientId,'kind'=>$kind,'aggregate'=>!$_dbgPaddingImmediate,'count'=>$_dbgPurePaddingJ[$clientId]['count'],'origSeq'=>(int)$_dbgPaddingOrigSeq,'outSeq'=>(int)$_dbgPaddingOutSeq,'timestamp'=>(int)$_dbgPaddingTimestamp,'paddingCount'=>$_dbgPaddingCount],'ts'=>(int)($_dbgPaddingNow*1000)]);
                $this->_udpDbgHttpPost($_dbgPayload);
                if ($_dbgPaddingPeriodic || ($_dbgPaddingImmediate && $_dbgPurePaddingJ[$clientId]['immediate'] === 3)) { $_dbgPurePaddingJ[$clientId]['count']=0; $_dbgPurePaddingJ[$clientId]['lastReport']=$_dbgPaddingNow; }
                }
            }
        } catch (\Throwable $_dbgPaddingError) {
        }

        $_dbgProtectStarted = $kind === 'video' ? hrtime(true) : 0;

        try {
            $srtpOut = $srtpTx->protect($fwRtp);
        } catch (\Throwable $e) {
            if ($kind === 'video' && method_exists($this, '_dbgPerfSubscriberVideo')) $this->_dbgPerfSubscriberVideo($clientId, 0, $_dbgRewriteNs, (int)(hrtime(true) - $_dbgProtectStarted), 0, false);
            $this->_log_std("Client {$clientId} protectAndSendRtp protect() FAIL: " . $e->getMessage() . "\n");
            return false;
        }
        if (!is_string($srtpOut) || strlen($srtpOut) === 0) {
            if ($kind === 'video' && method_exists($this, '_dbgPerfSubscriberVideo')) $this->_dbgPerfSubscriberVideo($clientId, 0, $_dbgRewriteNs, (int)(hrtime(true) - $_dbgProtectStarted), 0, false);
            $this->_log_std("Client {$clientId} protectAndSendRtp protect() FAIL: empty output\n");
            return false;
        }
        $_dbgProtectedAt = $kind === 'video' ? hrtime(true) : 0;
        $sent = $this->sendUDP($clientId, $srtpOut);
        if ($kind === 'video' && method_exists($this, '_dbgPerfSubscriberVideo')) {
            $_dbgSentAt = hrtime(true);
            $_obsOutSeq = unpack('n', substr($fwRtp, 2, 2))[1];
            $_obsOutTimestamp = unpack('N', substr($fwRtp, 4, 4))[1];
            $_obsOutMarker = (ord($fwRtp[1]) >> 7) & 1;
            $this->_dbgPerfSubscriberVideo($clientId, strlen($srtpOut), $_dbgRewriteNs, (int)($_dbgProtectedAt - $_dbgProtectStarted), (int)($_dbgSentAt - $_dbgProtectedAt), (bool)$sent, $_obsOutSeq, $_obsOutTimestamp, $_obsOutMarker);
        }

        if ($kind === 'video') {
            static $_dbgVideoSendCount = [];
            $_dbgVideoSendCount[$clientId] = (int)($_dbgVideoSendCount[$clientId] ?? 0);
            if ($_dbgVideoSendCount[$clientId] < 1) {
                $_dbgVideoSendCount[$clientId]++;
                $_dbgRc = is_array($c['remoteCandidate'] ?? null) ? $c['remoteCandidate'] : [];
                $_dbgSeq = unpack('n', substr($fwRtp, 2, 2))[1];
                $_dbgSsrc = unpack('N', substr($fwRtp, 8, 4))[1];
                $_dbgPayload = json_encode(['sessionId'=>'whep-zero-video','runId'=>'pre-fix','hypothesisId'=>'C','location'=>'src/Core/UDP.php:protectAndSendRtp','msg'=>'[DEBUG] Video RTP protected and send attempted','data'=>['clientId'=>$clientId,'origPt'=>$origPT,'outPt'=>(ord($fwRtp[1]) & 0x7F),'outSsrc'=>(int)$_dbgSsrc,'outSeq'=>(int)$_dbgSeq,'destination'=>['ip'=>(string)($_dbgRc['ip'] ?? ''),'port'=>(int)($_dbgRc['port'] ?? 0)],'plainLen'=>strlen($fwRtp),'srtpLen'=>strlen($srtpOut),'sendOk'=>(bool)$sent,'sample'=>(int)$_dbgVideoSendCount[$clientId]],'ts'=>(int)(microtime(true)*1000)]);
                $this->_udpDbgHttpPost($_dbgPayload);
            }
        }
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
                $_dbgMetaL = is_array($c['meta'] ?? null) ? $c['meta'] : [];
                if (in_array(($_dbgMetaL['role'] ?? ''), ['push', 'play'], true)) {
                    static $_dbgSrtcpL = [];
                    $_dbgNowL = microtime(true);
                    if (!isset($_dbgSrtcpL[$targetClientId])) $_dbgSrtcpL[$targetClientId] = ['total'=>0,'ok'=>0,'fail'=>0,'rawPt'=>[],'plainPtFmt'=>[],'immediate'=>0,'lastReport'=>$_dbgNowL];
                    $_dbgStatsL = &$_dbgSrtcpL[$targetClientId];
                    $_dbgUnprotectOkL = is_string($plainRtcp) && strlen($plainRtcp) >= 8;
                    $_dbgRawPtL = strlen($data) >= 2 ? ord($data[1]) : -1;
                    $_dbgStatsL['total']++; $_dbgStatsL[$_dbgUnprotectOkL ? 'ok' : 'fail']++;
                    $_dbgStatsL['rawPt'][(string)$_dbgRawPtL] = (int)($_dbgStatsL['rawPt'][(string)$_dbgRawPtL] ?? 0) + 1;
                    $_dbgCompoundL = [];
                    if ($_dbgUnprotectOkL) {
                        for ($_dbgOffsetL=0, $_dbgPlainLenL=strlen($plainRtcp); ($_dbgOffsetL+4)<=$_dbgPlainLenL;) {
                            $_dbgPacketLenL = (unpack('n', substr($plainRtcp, $_dbgOffsetL+2, 2))[1]+1)*4;
                            if ($_dbgPacketLenL < 4 || ($_dbgOffsetL+$_dbgPacketLenL)>$_dbgPlainLenL) break;
                            $_dbgPtL=ord($plainRtcp[$_dbgOffsetL+1]); $_dbgFmtL=ord($plainRtcp[$_dbgOffsetL])&0x1F; $_dbgKeyL=$_dbgPtL . '/' . $_dbgFmtL;
                            $_dbgStatsL['plainPtFmt'][$_dbgKeyL]=(int)($_dbgStatsL['plainPtFmt'][$_dbgKeyL]??0)+1;
                            $_dbgCompoundL[]=['pt'=>$_dbgPtL,'fmt'=>$_dbgFmtL,'length'=>$_dbgPacketLenL]; $_dbgOffsetL += $_dbgPacketLenL;
                        }
                    }
                    $_dbgPeriodicL = ($_dbgNowL - $_dbgStatsL['lastReport']) >= 1.0;
                    if ($_dbgPeriodicL) {
                        $_dbgDataL=['clientId'=>$targetClientId,'role'=>(string)($_dbgMetaL['role']??''),'streamId'=>(string)($_dbgMetaL['streamId']??''),'aggregate'=>true,'total'=>$_dbgStatsL['total'],'unprotectOk'=>$_dbgStatsL['ok'],'unprotectFail'=>$_dbgStatsL['fail'],'rawPtDistribution'=>$_dbgStatsL['rawPt'],'decryptedPtFmtDistribution'=>$_dbgStatsL['plainPtFmt']];
                        $_dbgPayloadL=json_encode(['sessionId'=>'whep-zero-video','runId'=>'post-srtcp-feedback-fix','hypothesisId'=>'L','location'=>'src/Core/UDP.php:srtcp-unprotect','msg'=>'[DEBUG] Publisher/subscriber SRTCP 1s aggregate','data'=>$_dbgDataL,'ts'=>(int)($_dbgNowL*1000)]);
                        $this->_udpDbgHttpPost($_dbgPayloadL);
                        $_dbgSrtcpL[$targetClientId]=['total'=>0,'ok'=>0,'fail'=>0,'rawPt'=>[],'plainPtFmt'=>[],'immediate'=>0,'lastReport'=>$_dbgNowL];
                    }
                    unset($_dbgStatsL);
                }

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

                $_dbgUnprotectStarted = hrtime(true);
                $plainRtp = $srtpRx->unprotect($data);
                $_dbgUnprotectNs = (int)(hrtime(true) - $_dbgUnprotectStarted);

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

            $_dbgMeta = is_array($c['meta'] ?? null) ? $c['meta'] : [];
            $_dbgIsPublisherVideo = (($_dbgMeta['role'] ?? '') === 'push')
                && (isset($c['videoPTs'][$pt])
                    || (int)($c['incomingSsrcByKind']['video'] ?? 0) === $ssrcVal
                    || !isset($c['audioPTs'][$pt]));
            if ($_dbgIsPublisherVideo) {
                static $_obsInbound = [];
                $_obsNow = microtime(true);
                $_obsKey = $targetClientId . ':' . $ssrcVal;
                if (!isset($_obsInbound[$_obsKey])) {
                    $_obsInbound[$_obsKey] = ['lastReportAt'=>$_obsNow,'packetCount'=>0,'bytes'=>0,'markerCount'=>0,'distinctTimestamp'=>0,'gapEvents'=>0,'estimatedLost'=>0,'duplicate'=>0,'outOfOrder'=>0,'firstSeq'=>null,'lastSeq'=>null,'firstTs'=>null,'lastTs'=>null,'previousSeq'=>null,'previousTs'=>null,'completedFrames'=>0,'framesWithoutMarker'=>0,'fuStartWithoutEnd'=>0,'fuEndWithoutStart'=>0,'fuSequenceGap'=>0,'idrFrames'=>0,'sps'=>0,'pps'=>0,'nalTypes'=>[],'frame'=>null];
                }
                $_obs = &$_obsInbound[$_obsKey];
                $_obs['packetCount']++; $_obs['bytes'] += strlen($plainRtp); $_obs['markerCount'] += ($b1 >> 7) & 1;
                if ($_obs['firstSeq'] === null) { $_obs['firstSeq']=$seq; $_obs['firstTs']=$ts; }
                if ($_obs['previousTs'] === null || $_obs['previousTs'] !== $ts) $_obs['distinctTimestamp']++;
                if ($_obs['previousSeq'] !== null) {
                    $_obsSeqDelta = (($seq - (int)$_obs['previousSeq'] + 0x8000) & 0xFFFF) - 0x8000;
                    if ($_obsSeqDelta > 1) { $_obs['gapEvents']++; $_obs['estimatedLost'] += $_obsSeqDelta - 1; }
                    elseif ($_obsSeqDelta === 0) $_obs['duplicate']++;
                    elseif ($_obsSeqDelta < 0) $_obs['outOfOrder']++;
                }
                $_obsB0 = ord($plainRtp[0]); $_obsPacketLen = strlen($plainRtp); $_obsPayloadOffset = 12 + 4 * ($_obsB0 & 0x0F); $_obsPayloadValid = $_obsPayloadOffset <= $_obsPacketLen;
                if (($_obsB0 & 0x10) !== 0) {
                    if ($_obsPayloadOffset + 4 <= $_obsPacketLen) { $_obsExtWords=unpack('n', substr($plainRtp,$_obsPayloadOffset+2,2))[1]; $_obsPayloadOffset += 4 + 4*$_obsExtWords; }
                    else $_obsPayloadValid=false;
                }
                $_obsPadding = 0;
                if (($_obsB0 & 0x20) !== 0 && $_obsPacketLen > $_obsPayloadOffset) { $_obsPadding=ord($plainRtp[$_obsPacketLen-1]); if ($_obsPadding <= 0 || $_obsPadding > ($_obsPacketLen-$_obsPayloadOffset)) $_obsPayloadValid=false; }
                $_obsPayloadLen = $_obsPayloadValid ? $_obsPacketLen - $_obsPayloadOffset - $_obsPadding : 0;
                if ($_obs['frame'] !== null && (int)$_obs['frame']['ts'] !== $ts) {
                    if (empty($_obs['frame']['marker'])) $_obs['framesWithoutMarker']++;
                    if (!empty($_obs['frame']['fuOpen'])) $_obs['fuStartWithoutEnd']++;
                    $_obs['frame'] = null;
                }
                if ($_obs['frame'] === null) $_obs['frame']=['ts'=>$ts,'marker'=>false,'fuOpen'=>false,'fuType'=>null,'fuLastSeq'=>null,'idr'=>false];
                if ($_obsPayloadLen > 0) {
                    $_obsNalType=ord($plainRtp[$_obsPayloadOffset])&0x1F; $_obs['nalTypes'][(string)$_obsNalType]=(int)($_obs['nalTypes'][(string)$_obsNalType]??0)+1;
                    $_obsNalList=[$_obsNalType];
                    if ($_obsNalType === 24) { $_obsNalList=[]; for ($_obsP=$_obsPayloadOffset+1,$_obsEnd=$_obsPayloadOffset+$_obsPayloadLen; $_obsP+2<=$_obsEnd;) { $_obsSz=unpack('n',substr($plainRtp,$_obsP,2))[1]; $_obsP+=2; if ($_obsSz<=0||$_obsP+$_obsSz>$_obsEnd) break; $_obsInner=ord($plainRtp[$_obsP])&0x1F; $_obsNalList[]=$_obsInner; $_obs['nalTypes'][(string)$_obsInner]=(int)($_obs['nalTypes'][(string)$_obsInner]??0)+1; $_obsP+=$_obsSz; } }
                    if ($_obsNalType === 28 && $_obsPayloadLen >= 2) {
                        $_obsFu=ord($plainRtp[$_obsPayloadOffset+1]); $_obsFuType=$_obsFu&0x1F; $_obsFuStart=($_obsFu&0x80)!==0; $_obsFuEnd=($_obsFu&0x40)!==0;
                        if ($_obsFuStart) { if (!empty($_obs['frame']['fuOpen'])) $_obs['fuStartWithoutEnd']++; $_obs['frame']['fuOpen']=true; $_obs['frame']['fuType']=$_obsFuType; }
                        elseif (!$_obsFuEnd && empty($_obs['frame']['fuOpen'])) $_obs['fuEndWithoutStart']++;
                        if ($_obs['frame']['fuLastSeq'] !== null) { $_obsFuDelta=(($seq-(int)$_obs['frame']['fuLastSeq']+0x8000)&0xFFFF)-0x8000; if ($_obsFuDelta>1) $_obs['fuSequenceGap']++; }
                        $_obs['frame']['fuLastSeq']=$seq; if ($_obsFuEnd) { if (empty($_obs['frame']['fuOpen'])) $_obs['fuEndWithoutStart']++; $_obs['frame']['fuOpen']=false; } $_obsNalList=[$_obsFuType];
                    }
                    foreach ($_obsNalList as $_obsType) { if ($_obsType===5) $_obs['frame']['idr']=true; elseif ($_obsType===7) $_obs['sps']++; elseif ($_obsType===8) $_obs['pps']++; }
                }
                if ((($b1 >> 7) & 1) === 1) { $_obs['completedFrames']++; $_obs['frame']['marker']=true; if (!empty($_obs['frame']['fuOpen'])) $_obs['fuStartWithoutEnd']++; if (!empty($_obs['frame']['idr'])) $_obs['idrFrames']++; $_obs['frame']=null; }
                $_obs['lastSeq']=$seq; $_obs['lastTs']=$ts; $_obs['previousSeq']=$seq; $_obs['previousTs']=$ts;
                if (($_obsNow-(float)$_obs['lastReportAt'])>=1.0) {
                    $_obsData=$_obs; unset($_obsData['frame'],$_obsData['previousSeq'],$_obsData['previousTs'],$_obsData['lastReportAt']); $_obsData += ['clientId'=>(int)$targetClientId,'streamId'=>(string)($_dbgMeta['streamId']??''),'ssrc'=>(int)$ssrcVal,'pt'=>(int)$pt,'fps'=>(int)$_obs['markerCount'],'intervalMs'=>(int)(($_obsNow-(float)$_obs['lastReportAt'])*1000)];
                    $this->_udpDbgHttpPost(json_encode(['sessionId'=>'obs-media-pixelation','runId'=>'pre-rr-gap-analysis','hypothesisId'=>'publisher-gap-h264','location'=>'src/Core/UDP.php:publisher-video-inbound','msg'=>'[DEBUG] Publisher video/H264 1s aggregate','data'=>$_obsData,'ts'=>(int)($_obsNow*1000)]),'obs-media-pixelation');
                    $_obsFrame=$_obs['frame']; $_obsPrevSeq=$_obs['previousSeq']; $_obsPrevTs=$_obs['previousTs']; $_obsInbound[$_obsKey]=['lastReportAt'=>$_obsNow,'packetCount'=>0,'bytes'=>0,'markerCount'=>0,'distinctTimestamp'=>0,'gapEvents'=>0,'estimatedLost'=>0,'duplicate'=>0,'outOfOrder'=>0,'firstSeq'=>null,'lastSeq'=>null,'firstTs'=>null,'lastTs'=>null,'previousSeq'=>$_obsPrevSeq,'previousTs'=>$_obsPrevTs,'completedFrames'=>0,'framesWithoutMarker'=>0,'fuStartWithoutEnd'=>0,'fuEndWithoutStart'=>0,'fuSequenceGap'=>0,'idrFrames'=>0,'sps'=>0,'pps'=>0,'nalTypes'=>[],'frame'=>$_obsFrame];
                }
                unset($_obs);
            }

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
                if (isset($_dbgUnprotectNs) && method_exists($this, '_dbgPerfPipelineStage')) {
                    $this->_dbgPerfPipelineStage((string)$meta['streamId'], 'publisherUnprotect', (int)$_dbgUnprotectNs, strlen($data), 0);
                }
                $_dbgForwardStarted = hrtime(true);

                $_dbgKindMedia = isset($c['videoPTs'][$pt]) ? 'video' : (isset($c['audioPTs'][$pt]) ? 'audio' : 'unknown');
                if (method_exists($this, '_dbgPerfPublisherInbound')) $this->_dbgPerfPublisherInbound((int)$targetClientId, (string)$meta['streamId'], $_dbgKindMedia, strlen($plainRtp), (int)$ts, (int)$seq, ($b1 >> 7) & 1);
                $n = $this->forwardRtpToAllSubscribers((string)$meta['streamId'], $plainRtp, $targetClientId);
                if (method_exists($this, '_dbgPerfPipelineStage')) {
                    $this->_dbgPerfPipelineStage((string)$meta['streamId'], 'forwardTotal', (int)(hrtime(true) - $_dbgForwardStarted), strlen($plainRtp), (int)$n);
                }
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
