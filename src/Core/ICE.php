<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose ICE寻路系统
 * @author yanglong
 */
trait ICE
{
    /**
     * 内部 helper：若首个 SRTP 包成功，触发 onMediaConnected（只触发一次/client）
     */
    public function _notifyMediaConnectedIfFirst(int $clientId, array $parsedRtpHeader): void
    {
        if (empty($this->clients[$clientId]['_mediaConnectedFired'])) {
            $this->clients[$clientId]['_mediaConnectedFired'] = true;
            if (isset($this->onMediaConnected) && is_callable($this->onMediaConnected)) {
                try {
                    $_cb = $this->onMediaConnected;
                    $_cb($clientId, $parsedRtpHeader, $this);
                } catch (\Throwable $e) {
                    $this->_log_std("Client {$clientId} onMediaConnected exception: " . $e->getMessage() . "\n");
                }
            }
        }
    }

    /**
     * 处理浏览器发来的 SDP offer，生成 answer 并回传
     * @param int $clientId
     * @param array $offer {type, sdp}
     * @return void
     */
    private function handleOffer($clientId, $offer)
    {
        $sdp = (string)($offer['sdp'] ?? '');
        if ($sdp === '') {
            $this->_log_std("Client {$clientId} handleOffer: empty sdp, skip\n");
            return;
        }
        $this->_log_std("Client {$clientId} Received SDP Offer (len=" . strlen($sdp) . ")\n");

        $remoteIceUfrag = $this->extractSdpAttribute($sdp, 'ice-ufrag');
        $remoteIcePwd   = $this->extractSdpAttribute($sdp, 'ice-pwd');
        $remoteSetup    = $this->extractSdpAttribute($sdp, 'setup');
        $this->_log_std("Client {$clientId} remote ufrag={$remoteIceUfrag} pwd={$remoteIcePwd} setup={$remoteSetup}\n");

        $this->clients[$clientId]['remoteIceUfrag'] = $remoteIceUfrag;
        $this->clients[$clientId]['remoteIcePwd']   = $remoteIcePwd;

        $answerInfo = $this->generateAnswerSDP($sdp, $remoteIceUfrag, $remoteIcePwd, $remoteSetup, ['forceVideoAudioDefault' => false]);

        $localUfrag = (string)($answerInfo['ice-ufrag'] ?? '');
        $localPwd   = (string)($answerInfo['ice-pwd']   ?? '');
        $localSdp   = (string)($answerInfo['sdp']       ?? '');
        if ($localUfrag === '' || $localSdp === '') {
            $this->_log_std("Client {$clientId} handleOffer: generateAnswerSDP returned empty! ABORT.\n");
            return;
        }

        $this->clients[$clientId]['localIceUfrag'] = $localUfrag;
        $this->clients[$clientId]['localIcePwd']   = $localPwd;
        $this->clients[$clientId]['iceUfrag']      = $localUfrag;
        $this->clients[$clientId]['icePwd']        = $localPwd;
        $this->clients[$clientId]['remoteIcePwdForSTUN'] = $remoteIcePwd;

        $this->clients[$clientId]['videoPTs']        = isset($answerInfo['videoPTs']) && is_array($answerInfo['videoPTs']) ? $answerInfo['videoPTs'] : [];
        $this->clients[$clientId]['audioPTs']        = isset($answerInfo['audioPTs']) && is_array($answerInfo['audioPTs']) ? $answerInfo['audioPTs'] : [];
        $this->clients[$clientId]['serverVideoSsrc'] = (int)($answerInfo['serverVideoSsrc'] ?? 4147483647);
        $this->clients[$clientId]['serverAudioSsrc'] = (int)($answerInfo['serverAudioSsrc'] ?? 3741943039);
        $this->clients[$clientId]['serverSsrc']      = $this->clients[$clientId]['serverVideoSsrc']; // 兼容名
        $this->clients[$clientId]['localSsrcByKind'] = isset($answerInfo['localSsrcByKind']) && is_array($answerInfo['localSsrcByKind']) ? $answerInfo['localSsrcByKind'] : [
            'video' => $this->clients[$clientId]['serverVideoSsrc'],
            'audio' => $this->clients[$clientId]['serverAudioSsrc'],
        ];

        if (!empty($answerInfo['videoPTs']) && is_array($answerInfo['videoPTs'])) {
            $pvSmart = $this->_pickRealPrimaryPT($answerInfo['videoPTs'], 'video');
            if ($pvSmart > 0 && isset($answerInfo['videoPTs'][$pvSmart])) {
                $this->clients[$clientId]['primaryVideoPT'] = $pvSmart;
            } else {
                $vpts = array_keys($answerInfo['videoPTs']);
                $this->clients[$clientId]['primaryVideoPT'] = (int)($vpts[0] ?? 0);
            }
            $this->clients[$clientId]['videoPTs'] = $this->_reorderPTsForSubscriber(
                is_array($this->clients[$clientId]['videoPTs']) ? $this->clients[$clientId]['videoPTs'] : [],
                (int)$this->clients[$clientId]['primaryVideoPT']
            );
        }
        if (!empty($answerInfo['audioPTs']) && is_array($answerInfo['audioPTs'])) {
            $paSmart = $this->_pickRealPrimaryPT($answerInfo['audioPTs'], 'audio');
            if ($paSmart > 0 && isset($answerInfo['audioPTs'][$paSmart])) {
                $this->clients[$clientId]['primaryAudioPT'] = $paSmart;
            } else {
                $apts = array_keys($answerInfo['audioPTs']);
                $this->clients[$clientId]['primaryAudioPT'] = (int)($apts[0] ?? 0);
            }
            $this->clients[$clientId]['audioPTs'] = $this->_reorderPTsForSubscriber(
                is_array($this->clients[$clientId]['audioPTs']) ? $this->clients[$clientId]['audioPTs'] : [],
                (int)$this->clients[$clientId]['primaryAudioPT']
            );
        }
        $this->_log_std("Client {$clientId} PT map: videoPTs=" . json_encode(array_keys($this->clients[$clientId]['videoPTs'])) .
            " audioPTs=" . json_encode(array_keys($this->clients[$clientId]['audioPTs'])) .
            " videoSSRC={$this->clients[$clientId]['serverVideoSsrc']} audioSSRC={$this->clients[$clientId]['serverAudioSsrc']}" .
            " primaryV=" . ($this->clients[$clientId]['primaryVideoPT'] ?? '?') .
            " primaryA=" . ($this->clients[$clientId]['primaryAudioPT'] ?? '?') . "\n");

        $answerMsg = json_encode(['type' => 'answer', 'sdp' => $localSdp], JSON_UNESCAPED_SLASHES);
        $socket = $this->clients[$clientId]['socket'] ?? null;
        if (is_resource($socket)) {
            $ok = $this->sendWebSocketText($socket, $answerMsg);
            $this->_log_std("Client {$clientId} Sent SDP Answer (len=" . strlen($localSdp) . ", wsSend=" . ($ok ? 'ok' : 'FAIL') . ")\n");
        } else {
            $this->_log_std("Client {$clientId} handleOffer: WebSocket socket lost! Cannot send answer.\n");
        }

        $this->clients[$clientId]['remoteOfferSdp'] = $sdp;

        if (isset($this->onOffer) && is_callable($this->onOffer)) {
            try {
                $_cb = $this->onOffer;
                $_cb($clientId, $sdp, $localSdp, $this);
            } catch (\Throwable $e) {
                $this->_log_std("Client {$clientId} onOffer exception: " . $e->getMessage() . "\n");
            }
        }

        $role = (string)$this->getClientMeta($clientId, 'role', '');
        if ($role === 'push' && isset($this->onPublisher) && is_callable($this->onPublisher)) {
            try {
                $_cb = $this->onPublisher;
                $_cb($clientId, [
                    'streamId'   => (string)$this->getClientMeta($clientId, 'streamId', ''),
                    'localSsrc'  => $this->clients[$clientId]['localSsrcByKind'] ?? [],
                    'videoPTs'   => $this->clients[$clientId]['videoPTs'] ?? [],
                    'audioPTs'   => $this->clients[$clientId]['audioPTs'] ?? [],
                ], $this);
            } catch (\Throwable $e) {
                $this->_log_std("Client {$clientId} onPublisher exception: " . $e->getMessage() . "\n");
            }
        }

        if ($role === 'push') {
            $streamId = (string)$this->getClientMeta($clientId, 'streamId', '');
            $pv = (int)($this->clients[$clientId]['primaryVideoPT'] ?? 0);
            $pa = (int)($this->clients[$clientId]['primaryAudioPT'] ?? 0);
            $vPTs = $this->_reorderPTsForSubscriber(
                is_array($this->clients[$clientId]['videoPTs'] ?? []) ? $this->clients[$clientId]['videoPTs'] : [],
                $pv
            );
            $aPTs = $this->_reorderPTsForSubscriber(
                is_array($this->clients[$clientId]['audioPTs'] ?? []) ? $this->clients[$clientId]['audioPTs'] : [],
                $pa
            );
            $cfg = [
                'createdAt'         => microtime(true),
                'publisherId'       => (int)$clientId,
                'videoPTs'          => $vPTs,
                'audioPTs'          => $aPTs,
                'primaryVideoPT'    => $pv,
                'primaryAudioPT'    => $pa,
                'serverVideoSsrc'   => (int)($this->clients[$clientId]['serverVideoSsrc'] ?? (0x80000000 | mt_rand(1, 0x7FFFFFFF))),
                'serverAudioSsrc'   => (int)($this->clients[$clientId]['serverAudioSsrc'] ?? (0x80000000 | mt_rand(1, 0x7FFFFFFF))),
                'msidStreamId'      => 'sfu-' . $streamId . '-' . substr(bin2hex(random_bytes(6)), 0, 12),
                'msidVideoTrackId'  => 'sfu-vid-' . $streamId . '-' . substr(bin2hex(random_bytes(6)), 0, 12),
                'msidAudioTrackId'  => 'sfu-aud-' . $streamId . '-' . substr(bin2hex(random_bytes(6)), 0, 12),
                'cname'             => 'sfu-cname-' . $streamId,
                'originalOfferSdp'  => $sdp,
            ];

            if (isset($this->_sfuStreamConfig[$streamId]) && is_array($this->_sfuStreamConfig[$streamId])) {
                $old = $this->_sfuStreamConfig[$streamId];
                $cfg['serverVideoSsrc']  = (int)($old['serverVideoSsrc']  ?? $cfg['serverVideoSsrc']);
                $cfg['serverAudioSsrc']  = (int)($old['serverAudioSsrc']  ?? $cfg['serverAudioSsrc']);
                $cfg['msidStreamId']     = (string)($old['msidStreamId']    ?? $cfg['msidStreamId']);
                $cfg['msidVideoTrackId'] = (string)($old['msidVideoTrackId'] ?? $cfg['msidVideoTrackId']);
                $cfg['msidAudioTrackId'] = (string)($old['msidAudioTrackId'] ?? $cfg['msidAudioTrackId']);
                $cfg['cname']            = (string)($old['cname']           ?? $cfg['cname']);
            }
            $this->_sfuStreamConfig[$streamId] = $cfg;
            $this->_log_std("[_sfuStreamConfig 生成/刷新] streamId={$streamId} publisherId={$clientId}"
                . " primaryV={$pv} primaryA={$pa}"
                . " videoPTs=" . json_encode(array_keys($vPTs))
                . " audioPTs=" . json_encode(array_keys($aPTs))
                . " vSSRC={$cfg['serverVideoSsrc']} aSSRC={$cfg['serverAudioSsrc']}"
                . " cname={$cfg['cname']}"
                . " msidStreamId={$cfg['msidStreamId']}\n");

            $this->_defaultSfuRelayPublisherOfferToSubscribers($clientId, $sdp);
        }
    }

    /**
     * 缺省 SFU：当 push 端 answer 完成后，向同 streamId 的 play 端批量 offer（play.html 会收到 offer → answer）
     * - 订阅者（play 端） receive-only，我们用 push 端 offer 的音视频 PT 和 SSRC 重写为 play 端的 serverVideoSsrc/serverAudioSsrc
     *   然后调用 generateAnswerSDP 生成 SFU -> play 端的 Answer SDP？其实 SFU 是向 play 端发送 Offer，让 play 端 Answer。
     *   SDP trait 有 generateAnswerSDP（远端 offer → 本端 answer）；
     *   对 play 端 → SFU 需要 SFU 自己构造 Offer 给 play 端；为了避免改 SDP trait 太复杂，
     *   我们把 push 端的 remoteOfferSdp 直接转交给 onSubscriber，由想实现 SFU 的高级用户在 onSubscriber 中自行构造。
     *   本默认保持无侵入（不修改 push.html/play.html 现有代码）：
     *     - 当 play 端 join 时如果 push 端已 ready，触发 onSubscriber 后即可做定制处理；
     *     - SRTP 层走 forwardRtpToAllSubscribers() 自动重写 SSRC protect 分发；
     *   也就是说：SDP 里 SSRC 不一致的浏览器严格校验场景由用户在 onSubscriber/onPublisher/onOffer 中接管，
     *   不接管的情况下本服务的核心转发（SRTP protect 改写）是完全可用的。
     *
     * 这里保留函数入口，后续扩展完整 SFU Offer 生成逻辑时可直接填充。
     *
     * @codeCoverageIgnore 高级实现占位
     */
    private function _defaultSfuRelayPublisherOfferToSubscribers(int $pushId, string $pushOfferSdp): void
    {
        $streamId = (string)$this->getClientMeta($pushId, 'streamId', '');
        $playIds = array_values(array_filter(
            $this->getClientsByMeta('streamId', $streamId),
            function ($id) { return (string)$this->getClientMeta((int)$id, 'role', '') === 'play'; }
        ));
        if (count($playIds) > 0) {
            $this->_log_std("Client {$pushId} (push,streamId={$streamId}) publisher ready. Existing subscriber count: " . count($playIds) . " (onOffer/onPublisher callbacks may relay offer)\n");
        }
    }

    /**
     * 处理浏览器发来的 ICE candidate
     * @param int $clientId
     * @param array $candidate {type, candidate, sdpMid?, sdpMLineIndex?}
     * @return void
     */
    private function handleCandidate($clientId, $candidate)
    {
        $iceCandidate = (string)($candidate['candidate'] ?? '');
        if ($iceCandidate === '') return;

        $this->_log_std("Client {$clientId} Received candidate: {$iceCandidate}\n");

        if (stripos($iceCandidate, ' tcp ') !== false || stripos($iceCandidate, 'tcptype') !== false) {
            $this->_log_std("Client {$clientId} SKIP TCP candidate (transport=tcp or tcptype present, server only supports UDP)\n");
            return;
        }
        $transport = 'udp';
        if (preg_match('/^\s*candidate:\S+\s+\d+\s+(udp|tcp)\s+/i', $iceCandidate, $tm)) {
            $transport = strtolower($tm[1]);
        }
        if ($transport !== 'udp') {
            $this->_log_std("Client {$clientId} SKIP non-UDP candidate (transport={$transport})\n");
            return;
        }

        if (preg_match('/(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+typ\s+(\w+)/', $iceCandidate, $matches)) {
            $candidateIP   = $matches[1];
            $candidatePort = (int)$matches[2];
            $candidateType = $matches[3];
            if ($candidateIP === '0.0.0.0' || $candidatePort <= 0 || $candidatePort > 65535) {
                $this->_log_std("Client {$clientId} SKIP invalid candidate ip={$candidateIP} port={$candidatePort}\n");
                return;
            }
            if ($candidateIP === '255.255.255.255' || strpos($candidateIP, '224.') === 0 || strpos($candidateIP, '239.') === 0) {
                $this->_log_std("Client {$clientId} SKIP multicast candidate ip={$candidateIP}\n");
                return;
            }

            if (empty($this->clients[$clientId]['remoteCandidateValidated'])) {
                $prev = $this->clients[$clientId]['remoteCandidate'] ?? null;
                $prevAddr = $prev ? "{$prev['ip']}:{$prev['port']}" : "none";
                $typeOrder = ['host' => 10, 'srflx' => 20, 'prflx' => 30, 'relay' => 40];
                $curOrder = $prev ? ($typeOrder[$prev['_type'] ?? 'host'] ?? 50) : 999;
                $newOrder = $typeOrder[strtolower($candidateType)] ?? 60;
                $shouldSet = ($prev === null) || ($newOrder < $curOrder);
                if ($shouldSet) {
                    $this->clients[$clientId]['remoteCandidate'] = ['ip' => $candidateIP, 'port' => $candidatePort, '_type' => strtolower($candidateType)];
                    $this->udpAddrMap["{$candidateIP}:{$candidatePort}"] = $clientId;
                    $this->clients[$clientId]['state'] = 'connecting';
                    $this->_log_std("Client {$clientId} remote candidate set (signaling, pre-lock, trans=udp, type={$candidateType}): {$prevAddr} -> {$candidateIP}:{$candidatePort}\n");
                } else {
                    $this->_log_std("Client {$clientId} KEEP existing candidate {$prevAddr} (type order {$curOrder} vs new {$newOrder}), IGNORE {$candidateIP}:{$candidatePort} type={$candidateType}\n");
                }
            }
        }
    }


    /**
     * 内部 helper：缺省 SFU candidate 转发（可被 onCandidate $handled=true 屏蔽）
     */
    private function _defaultRelayCandidate(int $srcId, array $msg): void
    {
        $srcRole = (string)$this->getClientMeta($srcId, 'role', '');
        $streamId = (string)$this->getClientMeta($srcId, 'streamId', '');
        if ($streamId === '' || !in_array($srcRole, ['push','play'], true)) return;
        $targets = [];
        if ($srcRole === 'push') {
            $targets = $this->getClientsByMeta('streamId', $streamId);
            $targets = array_values(array_filter($targets, function ($id) use ($srcId) { return (int)$id !== $srcId && (string)$this->getClientMeta((int)$id, 'role', '') === 'play'; }));
        } elseif ($srcRole === 'play') {
            $pid = $this->getPublisherIdByStreamId($streamId);
            if ($pid !== null && $pid !== $srcId) $targets = [$pid];
        }
        if (empty($targets)) return;
        $this->broadcastSignaling($targets, ['type' => 'candidate', 'candidate' => (string)($msg['candidate'] ?? '')]);
    }

    /**
     * 原来的方法
     * 内部 helper：若订阅者已就绪，触发 onSubscriber 事件；缺省 SFU 信令
     *   另外，无论 onSubscriber 是否已注册都会尝试：当 publisherId 存在时自动向 subscriber 发送 offer
     * 幂等：onSubscriber 每个 clientId 只触发一次；auto SFU offer 每个 clientId 也只发送一次
     *   （防止 play 端 ICE/DTLS/answer 等阶段再次误触发，导致 offer ↔ answer 无限回环）
     */
    private function _fireSubscriberIfReady2(int $subscriberId, string $streamId): void
    {
        $this->_log_std("[_fireSubscriberIfReady ENTER] client={$subscriberId} streamId={$streamId}\n");

        if (!empty($this->clients[$subscriberId]['_sfuOfferFired'])) {
            $this->_log_std("[_fireSubscriberIfReady] client={$subscriberId} 已发送过 Offer，跳过\n");
            return;
        }

        $publisherId = $this->getPublisherIdByStreamId($streamId);
        if ($publisherId === null) {
            $this->_log_std("[_fireSubscriberIfReady] streamId={$streamId} 无推流端\n");
            return;
        }

        if (isset($this->onSubscriber) && is_callable($this->onSubscriber)) {
            try {
                $_cb = $this->onSubscriber;
                $_cb($subscriberId, [
                    'streamId' => $streamId,
                    'pushClientId' => $publisherId,
                ], $this);
            } catch (\Throwable $e) {
                $this->_log_std("[_fireSubscriberIfReady] onSubscriber exception: " . $e->getMessage() . "\n");
            }
        }

        $offerSdp = $this->makeSfuOfferForSubscriber($subscriberId, $publisherId, 'passive');
        if ($offerSdp !== null && $offerSdp !== '') {
            $this->sendSignaling($subscriberId, [
                'type' => 'offer',
                'sdp' => $offerSdp,
                'streamId' => $streamId,
            ]);
            $this->clients[$subscriberId]['_sfuOfferFired'] = true;
            $this->_log_std("[_fireSubscriberIfReady] 已向 subscriber={$subscriberId} 发送 SFU Offer (len=" . strlen($offerSdp) . ")\n");
        } else {
            $this->_log_std("[_fireSubscriberIfReady] makeSfuOfferForSubscriber 返回空\n");
        }
    }

    private function _fireSubscriberIfReady(int $subscriberId, string $streamId): void
    {
        $this->_log_std("[_fireSubscriberIfReady ENTER] client={$subscriberId} streamId={$streamId}\n");
        if (!empty($this->clients[$subscriberId]['_sfuOfferFired'])) {
            $this->_log_std("[_fireSubscriberIfReady] client={$subscriberId} 已发送过 Offer，跳过\n");
            return;
        }

        $publisherId = $this->getPublisherIdByStreamId($streamId);
        if ($publisherId === null) {
            $this->_log_std("[_fireSubscriberIfReady] streamId={$streamId} 无推流端\n");
            return;
        }

        if (isset($this->onSubscriber) && is_callable($this->onSubscriber)) {
            try {
                $_cb = $this->onSubscriber;
                $_cb($subscriberId, [
                    'streamId' => $streamId,
                    'pushClientId' => $publisherId,
                ], $this);
            } catch (\Throwable $e) {
                $this->_log_std("[_fireSubscriberIfReady] onSubscriber exception: " . $e->getMessage() . "\n");
            }

            $this->_log_std("[_fireSubscriberIfReady] onSubscriber 回调已执行，框架不再自动发送 offer（请确保回调中发送了 offer 并设置 _sfuOfferFired）\n");
            return;
        }

        $offerSdp = $this->makeSfuOfferForSubscriber($subscriberId, $publisherId, 'passive');
        if ($offerSdp !== null && $offerSdp !== '') {
            $this->sendSignaling($subscriberId, [
                'type' => 'offer',
                'sdp' => $offerSdp,
                'streamId' => $streamId,
            ]);
            $this->clients[$subscriberId]['_sfuOfferFired'] = true;
            $this->_log_std("[_fireSubscriberIfReady] 已向 subscriber={$subscriberId} 发送 SFU Offer (len=" . strlen($offerSdp) . ")\n");
        } else {
            $this->_log_std("[_fireSubscriberIfReady] makeSfuOfferForSubscriber 返回空\n");
        }
    }
}