<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose Session Description Protocol 会话描述协议
 * @author yanglong
 * @note 描述媒体通信能力的文本协议
 */
trait SDP
{

    /**
     * 从 SDP 中提取 a=$attrName:value 的首个值
     * @param string $sdp
     * @param string $attrName
     * @return string
     */
    private function extractSdpAttribute($sdp, $attrName)
    {
        if (preg_match("/a={$attrName}:([^\r\n]+)/", $sdp, $matches)) {
            return trim($matches[1]);
        }
        return '';
    }

    /**
     * 构建sdp应答内容
     * - 支持 datachannel (m=application UDP/DTLS/SCTP)
     * - 支持 audio/video (m= UDP/TLS/RTP/SAVPF)
     * - 按 Offer a=group:BUNDLE mid 顺序输出 sections
     * - 返回数组除 sdp/ufrag/pwd/setup 外，额外附带：
     *     videoPTs, audioPTs, serverVideoSsrc, serverAudioSsrc, localSsrcByKind
     *
     * @param string $offerSdp 客户端的sdp内容
     * @param string $remoteIceUfrag 客户端的账号
     * @param string $remoteIcePwd 客户端密码
     * @param string $remoteSetup 客户端设置
     * @return array
     * @throws \Random\RandomException
     * @note 作为服务器，为了兼容不同的设备，这里服务端仅提供最通用的h264+opus
     */
    private function generateAnswerSDP(string $offerSdp, string $remoteIceUfrag = '', string $remoteIcePwd = '', string $remoteSetup = '', array $options = [])
    {
        $forceVideoAudioDefault = !empty($options['forceVideoAudioDefault']);
        $isWhep = !empty($options['whep']);
        $preferLoopback = !empty($options['preferLoopback']);

        $customVideoSsrc  = isset($options['serverVideoSsrc'])  ? (int)$options['serverVideoSsrc']  : 0;
        $customAudioSsrc  = isset($options['serverAudioSsrc'])  ? (int)$options['serverAudioSsrc']  : 0;
        $customCname      = isset($options['cname'])            ? (string)$options['cname']          : '';
        $customStreamId   = isset($options['msidStream'])       ? (string)$options['msidStream']     : '';
        $customVideoTrack = isset($options['msidVideoTrack'])   ? (string)$options['msidVideoTrack'] : '';
        $customAudioTrack = isset($options['msidAudioTrack'])   ? (string)$options['msidAudioTrack'] : '';
        $h264ProfileLevelId = strtolower((string)($options['h264ProfileLevelId'] ?? '42e01f'));
        if (!preg_match('/^[0-9a-f]{6}$/', $h264ProfileLevelId)) {
            $h264ProfileLevelId = '42e01f';
        }

        $fingerprint = $this->generateFingerprint();
        $localIP = $this->getLocalIP();

        $localIceUfrag = substr(bin2hex(random_bytes(4)), 0, 8);
        $localIcePwd = substr(bin2hex(random_bytes(16)), 0, 24);
        $this->_log_std("generateAnswerSDP: local ufrag={$localIceUfrag}, pwd={$localIcePwd}\n");
        $this->_log_std("generateAnswerSDP: remote ufrag={$remoteIceUfrag}, pwd={$remoteIcePwd} forceVideoAudioDefault=" . ($forceVideoAudioDefault ? 'YES(SFU)' : 'NO(chat/p2p)') . "\n");

        $localSetup = 'passive';
        if ($remoteSetup === 'actpass') {
            $localSetup = 'passive';
        } elseif ($remoteSetup === 'passive') {
            $localSetup = 'active';
        }

        $isDataChannel = strpos($offerSdp, 'm=application') !== false;
        $hasVideoOffer = (bool)preg_match('/^m=video\s+/m', $offerSdp);
        $hasAudioOffer = (bool)preg_match('/^m=audio\s+/m', $offerSdp);

        $videoPayloadTypes = [];
        $audioPayloadTypes = [];

        // 服务端不转码，只接受 Offer 中明确提供的 H264 + Opus；不注入未出现在 Offer 中的 PT。

        $bundleMids = [];
        if (preg_match('/^a=group:BUNDLE\s+(.+)$/m', $offerSdp, $bm)) {
            $bundleMids = preg_split('/\s+/', trim($bm[1]));
        }

        $offerMediaSections = [];
        $normalizedOfferSdp = str_replace("\r\n", "\n", $offerSdp);
        $mediaParts = preg_split('/(?=^m=)/m', $normalizedOfferSdp);
        foreach ($mediaParts as $mediaPart) {
            if (!preg_match('/^m=([^\s]+)\s+([^\n]+)$/m', $mediaPart, $mediaMatch)) {
                continue;
            }
            $kind = strtolower($mediaMatch[1]);
            $mid = '';
            if (preg_match('/^a=mid:(\S+)/m', $mediaPart, $midMatch)) {
                $mid = $midMatch[1];
            }
            if ($mid === '') {
                $mid = (string)count($offerMediaSections);
            }
            $direction = 'sendrecv';
            if (preg_match('/^a=(sendonly|recvonly|sendrecv|inactive)\s*$/m', $mediaPart, $directionMatch)) {
                $direction = $directionMatch[1];
            }
            $offerMediaSections[] = [
                'kind' => $kind,
                'mid' => $mid,
                'direction' => $direction,
                'mLine' => $kind . ' ' . trim($mediaMatch[2]),
            ];
        }

        $usedMids = [];
        foreach ($bundleMids as $m) if ($m !== '') $usedMids[$m] = true;

        $appMid = 'data';
        if ($isDataChannel) {
            if (preg_match('/(^m=application[\s\S]*?)(?=^m=|\z)/m', $offerSdp, $ma)) {
                if (preg_match('/^a=mid:(\S+)/m', $ma[1], $amid)) {
                    $appMid = $amid[1];
                }
            }
            if (!isset($usedMids[$appMid])) $usedMids[$appMid] = true;
            if (empty($bundleMids)) $bundleMids[] = $appMid;
        }

        $_pickFreeMid = function (string $candidate) use (&$usedMids): string {
            if (!isset($usedMids[$candidate])) { $usedMids[$candidate] = true; return $candidate; }
            for ($i = 0; $i < 200; $i++) {
                $t = (string)$i;
                if (!isset($usedMids[$t])) { $usedMids[$t] = true; return $t; }
            }
            $base = 'auto';
            for ($i = 0; $i < 100; $i++) {
                $t = $base . $i;
                if (!isset($usedMids[$t])) { $usedMids[$t] = true; return $t; }
            }
            return $candidate;
        };

        $audioMid = $_pickFreeMid('0');

        if (!isset($audioPayloadTypes) || !is_array($audioPayloadTypes)) $audioPayloadTypes = [];
        $audioOfferDir = 'sendrecv';
        $audioSection = '';
        if ($hasAudioOffer) {
            if (preg_match('/^(m=audio.*)$/m', $offerSdp, $mLine)) {
                $parts = preg_split('/\s+/', trim($mLine[1]));
                for ($i = 3; $i < count($parts); $i++) {
                    if (ctype_digit($parts[$i])) {
                        $audioPayloadTypes[(int)$parts[$i]] = [
                            'rtpmap' => null, 'fmtp' => null, 'codec' => null, 'clock' => 48000
                        ];
                    }
                }
            }
            if (preg_match('/(^m=audio[\s\S]*?)(?=^m=|\z)/m', $offerSdp, $ma)) {
                $audioSection = $ma[1];
            }
            if ($audioSection !== '') {
                if (preg_match('/^a=mid:(\S+)/m', $audioSection, $amid)) {
                    $audioMid = $amid[1];
                }

                if (preg_match('/^a=sendrecv/m', $audioSection)) {
                    $audioOfferDir = 'sendrecv';
                } elseif (preg_match('/^a=sendonly/m', $audioSection)) {
                    $audioOfferDir = 'sendonly';
                } elseif (preg_match('/^a=recvonly/m', $audioSection)) {
                    $audioOfferDir = 'recvonly';
                } elseif (preg_match('/^a=inactive/m', $audioSection)) {
                    $audioOfferDir = 'inactive';
                } else {

                    $audioOfferDir = 'sendrecv';
                }
                $lines = explode("\n", str_replace("\r\n", "\n", $audioSection));
                foreach ($lines as $line) {
                    $line = rtrim($line, "\r\n");
                    if (preg_match('/^a=rtpmap:(\d+)\s+(.+)$/', $line, $m)) {
                        $pt = (int)$m[1];
                        if (isset($audioPayloadTypes[$pt])) {
                            $audioPayloadTypes[$pt]['rtpmap'] = $m[2];
                            $cp = explode('/', $m[2]);
                            $audioPayloadTypes[$pt]['codec'] = $cp[0] ?? null;
                            $audioPayloadTypes[$pt]['clock'] = (int)($cp[1] ?? 48000);
                        }
                    } elseif (preg_match('/^a=fmtp:(\d+)\s+(.+)$/', $line, $m)) {
                        $pt = (int)$m[1];
                        if (isset($audioPayloadTypes[$pt])) {
                            $audioPayloadTypes[$pt]['fmtp'] = $m[2];
                        }
                    }
                }
            }
            if (empty($bundleMids)) $bundleMids[] = $audioMid;
        }

        $videoMid = $_pickFreeMid('1');

        if (!isset($videoPayloadTypes) || !is_array($videoPayloadTypes)) $videoPayloadTypes = [];
        $videoOfferDir = 'sendrecv';
        $videoSection = '';
        if ($hasVideoOffer) {
            if (preg_match('/^(m=video.*)$/m', $offerSdp, $mLine)) {
                $parts = preg_split('/\s+/', trim($mLine[1]));
                for ($i = 3; $i < count($parts); $i++) {
                    if (ctype_digit($parts[$i])) {
                        $videoPayloadTypes[(int)$parts[$i]] = [
                            'rtpmap' => null, 'fmtp' => null, 'codec' => null, 'clock' => 90000
                        ];
                    }
                }
            }
            if (preg_match('/(^m=video[\s\S]*?)(?=^m=|\z)/m', $offerSdp, $mv)) {
                $videoSection = $mv[1];
            }
            if ($videoSection !== '') {
                if (preg_match('/^a=mid:(\S+)/m', $videoSection, $vmid)) {
                    $videoMid = $vmid[1];
                }
                if (preg_match('/^a=sendrecv/m', $videoSection)) {
                    $videoOfferDir = 'sendrecv';
                } elseif (preg_match('/^a=sendonly/m', $videoSection)) {
                    $videoOfferDir = 'sendonly';
                } elseif (preg_match('/^a=recvonly/m', $videoSection)) {
                    $videoOfferDir = 'recvonly';
                } elseif (preg_match('/^a=inactive/m', $videoSection)) {
                    $videoOfferDir = 'inactive';
                } else {
                    $videoOfferDir = 'sendrecv';
                }
                $lines = explode("\n", str_replace("\r\n", "\n", $videoSection));
                foreach ($lines as $line) {
                    $line = rtrim($line, "\r\n");
                    if (preg_match('/^a=rtpmap:(\d+)\s+(.+)$/', $line, $m)) {
                        $pt = (int)$m[1];
                        if (isset($videoPayloadTypes[$pt])) {
                            $videoPayloadTypes[$pt]['rtpmap'] = $m[2];
                            $cp = explode('/', $m[2]);
                            $videoPayloadTypes[$pt]['codec'] = $cp[0] ?? null;
                            $videoPayloadTypes[$pt]['clock'] = (int)($cp[1] ?? 90000);
                        }
                    } elseif (preg_match('/^a=fmtp:(\d+)\s+(.+)$/', $line, $m)) {
                        $pt = (int)$m[1];
                        if (isset($videoPayloadTypes[$pt])) {
                            $videoPayloadTypes[$pt]['fmtp'] = $m[2];
                        }
                    }
                }
            }
            if (empty($bundleMids)) $bundleMids[] = $videoMid;
            $this->_log_std("generateAnswerSDP: hasVideo=$hasVideoOffer hasAudio=$hasAudioOffer isData=$isDataChannel videoDir=$videoOfferDir audioDir=$audioOfferDir\n");
        }

        $selectedH264PT = 0;
        $selectedH264Info = null;
        foreach ($videoPayloadTypes as $pt => $info) {
            if (!is_array($info) || strtolower((string)($info['codec'] ?? '')) !== 'h264' || (int)($info['clock'] ?? 0) !== 90000) {
                continue;
            }
            $fmtp = (string)($info['fmtp'] ?? '');
            if (!preg_match('/(?:^|;)\s*packetization-mode=1(?:;|$)/i', $fmtp)) {
                continue;
            }
            $selectedH264PT = (int)$pt;
            $selectedH264Info = $info;
            break;
        }

        $selectedOpusPT = 0;
        $selectedOpusInfo = null;
        foreach ($audioPayloadTypes as $pt => $info) {
            if (!is_array($info) || strtolower((string)($info['codec'] ?? '')) !== 'opus' || (int)($info['clock'] ?? 0) !== 48000) {
                continue;
            }
            $rtpmapParts = explode('/', (string)($info['rtpmap'] ?? ''));
            if (isset($rtpmapParts[2]) && (int)$rtpmapParts[2] !== 2) {
                continue;
            }
            $selectedOpusPT = (int)$pt;
            $selectedOpusInfo = $info;
            break;
        }

        if ($hasVideoOffer && ($selectedH264PT <= 0 || $selectedH264Info === null)) {
            $this->_log_std("generateAnswerSDP: codec negotiation failed: Offer 缺少 H264/90000 packetization-mode=1\n");
            return ['error' => 'unsupported-codec', 'message' => 'Offer must include H264/90000 with packetization-mode=1'];
        }
        if ($hasAudioOffer && ($selectedOpusPT <= 0 || $selectedOpusInfo === null)) {
            $this->_log_std("generateAnswerSDP: codec negotiation failed: Offer 缺少 opus/48000/2\n");
            return ['error' => 'unsupported-codec', 'message' => 'Offer must include opus/48000/2'];
        }
        if (!$hasVideoOffer || !$hasAudioOffer) {
            $this->_log_std("generateAnswerSDP: codec negotiation failed: Offer 必须同时包含 video 和 audio m-line\n");
            return ['error' => 'unsupported-codec', 'message' => 'Offer must include both H264 video and Opus audio'];
        }

        $mirrorDir = function (string $offerDir): string {
            switch ($offerDir) {
                case 'sendonly': return 'recvonly';
                case 'recvonly': return 'sendonly';
                case 'inactive': return 'inactive';
                case 'sendrecv':
                default:         return 'sendrecv';
            }
        };
        $videoAnswerDir = $mirrorDir($videoOfferDir);
        $audioAnswerDir = $mirrorDir($audioOfferDir);

        $sdp = "v=0\r\n";
        $sdp .= "o=- 12345 12345 IN IP4 {$localIP}\r\n";
        $sdp .= "s=-\r\n";
        $sdp .= "t=0 0\r\n";
        $sdp .= "a=ice-lite\r\n";
        $_bundlePlaceholder = true;
        $sdp .= "a=extmap-allow-mixed\r\n";
        $sdp .= "a=msid-semantic: WMS\r\n";

        $transportBlock = "";
        $transportBlock .= "a=ice-ufrag:{$localIceUfrag}\r\n";
        $transportBlock .= "a=ice-pwd:{$localIcePwd}\r\n";
        $transportBlock .= "a=ice-options:trickle\r\n";
        $transportBlock .= "a=fingerprint:sha-256 {$fingerprint}\r\n";
        $transportBlock .= "a=setup:{$localSetup}\r\n";
        if ($localIP != "127.0.0.1") {
            if ($preferLoopback) {
                $transportBlock .= "a=candidate:1 1 UDP 2130706431 127.0.0.1 " . $this->udpPort . " typ host\r\n";
                $transportBlock .= "a=candidate:2 1 UDP 2130706175 {$localIP} " . $this->udpPort . " typ host\r\n";
            } else {
                $transportBlock .= "a=candidate:1 1 UDP 2130706431 {$localIP} " . $this->udpPort . " typ host\r\n";
            }
        } else {
            $transportBlock .= "a=candidate:1 1 UDP 2130706431 127.0.0.1 " . $this->udpPort . " typ host\r\n";
        }
        $this->_log_std("[ICE candidates] preferLoopback=" . ($preferLoopback ? 'yes' : 'no')
            . " requestCandidate=" . ($preferLoopback ? '127.0.0.1' : $localIP) . "\n");
        $transportBlock .= "a=end-of-candidates\r\n";

        $sections = [];
        $sectionMid = [];

        if ($isDataChannel) {
            $appSec = "";
            $appSec .= "m=application " . $this->udpPort . " UDP/DTLS/SCTP webrtc-datachannel\r\n";
            $appSec .= "c=IN IP4 {$localIP}\r\n";
            $appSec .= "a=mid:{$appMid}\r\n";
            $appSec .= "a=sctp-port:5000\r\n";
            $appSec .= "a=max-message-size:262144\r\n";
            $sections['application'] = $appSec;
            $sectionMid['application'] = $appMid;
        }

        $serverVideoSsrc = ($customVideoSsrc > 0) ? $customVideoSsrc : 4147483647;
        $serverAudioSsrc = ($customAudioSsrc > 0) ? $customAudioSsrc : 3741943039;
        $_cname      = ($customCname      !== '') ? $customCname      : "php-srtp-echo";
        $_streamId    = ($customStreamId   !== '') ? $customStreamId   : "php-srtp-echo-stream";
        $_videoTrkId = ($customVideoTrack !== '') ? $customVideoTrack : "php-srtp-vid-1";
        $_audioTrkId = ($customAudioTrack !== '') ? $customAudioTrack : "php-srtp-aud-1";
        $videoPTSet = [];
        $audioPTSet = [];

        if ($hasVideoOffer) {
            $vidSec = "";
            $fixedVideoPT = $selectedH264PT;
            $offerH264Fmtp = (string)($selectedH264Info['fmtp'] ?? '');
            $answerH264Profile = $h264ProfileLevelId;
            if (preg_match('/(?:^|;)\s*profile-level-id=([0-9a-f]{6})(?:;|$)/i', $offerH264Fmtp, $profileMatch)) {
                $answerH264Profile = strtolower($profileMatch[1]);
            }
            $validPTs = [$fixedVideoPT];
            $fixedVideoInfo = [
                'rtpmap' => 'H264/90000',
                'codec'  => 'H264',
                'clock'  => 90000,
                'fmtp'   => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=' . $answerH264Profile,
            ];
            $validPTInfo = [$fixedVideoPT => $fixedVideoInfo];
            $videoPTSet = [$fixedVideoPT => $fixedVideoInfo];
            $videoPayloadTypes = [$fixedVideoPT => $fixedVideoInfo];

            $ptList = implode(' ', $validPTs);
            $vidSec .= "m=video " . $this->udpPort . " UDP/TLS/RTP/SAVPF {$ptList}\r\n";
            $vidSec .= "c=IN IP4 {$localIP}\r\n";
            $vidSec .= "a=rtcp:9 IN IP4 0.0.0.0\r\n";
            $vidSec .= "a=mid:{$videoMid}\r\n";
            $vidSec .= "a={$videoAnswerDir}\r\n";
            $vidSec .= "a=rtcp-mux\r\n";
            $vidSec .= "a=rtcp-rsize\r\n";

            $extLines = []; $rtcpFbLines = [];
            if ($videoSection !== '') {
                $vlines = explode("\n", str_replace("\r\n", "\n", $videoSection));
                foreach ($vlines as $vl) {
                    $vl = rtrim($vl, "\r\n");
                    if (preg_match('/^a=extmap:(\d+)(?:\/\S+)?\s+(\S+)/i', $vl, $m)) {
                        $extUri = strtolower($m[2]);
                        if ($extUri === 'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01'
                            || $extUri === 'urn:ietf:params:rtp-hdrext:transport-wide-cc') continue;
                        $extLines[(int)$m[1]] = $vl;
                    } elseif (preg_match('/^a=rtcp-fb:(?:\*|\d+)\s+nack\s+pli\s*$/i', $vl)) {
                        if (!isset($rtcpFbLines[$fixedVideoPT])) $rtcpFbLines[$fixedVideoPT] = [];
                        $rtcpFbLines[$fixedVideoPT][] = 'a=rtcp-fb:' . $fixedVideoPT . ' nack pli';
                    }
                }
            }
            ksort($extLines);
            foreach ($extLines as $l) $vidSec .= $l . "\r\n";

            $vidSec .= "a=msid:{$_streamId} {$_videoTrkId}\r\n";
            $mainSsrc = $serverVideoSsrc;
            $cname = $_cname;
            $mslabel = $_streamId;
            $label = $_videoTrkId;
            $vidSec .= "a=ssrc:{$mainSsrc} cname:{$cname}\r\n";
            $vidSec .= "a=ssrc:{$mainSsrc} msid:{$mslabel} {$label}\r\n";
            $vidSec .= "a=ssrc:{$mainSsrc} mslabel:{$mslabel}\r\n";
            $vidSec .= "a=ssrc:{$mainSsrc} label:{$label}\r\n";
            $vidSec .= "a=rtpmap:{$fixedVideoPT} H264/90000\r\n";
            $vidSec .= "a=fmtp:{$fixedVideoPT} level-asymmetry-allowed=1;packetization-mode=1;profile-level-id={$answerH264Profile}\r\n";
            $vidSec .= "a=rtcp-fb:{$fixedVideoPT} nack pli\r\n";
            if (!empty($rtcpFbLines[$fixedVideoPT])) {
                $_seenRtcpFb = [];
                foreach ($rtcpFbLines[$fixedVideoPT] as $fbl) {
                    if (!isset($_seenRtcpFb[$fbl])) {
                        $_seenRtcpFb[$fbl] = true;
                        if (preg_match('/^a=rtcp-fb:' . $fixedVideoPT . '\s+nack\s+pli\s*$/i', $fbl)) {
                            continue;
                        }
                    }
                }
            }
            $sections['video'] = $vidSec;
            $sectionMid['video'] = $videoMid;
            $this->_log_std("generateAnswerSDP: 仅协商 Offer 中的 H264 PT={$fixedVideoPT}, packetization-mode=1, profile-level-id={$answerH264Profile}\n");
        }

        if ($hasAudioOffer) {
            $audSec = "";
            $fixedOpusPT = $selectedOpusPT;
            $validAudioPTs = [$fixedOpusPT];
            $validAudioPTInfo = [
                $fixedOpusPT => ['rtpmap' => 'opus/48000/2', 'codec' => 'opus', 'clock' => 48000,
                                 'fmtp' => 'minptime=10;useinbandfec=1'],
            ];
            $audioPTSet = $validAudioPTInfo;
            $audioPayloadTypes = $validAudioPTInfo;

            $ptList = implode(' ', $validAudioPTs);
            $audSec .= "m=audio " . $this->udpPort . " UDP/TLS/RTP/SAVPF {$ptList}\r\n";
            $audSec .= "c=IN IP4 {$localIP}\r\n";
            $audSec .= "a=rtcp:9 IN IP4 0.0.0.0\r\n";
            $audSec .= "a=mid:{$audioMid}\r\n";
            $audSec .= "a={$audioAnswerDir}\r\n";
            $audSec .= "a=rtcp-mux\r\n";

            $extLines = [];
            if ($audioSection !== '') {
                $alines = explode("\n", str_replace("\r\n", "\n", $audioSection));
                foreach ($alines as $al) {
                    $al = rtrim($al, "\r\n");
                    if (preg_match('/^a=extmap:(\d+)(?:\/\S+)?\s+(\S+)/i', $al, $m)) {
                        $extUri = strtolower($m[2]);
                        if ($extUri === 'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01'
                            || $extUri === 'urn:ietf:params:rtp-hdrext:transport-wide-cc') continue;
                        $extLines[(int)$m[1]] = $al;
                    }
                }
            }
            ksort($extLines);
            foreach ($extLines as $l) $audSec .= $l . "\r\n";

            $audSec .= "a=msid:{$_streamId} {$_audioTrkId}\r\n";
            $audSsrc = $serverAudioSsrc;
            $cname = $_cname;
            $mslabel = $_streamId;
            $label = $_audioTrkId;
            $audSec .= "a=ssrc:{$audSsrc} cname:{$cname}\r\n";
            $audSec .= "a=ssrc:{$audSsrc} msid:{$mslabel} {$label}\r\n";
            $audSec .= "a=ssrc:{$audSsrc} mslabel:{$mslabel}\r\n";
            $audSec .= "a=ssrc:{$audSsrc} label:{$label}\r\n";
            $audSec .= "a=rtpmap:{$fixedOpusPT} opus/48000/2\r\n";
            $audSec .= "a=fmtp:{$fixedOpusPT} minptime=10;useinbandfec=1\r\n";

            $sections['audio'] = $audSec;
            $sectionMid['audio'] = $audioMid;
            $this->_log_std("generateAnswerSDP: 仅协商 Offer 中的 Opus PT={$fixedOpusPT}\n");
        }

        $orderedSections = [];
        $actualBundleMids = [];
        $whepSendingKinds = [];
        foreach ($offerMediaSections as $offerMedia) {
            $kind = $offerMedia['kind'];
            $mid = $offerMedia['mid'];
            $actualBundleMids[] = $mid;

            if (isset($sections[$kind])) {
                $answerDirection = $mirrorDir($offerMedia['direction']);
                if ($isWhep
                    && ($kind === 'audio' || $kind === 'video')
                    && ($answerDirection === 'sendonly' || $answerDirection === 'sendrecv')
                    && isset($whepSendingKinds[$kind])) {
                    $mParts = preg_split('/\s+/', trim($offerMedia['mLine']));
                    if (count($mParts) >= 2) {
                        $mParts[1] = '0';
                    }
                    $rejected = 'm=' . implode(' ', $mParts) . "\r\n";
                    $rejected .= "c=IN IP4 0.0.0.0\r\n";
                    $rejected .= "a=mid:{$mid}\r\n";
                    $rejected .= "a=inactive\r\n";
                    $orderedSections[] = ['sdp' => $rejected, 'accepted' => false];
                    continue;
                }

                $section = preg_replace('/^a=mid:\S+\r?$/m', 'a=mid:' . $mid, $sections[$kind]);
                if ($kind === 'audio' || $kind === 'video') {
                    $section = preg_replace(
                        '/^a=(?:sendonly|recvonly|sendrecv|inactive)\r?$/m',
                        'a=' . $answerDirection,
                        $section
                    );
                    if ($isWhep) {
                        if ($answerDirection === 'sendonly' || $answerDirection === 'sendrecv') {
                            $whepSendingKinds[$kind] = true;
                        } else {
                            $section = preg_replace('/^a=(?:msid:|ssrc:)[^\r\n]*(?:\r?\n|$)/m', '', $section);
                        }
                    }
                }
                $orderedSections[] = ['sdp' => $section, 'accepted' => true];
                continue;
            }

            $mParts = preg_split('/\s+/', trim($offerMedia['mLine']));
            if (count($mParts) >= 2) {
                $mParts[1] = '0';
            }
            $rejected = 'm=' . implode(' ', $mParts) . "\r\n";
            $rejected .= "c=IN IP4 0.0.0.0\r\n";
            $rejected .= "a=mid:{$mid}\r\n";
            $rejected .= "a=inactive\r\n";
            $orderedSections[] = ['sdp' => $rejected, 'accepted' => false];
        }

        $sdp = "v=0\r\n"
             . "o=- 12345 12345 IN IP4 {$localIP}\r\n"
             . "s=-\r\n"
             . "t=0 0\r\n"
             . "a=ice-lite\r\n";
        if (!empty($actualBundleMids)) {
            $sdp .= "a=group:BUNDLE " . implode(' ', $actualBundleMids) . "\r\n";
        }
        $sdp .= "a=extmap-allow-mixed\r\n";
        $sdp .= "a=msid-semantic: WMS\r\n";

        $transportWritten = false;
        foreach ($orderedSections as $orderedSection) {
            $sdp .= $orderedSection['sdp'];
            if (!$transportWritten && $orderedSection['accepted']) {
                $sdp .= $transportBlock;
                $transportWritten = true;
            }
        }

        $sdp = preg_replace("/\r\n|\r|\n/", "\r\n", rtrim($sdp, "\r\n")) . "\r\n";

        $result = [
            'sdp' => $sdp,
            'ice-ufrag' => $localIceUfrag,
            'ice-pwd' => $localIcePwd,
            'setup' => $localSetup,
            'videoPTs' => $videoPTSet,
            'audioPTs' => $audioPTSet,
            'serverVideoSsrc' => $serverVideoSsrc,
            'serverAudioSsrc' => $serverAudioSsrc,
            'localSsrcByKind' => [
                'video' => $serverVideoSsrc,
                'audio' => $serverAudioSsrc,
            ],
        ];
        return $result;
    }

    /**
     * 生成DTLS 证书指纹
     * @return string
     */
    private function generateFingerprint()
    {
        if (!file_exists($this->certPath)) {
            return "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
        }

        $certPem = file_get_contents($this->certPath);
        $certData = '';
        $lines = explode("\n", $certPem);
        foreach ($lines as $line) {
            if ($line && !preg_match('/^-----/', $line)) {
                $certData .= trim($line);
            }
        }
        $certData = base64_decode($certData);

        $hash = hash('sha256', $certData, true);
        $fingerprint = strtoupper(chunk_split(bin2hex($hash), 2, ':'));

        $this->_log_std("Generated fingerprint: " . rtrim($fingerprint, ':') . "\n");

        return rtrim($fingerprint, ':');
    }

}
