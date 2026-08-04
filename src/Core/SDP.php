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

        $customVideoSsrc  = isset($options['serverVideoSsrc'])  ? (int)$options['serverVideoSsrc']  : 0;
        $customAudioSsrc  = isset($options['serverAudioSsrc'])  ? (int)$options['serverAudioSsrc']  : 0;
        $customCname      = isset($options['cname'])            ? (string)$options['cname']          : '';
        $customStreamId   = isset($options['msidStream'])       ? (string)$options['msidStream']     : '';
        $customVideoTrack = isset($options['msidVideoTrack'])   ? (string)$options['msidVideoTrack'] : '';
        $customAudioTrack = isset($options['msidAudioTrack'])   ? (string)$options['msidAudioTrack'] : '';

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

        /** 此处之所以写死了编码为h264 + opus ,因为作为服务端只负责转发不负责转码，那么当推流端和服务器协商一致后，所有拉流端必须使用相同的编码否则无法解码
         * 而h264+opus也是大多数设备都支持的格式
         * */
        $_injectDefaultVideoPTs = function (array &$videoPayloadTypes, array &$audioPayloadTypes,
                                            bool $hasVideo, bool $hasAudio): void {
            if ($hasVideo && empty($videoPayloadTypes)) {
                $videoPayloadTypes = [
                    123 => ['rtpmap' => 'H264/90000', 'codec' => 'H264', 'clock' => 90000,
                            'fmtp' => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f'],
                    96  => ['rtpmap' => 'H264/90000', 'codec' => 'H264', 'clock' => 90000,
                            'fmtp' => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f'],
                ];
            }

            if ($hasAudio && empty($audioPayloadTypes)) {
                $audioPayloadTypes = [
                    111 => ['rtpmap' => 'opus/48000/2',       'codec' => 'opus',            'clock' => 48000,
                            'fmtp' => 'minptime=10;useinbandfec=1'],
                    126 => ['rtpmap' => 'telephone-event/8000','codec' => 'telephone-event', 'clock' => 8000,
                            'fmtp' => '0-15'],
                    127 => ['rtpmap' => 'CN/8000',            'codec' => 'cn',              'clock' => 8000],
                ];
            }
        };

        if ($hasVideoOffer || $hasAudioOffer) {
            $_injectDefaultVideoPTs($videoPayloadTypes, $audioPayloadTypes, $hasVideoOffer, $hasAudioOffer);
        }

        /** 这里是兼容只创建datachannel传输消息，而不传输音视频消息的 */

        if ($forceVideoAudioDefault && !$hasVideoOffer && !$hasAudioOffer) {
            $hasVideoOffer = true;
            $hasAudioOffer = true;
            $_injectDefaultVideoPTs($videoPayloadTypes, $audioPayloadTypes, true, true);
            $this->_log_std("generateAnswerSDP: [SFU ONLY] force video+audio defaults injected (offer had no m=video/m=audio)\n");
        }
        unset($_injectDefaultVideoPTs);

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
            $transportBlock .= "a=candidate:1 1 UDP 2130706431 {$localIP} " . $this->udpPort . " typ host\r\n";
            $transportBlock .= "a=candidate:2 1 UDP 2130706431 127.0.0.1 " . $this->udpPort . " typ host\r\n";
        } else {
            $transportBlock .= "a=candidate:1 1 UDP 2130706431 127.0.0.1 " . $this->udpPort . " typ host\r\n";
        }
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
            $fixedVideoPT = 103;
            $validPTs = [$fixedVideoPT];
            $fixedVideoInfo = [
                'rtpmap' => 'H264/90000',
                'codec'  => 'H264',
                'clock'  => 90000,
                'fmtp'   => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f',
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
                        // 只接收 Offer 中与本地实现一致的 nack pli；其余反馈能力不复制。
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
            $vidSec .= "a=fmtp:{$fixedVideoPT} level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n";
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
            $this->_log_std("generateAnswerSDP: [FORCE WRITE-STOP VIDEO PT=103]  忽略 Offer 原视频PT，强制只声明 H264 PT=103（保证和 RTP 转发翻译后的 PT 完全一致）\n");
        }

        if ($hasAudioOffer) {
            $audSec = "";

            $fixedOpusPT = 111;
            $fixedTelPT   = 126;
            $fixedCnPT    = 127;
            $validAudioPTs = [$fixedOpusPT, $fixedTelPT, $fixedCnPT];
            $validAudioPTInfo = [
                $fixedOpusPT => ['rtpmap' => 'opus/48000/2', 'codec' => 'opus', 'clock' => 48000,
                                 'fmtp' => 'minptime=10;useinbandfec=1'],
                $fixedTelPT  => ['rtpmap' => 'telephone-event/8000', 'codec' => 'telephone-event', 'clock' => 8000,
                                 'fmtp' => '0-15'],
                $fixedCnPT   => ['rtpmap' => 'CN/8000', 'codec' => 'cn', 'clock' => 8000],
            ];
            foreach ($validAudioPTs as $pt) $audioPTSet[$pt] = $validAudioPTInfo[$pt];
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
            $audSec .= "a=rtpmap:{$fixedTelPT} telephone-event/8000\r\n";
            $audSec .= "a=fmtp:{$fixedTelPT} 0-15\r\n";
            $audSec .= "a=rtpmap:{$fixedCnPT} CN/8000\r\n";

            $sections['audio'] = $audSec;
            $sectionMid['audio'] = $audioMid;
            $this->_log_std("generateAnswerSDP: [FORCE WRITE-STOP AUDIO PT=111]  忽略 Offer 原音频PT，强制声明 Opus=111, telephone-event=126, CN=127（保证和 RTP 转发翻译后的 PT 完全一致）\n");
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

        if ($isWhep) {
            static $_dbgWhepAnswerReported = false;
            if (!$_dbgWhepAnswerReported) {
                $_dbgWhepAnswerReported = true;
                $_dbgMedia = [];
                if (preg_match_all('/(^m=(audio|video)[\s\S]*?)(?=^m=|\z)/m', $sdp, $_dbgSections, PREG_SET_ORDER)) {
                    foreach ($_dbgSections as $_dbgSection) {
                        preg_match('/^m=\S+\s+\d+\s+\S+\s+(.+)$/m', $_dbgSection[1], $_dbgPts);
                        preg_match('/^a=mid:(\S+)/m', $_dbgSection[1], $_dbgMid);
                        preg_match('/^a=(sendonly|recvonly|sendrecv|inactive)$/m', $_dbgSection[1], $_dbgDir);
                        $_dbgMedia[] = ['kind'=>$_dbgSection[2], 'pts'=>preg_split('/\s+/', trim($_dbgPts[1] ?? '')), 'mid'=>$_dbgMid[1] ?? '', 'direction'=>$_dbgDir[1] ?? ''];
                    }
                }
                $_dbgEnv = @file_get_contents(dirname(__DIR__, 2) . '/.dbg/whep-zero-video.env');
                preg_match('/^DEBUG_SERVER_URL=(.+)$/m', (string)$_dbgEnv, $_dbgUrlMatch);
                $_dbgUrl = trim($_dbgUrlMatch[1] ?? 'http://127.0.0.1:7777/event');
                $_dbgPayload = json_encode(['sessionId'=>'whep-zero-video','runId'=>'pre-fix','hypothesisId'=>'E','location'=>'src/Core/SDP.php:WHEP-answer','msg'=>'[DEBUG] WHEP Answer media PT/MID/direction','data'=>['media'=>$_dbgMedia],'ts'=>(int)(microtime(true)*1000)]);
                @file_get_contents($_dbgUrl, false, stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/json\r\n",'content'=>$_dbgPayload,'timeout'=>0.05,'ignore_errors'=>true]]));
            }
        }

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

    /**
     * 解析任意 SDP (offer/answer) 的媒体层信息
     * 返回: [
     *   'videoPTs' => [pt => true],  // m=video 中所有的 payload type
     *   'audioPTs' => [pt => true],  // m=audio 中所有的 payload type
     *   'primaryVideoPT' => int|null,  // m=video 行中第一个数字 PT (浏览器优先使用的主PT)
     *   'primaryAudioPT' => int|null,  // m=audio 行中第一个数字 PT
     * ]
     * @param string $sdp
     * @return array
     */
    private function parseSdpMediaInfo(string $sdp): array
    {
        $videoPTs = [];
        $audioPTs = [];
        $primaryVideoPT = null;
        $primaryAudioPT = null;

        if (preg_match('/^m=video\s+/m', $sdp)) {
            $sec = '';
            if (preg_match('/(^m=video[\s\S]*?)(?=^m=|\z)/m', $sdp, $mv)) $sec = $mv[1];
            $ptCodecMap = [];
            $ptInfoMap = [];
            if (preg_match_all('/^a=rtpmap:(\d+)\s+(.+)$/m', $sec, $rrs, PREG_SET_ORDER)) {
                foreach ($rrs as $rr) {
                    $pt = (int)$rr[1];
                    $rtpmap = trim($rr[2]);
                    $cp = explode('/', $rtpmap);
                    $codec = strtolower(trim($cp[0] ?? ''));
                    $ptCodecMap[$pt] = $codec;
                    $ptInfoMap[$pt] = ['rtpmap' => $rtpmap, 'codec' => $codec, 'clock' => (int)($cp[1] ?? 90000), 'fmtp' => null];
                }
            }
            if (preg_match_all('/^a=fmtp:(\d+)\s+(.+)$/m', $sec, $frs, PREG_SET_ORDER)) {
                foreach ($frs as $fr) {
                    $pt = (int)$fr[1];
                    if (isset($ptInfoMap[$pt])) $ptInfoMap[$pt]['fmtp'] = trim($fr[2]);
                }
            }

            $videoH264Codes = ['h264', 'avc'];
            $orderedAllPts = [];
            if (preg_match('/^(m=video\s+.*)$/m', $sec, $mLine)) {
                $parts = preg_split('/\s+/', trim($mLine[1]));
                for ($i = 3; $i < count($parts); $i++) {
                    if (ctype_digit($parts[$i])) $orderedAllPts[] = (int)$parts[$i];
                }
            }
            foreach (array_keys($ptInfoMap) as $_pt) if (!in_array($_pt, $orderedAllPts, true)) $orderedAllPts[] = (int)$_pt;

            $_firstH264PT = null;
            foreach ($orderedAllPts as $pt) {
                $c = $ptCodecMap[$pt] ?? '';
                if ($c !== '' && in_array($c, $videoH264Codes, true)) {
                    $videoPTs[$pt] = $ptInfoMap[$pt]
                        ?? [
                            'rtpmap' => ($c === 'h264') ? 'H264/90000' : 'AVC/90000',
                            'codec'  => ($c === 'avc') ? 'AVC' : 'H264',
                            'clock'  => 90000,
                            'fmtp'   => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f',
                        ];
                    if ($_firstH264PT === null) $_firstH264PT = $pt;
                }
            }
            if ($_firstH264PT !== null) {
                $primaryVideoPT = $_firstH264PT;
            } elseif (!empty($orderedAllPts)) {
                $primaryVideoPT = 123;
                $videoPTs = [
                    123 => ['rtpmap' => 'H264/90000', 'codec' => 'H264', 'clock' => 90000,
                            'fmtp' => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f'],
                    96  => ['rtpmap' => 'H264/90000', 'codec' => 'H264', 'clock' => 90000,
                            'fmtp' => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f'],
                ];
            }
        }

        if (preg_match('/^m=audio\s+/m', $sdp)) {
            $sec = '';
            if (preg_match('/(^m=audio[\s\S]*?)(?=^m=|\z)/m', $sdp, $ma)) $sec = $ma[1];
            $ptCodecMap = [];
            $ptInfoMap = [];
            if (preg_match_all('/^a=rtpmap:(\d+)\s+(.+)$/m', $sec, $rrs, PREG_SET_ORDER)) {
                foreach ($rrs as $rr) {
                    $pt = (int)$rr[1];
                    $rtpmap = trim($rr[2]);
                    $cp = explode('/', $rtpmap);
                    $codec = strtolower(trim($cp[0] ?? ''));
                    $ptCodecMap[$pt] = $codec;
                    $ptInfoMap[$pt] = ['rtpmap' => $rtpmap, 'codec' => $codec, 'clock' => (int)($cp[1] ?? 48000), 'fmtp' => null];
                }
            }
            if (preg_match_all('/^a=fmtp:(\d+)\s+(.+)$/m', $sec, $frs, PREG_SET_ORDER)) {
                foreach ($frs as $fr) {
                    $pt = (int)$fr[1];
                    if (isset($ptInfoMap[$pt])) $ptInfoMap[$pt]['fmtp'] = trim($fr[2]);
                }
            }
            $audioAllowedCodes = ['opus' => true, 'telephone-event' => true, 'cn' => true];
            $orderedAllPts = [];
            if (preg_match('/^(m=audio\s+.*)$/m', $sec, $mLine)) {
                $parts = preg_split('/\s+/', trim($mLine[1]));
                for ($i = 3; $i < count($parts); $i++) {
                    if (ctype_digit($parts[$i])) $orderedAllPts[] = (int)$parts[$i];
                }
            }
            foreach (array_keys($ptInfoMap) as $_pt) if (!in_array($_pt, $orderedAllPts, true)) $orderedAllPts[] = (int)$_pt;

            $_firstOpusPT = null;
            foreach ($orderedAllPts as $pt) {
                $c = $ptCodecMap[$pt] ?? '';
                if ($c !== '' && isset($audioAllowedCodes[$c])) {
                    $audioPTs[$pt] = $ptInfoMap[$pt]
                        ?? (function() use ($c) {
                            if ($c === 'telephone-event') {
                                return ['rtpmap' => 'telephone-event/8000', 'codec' => 'telephone-event',
                                        'clock' => 8000, 'fmtp' => '0-15'];
                            }
                            if ($c === 'cn') {
                                return ['rtpmap' => 'CN/8000', 'codec' => 'cn', 'clock' => 8000, 'fmtp' => null];
                            }
                            return ['rtpmap' => 'opus/48000/2', 'codec' => 'opus', 'clock' => 48000,
                                    'fmtp' => 'minptime=10;useinbandfec=1'];
                        })();
                    if ($c === 'opus' && $_firstOpusPT === null) $_firstOpusPT = $pt;
                }
            }
            if ($_firstOpusPT !== null) {
                $primaryAudioPT = $_firstOpusPT;
            } elseif (!empty($orderedAllPts)) {
                $primaryAudioPT = 111;
                $audioPTs = [
                    111 => ['rtpmap' => 'opus/48000/2',       'codec' => 'opus',            'clock' => 48000,
                            'fmtp' => 'minptime=10;useinbandfec=1'],
                    126 => ['rtpmap' => 'telephone-event/8000','codec' => 'telephone-event', 'clock' => 8000,
                            'fmtp' => '0-15'],
                    127 => ['rtpmap' => 'CN/8000',            'codec' => 'cn',              'clock' => 8000],
                ];
            }
        }

        return [
            'videoPTs'       => $videoPTs,
            'audioPTs'       => $audioPTs,
            'primaryVideoPT' => $primaryVideoPT,
            'primaryAudioPT' => $primaryAudioPT,
        ];
    }

}
