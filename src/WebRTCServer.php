<?php

namespace Xiaosongshu\Webrtc;

use Xiaosongshu\Webrtc\Core\DTLS;
use Xiaosongshu\Webrtc\Core\ICE;
use Xiaosongshu\Webrtc\Core\SCTP;
use Xiaosongshu\Webrtc\Core\SDP;
use Xiaosongshu\Webrtc\Core\STUN;
use Xiaosongshu\Webrtc\Core\UDP;
use Xiaosongshu\Webrtc\Core\WebSocket;

/**
 * @purpose webrtc服务器
 * @author yanglong
 * @time 2026年7月31日10:03:48
 *
 * @note webrtc协议栈图
 * ┌─────────────────────────────────────────────┐
 * │               WebRTC 协议栈                   │
 * ├─────────────────┬───────────────────────────┤
 * │   媒体通道       │   数据通道                 │
 * │ (音视频流)       │ (DataChannel)             │
 * ├─────────────────┼───────────────────────────┤
 * │ SRTP/SRTCP      │ SCTP                      │ ← 传输层
 * │ (加密RTP)       │ (多流可靠传输)              │
 * ├─────────────────┴───────────────────────────┤
 * │              DTLS (加密)                      │ ← 安全层
 * ├─────────────────────────────────────────────┤
 * │              ICE + UDP                        │ ← 连接层
 * └─────────────────────────────────────────────┘
 */
class WebRTCServer
{

    use DTLS,SCTP,SDP,STUN,UDP,WebSocket,ICE;

    /**
     * @var string
     */
    private $docRoot;
    /**
     * @var string
     */
    private $pushHtmlContent;
    /**
     * @var string
     */
    private $playHtmlContent;
    public $publicIp = '';


    /**
     * 处理通过 HTTP 提交的 SDP Offer（用于 WHIP/WHEP 支持）
     * @param string $role 'push' 或 'play'
     * @param string $streamId
     * @param string $offerSdp
     * @param bool $forceVideoAudioDefault 生成 answer 时是否为 SFU 强制注入 media section
     * @param bool $preferLoopback 请求是否通过本机回环地址进入
     * @return array ['clientId'=>int, 'sdp'=>string]
     */
    public function handleHttpOffer(string $role, string $streamId, string $offerSdp, bool $forceVideoAudioDefault = false, bool $preferLoopback = false): array
    {
        $clientId = ++$this->clientCounter;
        $now = microtime(true);
        $this->clients[$clientId] = [
            'socket' => null,
            'createdAt' => $now,
            'lastSeenAt' => $now,
            'state'  => 'http',
            'buffer' => '',
            'remoteSdp' => null,
            'remoteCandidate' => null,
            'dtlsState' => 'waiting',
            'meta' => ['role' => $role, 'streamId' => $streamId],
        ];

        $sdp = (string)$offerSdp;
        $remoteIceUfrag = $this->extractSdpAttribute($sdp, 'ice-ufrag');
        $remoteIcePwd   = $this->extractSdpAttribute($sdp, 'ice-pwd');
        $remoteSetup    = $this->extractSdpAttribute($sdp, 'setup');

        $this->clients[$clientId]['remoteIceUfrag'] = $remoteIceUfrag;
        $this->clients[$clientId]['remoteIcePwd']   = $remoteIcePwd;

        $opts = [
            'forceVideoAudioDefault' => $forceVideoAudioDefault,
            'whep' => $role === 'play',
            'preferLoopback' => $preferLoopback,
        ];
        if ($role === 'play' && $streamId !== '' && isset($this->_sfuStreamConfig[$streamId]) && is_array($this->_sfuStreamConfig[$streamId])) {
            $cfg = $this->_sfuStreamConfig[$streamId];
            $opts['serverVideoSsrc'] = (int)($cfg['serverVideoSsrc'] ?? 0);
            $opts['serverAudioSsrc'] = (int)($cfg['serverAudioSsrc'] ?? 0);
            $opts['cname'] = (string)($cfg['cname'] ?? '');
            $opts['msidStream'] = (string)($cfg['msidStreamId'] ?? '');
            $opts['msidVideoTrack'] = (string)($cfg['msidVideoTrackId'] ?? '');
            $opts['msidAudioTrack'] = (string)($cfg['msidAudioTrackId'] ?? '');
            $opts['h264ProfileLevelId'] = (string)($cfg['h264ProfileLevelId'] ?? '42e01f');
        }

        $answerInfo = $this->generateAnswerSDP($sdp, $remoteIceUfrag, $remoteIcePwd, $remoteSetup, $opts);

        $localUfrag = (string)($answerInfo['ice-ufrag'] ?? '');
        $localPwd   = (string)($answerInfo['ice-pwd']   ?? '');
        $localSdp   = (string)($answerInfo['sdp']       ?? '');
        if ($localUfrag === '' || $localSdp === '') {
            return ['clientId' => $clientId, 'sdp' => ''];
        }

        $_dbgOfferH264 = [];
        $_dbgOfferVideoMLine = '';
        if (preg_match('/(^m=video[^\r\n]*[\s\S]*?)(?=^m=|\z)/m', $sdp, $_dbgVideoOfferMatch)) {
            $_dbgVideoSection = $_dbgVideoOfferMatch[1];
            if (preg_match('/^m=video[^\r\n]*/m', $_dbgVideoSection, $_dbgMLineMatch)) $_dbgOfferVideoMLine = trim($_dbgMLineMatch[0]);
            $_dbgRtpmapByPt = [];
            $_dbgFmtpByPt = [];
            if (preg_match_all('/^a=rtpmap:(\d+)\s+([^\r\n]+)/mi', $_dbgVideoSection, $_dbgRtpmapMatches, PREG_SET_ORDER)) {
                foreach ($_dbgRtpmapMatches as $_dbgRtpmapMatch) $_dbgRtpmapByPt[(int)$_dbgRtpmapMatch[1]] = trim($_dbgRtpmapMatch[2]);
            }
            if (preg_match_all('/^a=fmtp:(\d+)\s+([^\r\n]+)/mi', $_dbgVideoSection, $_dbgFmtpMatches, PREG_SET_ORDER)) {
                foreach ($_dbgFmtpMatches as $_dbgFmtpMatch) $_dbgFmtpByPt[(int)$_dbgFmtpMatch[1]] = trim($_dbgFmtpMatch[2]);
            }
            foreach ($_dbgRtpmapByPt as $_dbgPt => $_dbgRtpmap) {
                if (stripos($_dbgRtpmap, 'H264/') !== 0) continue;
                $_dbgOfferH264[] = ['pt'=>(int)$_dbgPt,'rtpmap'=>$_dbgRtpmap,'fmtp'=>(string)($_dbgFmtpByPt[$_dbgPt] ?? '')];
            }
        }
        $_dbgAnswerH264 = [];
        if (preg_match('/(^m=video[^\r\n]*[\s\S]*?)(?=^m=|\z)/m', $localSdp, $_dbgVideoAnswerMatch)) {
            $_dbgAnswerSection = $_dbgVideoAnswerMatch[1];
            if (preg_match_all('/^a=rtpmap:(\d+)\s+(H264\/[^\r\n]+)/mi', $_dbgAnswerSection, $_dbgAnswerRtpmapMatches, PREG_SET_ORDER)) {
                foreach ($_dbgAnswerRtpmapMatches as $_dbgAnswerRtpmapMatch) {
                    $_dbgAnswerPt = (int)$_dbgAnswerRtpmapMatch[1];
                    $_dbgAnswerFmtp = '';
                    if (preg_match('/^a=fmtp:' . $_dbgAnswerPt . '\s+([^\r\n]+)/mi', $_dbgAnswerSection, $_dbgAnswerFmtpMatch)) $_dbgAnswerFmtp = trim($_dbgAnswerFmtpMatch[1]);
                    preg_match('/(?:^|;)\s*profile-level-id=([0-9a-fA-F]{6})(?:;|$)/i', $_dbgAnswerFmtp, $_dbgAnswerProfileMatch);
                    $_dbgAnswerH264[] = ['pt'=>$_dbgAnswerPt,'rtpmap'=>trim($_dbgAnswerRtpmapMatch[2]),'fmtp'=>$_dbgAnswerFmtp,'profileLevelId'=>strtolower($_dbgAnswerProfileMatch[1] ?? '')];
                }
            }
        }
        $this->clients[$clientId]['_dbgOfferH264'] = $_dbgOfferH264;
        $this->clients[$clientId]['_dbgAnswerH264'] = $_dbgAnswerH264;
        $this->clients[$clientId]['localIceUfrag'] = $localUfrag;
        $this->clients[$clientId]['localIcePwd']   = $localPwd;
        $this->clients[$clientId]['iceUfrag']      = $localUfrag;
        $this->clients[$clientId]['icePwd']        = $localPwd;
        $this->clients[$clientId]['remoteIcePwdForSTUN'] = $remoteIcePwd;

        $this->clients[$clientId]['videoPTs']        = isset($answerInfo['videoPTs']) && is_array($answerInfo['videoPTs']) ? $answerInfo['videoPTs'] : [];
        $this->clients[$clientId]['audioPTs']        = isset($answerInfo['audioPTs']) && is_array($answerInfo['audioPTs']) ? $answerInfo['audioPTs'] : [];
        $this->clients[$clientId]['serverVideoSsrc'] = (int)($answerInfo['serverVideoSsrc'] ?? 4147483647);
        $this->clients[$clientId]['serverAudioSsrc'] = (int)($answerInfo['serverAudioSsrc'] ?? 3741943039);
        $this->clients[$clientId]['serverSsrc']      = $this->clients[$clientId]['serverVideoSsrc'];
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
        if ($role === 'play') {
            $this->clients[$clientId]['outVideoPT'] = (int)($this->clients[$clientId]['primaryVideoPT'] ?? 0);
            $this->clients[$clientId]['outAudioPT'] = (int)($this->clients[$clientId]['primaryAudioPT'] ?? 0);
        }

        $this->clients[$clientId]['remoteOfferSdp'] = $sdp;

        if ($role === 'push' && $streamId !== '') {
            $videoPTs = isset($answerInfo['videoPTs']) && is_array($answerInfo['videoPTs']) ? $answerInfo['videoPTs'] : [];
            $audioPTs = isset($answerInfo['audioPTs']) && is_array($answerInfo['audioPTs']) ? $answerInfo['audioPTs'] : [];
            $primaryVideoPT = (int)($this->clients[$clientId]['primaryVideoPT'] ?? 0);
            $primaryAudioPT = (int)($this->clients[$clientId]['primaryAudioPT'] ?? 0);
            $serverVideoSsrc = (int)($this->clients[$clientId]['serverVideoSsrc'] ?? 4147483647);
            $serverAudioSsrc = (int)($this->clients[$clientId]['serverAudioSsrc'] ?? 3741943039);

            $cname = (string)($answerInfo['cname'] ?? '');
            $msidStream = (string)($answerInfo['msidStream'] ?? '');
            $msidVideoTrack = (string)($answerInfo['msidVideoTrack'] ?? '');
            $msidAudioTrack = (string)($answerInfo['msidAudioTrack'] ?? '');

            if ($cname === '') {
                $cname = 'SFU_' . $streamId . '_' . $clientId;
            }
            if ($msidStream === '') {
                $msidStream = 'stream_' . $streamId;
            }
            if ($msidVideoTrack === '') {
                $msidVideoTrack = 'video_' . $streamId;
            }
            if ($msidAudioTrack === '') {
                $msidAudioTrack = 'audio_' . $streamId;
            }

            $this->_sfuStreamConfig[$streamId] = [
                'createdAt' => microtime(true),
                'publisherId' => $clientId,
                'videoPTs' => $videoPTs,
                'audioPTs' => $audioPTs,
                'primaryVideoPT' => $primaryVideoPT,
                'primaryAudioPT' => $primaryAudioPT,
                'h264ProfileLevelId' => '42e01f',
                'serverVideoSsrc' => $serverVideoSsrc,
                'serverAudioSsrc' => $serverAudioSsrc,
                'cname' => $cname,
                'msidStreamId' => $msidStream,
                'msidVideoTrackId' => $msidVideoTrack,
                'msidAudioTrackId' => $msidAudioTrack,
                'originalOfferSdp' => $sdp,
            ];

            $this->_log_std("[handleHttpOffer] WHIP 推流端已注册 _sfuStreamConfig[{$streamId}] "
                . "primaryV={$primaryVideoPT} primaryA={$primaryAudioPT} "
                . "vSSRC={$serverVideoSsrc} aSSRC={$serverAudioSsrc}\n");
        }

        if (isset($this->onOffer) && is_callable($this->onOffer)) {
            try {
                $_cb = $this->onOffer;
                $_cb($clientId, $sdp, $localSdp, $this);
            } catch (\Throwable $e) {
                $this->_log_std("Client {$clientId} onOffer exception: " . $e->getMessage() . "\n");
            }
        }

        if ($role === 'push' && isset($this->onPublisher) && is_callable($this->onPublisher)) {
            try {
                $_cb = $this->onPublisher;
                $_cb($clientId, [
                    'streamId'  => $streamId,
                    'localSsrc' => $this->clients[$clientId]['localSsrcByKind'] ?? [],
                    'videoPTs'  => $this->clients[$clientId]['videoPTs'] ?? [],
                    'audioPTs'  => $this->clients[$clientId]['audioPTs'] ?? [],
                ], $this);
            } catch (\Throwable $e) {
                $this->_log_std("Client {$clientId} onPublisher exception: " . $e->getMessage() . "\n");
            }
        }

        if ($role === 'play') {
            $this->_log_std("[handleHttpOffer] WHEP 订阅者已注册 clientId={$clientId} streamId={$streamId}\n");
        }

        return ['clientId' => $clientId, 'sdp' => $localSdp];
    }

    /** 开发模式 */
    public  $isDev = true;
    /** ws服务器 */
    private $wsServer;

    /** udp socket连接 */
    private $udpSocket;

    /** stun socket连接 */
    private $stunSocket;

    /**
     * 客户端连接（public，便于在 onPublisher/onSubscriber/自定义事件里直接读写 PT/SSRC/UDP 地址等底层状态，
     * 与原 server.php 的"公开 client 状态表"的使用习惯保持一致）。
     *
     * 推荐使用 getClientMeta()/setClientMeta() 存业务层字段；
     * 如需读协议层字段（videoPTs/audioPTs/serverVideoSsrc/serverAudioSsrc/remoteIceUfrag 等）可直接访问此数组。
     *
     * @var array<int, array>
     */
    public $clients = [];

    /** @var array<string, array{hasIdr:bool, gop:array<int,string>, lastSpsPps:array<int,string>, lastIdrSeq:?int, lastPliSentTs:float, lastKfBurstSids:array<int,float>, lastPeriodicPliTs:float, lastSpsAt:float, lastPpsAt:float, _retryKicks:array<int,array{0:float,1:bool,2:bool,3:bool}>}> */
    private $_gopCacheByStream = [];

    /** @var array<string, array{
     *   createdAt:float,
     *   publisherId:int,
     *   videoPTs:array<int,array{rtpmap:?string,fmtp:?string,codec:?string,clock:int}>,
     *   audioPTs:array<int,array{rtpmap:?string,fmtp:?string,codec:?string,clock:int}>,
     *   primaryVideoPT:int,
     *   primaryAudioPT:int,
     *   serverVideoSsrc:int,
     *   serverAudioSsrc:int,
     *   msidStreamId:string,
     *   msidVideoTrackId:string,
     *   msidAudioTrackId:string,
     *   cname:string,
     *   originalOfferSdp:string
     * }> */
    private $_sfuStreamConfig = [];

    /**
     * 从指定PT map中智能挑选"第一个有真实编解码"的PT作为primary（跳过空codec、RED、RTX等冗余条目）。
     * 背景：generateAnswerSDP返回的videoPTs第一个key可能是RED(REDundant/重传RTX)，傻选第一个会导致
     * primaryVideoPT=RED/RTX → UDP转发时把VP8/H264的真实包改为RED PT → 浏览器无法解码 → 黑屏。
     */
    private function _pickRealPrimaryPT(array $ptMap, string $kind): int
    {
        $realCodes = $kind === 'video'
            ? ['h264','avc','vp8','vp9','h265','hevc','av1','h263','mpeg4','mp4v','theora']
            : ['opus','pcmu','pcma','g722','isac','ilbc','speex','gsm','l16','aac','ac3','eac3','mpa','g726'];
        $knownBad = ['red','rtx','ulpfec','flexfec','fec','x-ulpfec','x-red','rtx-red','telephone-event','cn'];

        $videoPreferred = ['h264','avc'];
        $audioPreferred = ['opus'];
        $firstPreferred = 0;
        foreach ($ptMap as $pt => $info) {
            $pt = (int)$pt;
            if (!is_array($info)) continue;
            $c = '';
            if (!empty($info['codec'])) $c = strtolower(trim($info['codec']));
            elseif (!empty($info['rtpmap'])) {
                $rm = explode('/', trim($info['rtpmap']));
                $c = strtolower(trim($rm[0] ?? ''));
            }

            if ($c !== '' && in_array($c, $knownBad, true)) continue;
            if ($kind === 'video' && $c !== '' && in_array($c, $videoPreferred, true)) return $pt;
            if ($kind === 'audio' && $c !== '' && in_array($c, $audioPreferred, true)) return $pt;

            if ($firstPreferred <= 0) {
                if ($kind === 'video' && $c !== '' && in_array($c, $videoPreferred, true)) $firstPreferred = $pt;
                if ($kind === 'audio' && $c !== '' && in_array($c, $audioPreferred, true)) $firstPreferred = $pt;
            }
        }
        if ($firstPreferred > 0) return $firstPreferred;

        return 0;
    }

    /**
     *  以实际发包PT为准，不相信SDP声明的傻primary！
     *   浏览器推流经常出现"SDP声明primaryVideoPT=123(H264)，实际却选VP8(pt=103/96发包)"的矛盾，
     *   导致订阅者primaryV=123 → protectAndSendRtp翻译为123 → VP8内容写H264 PT → 浏览器100%无法解码→黑屏。
     *
     * 本函数在推流端每次收到SRTP-IN包时被UDP trait回调，做以下修正（幂等，第一包后直接return）：
     *   1. 修正 publisher 自己的 primaryVideoPT + videoPTs 顺序
     *   2. 同步刷新 _sfuStreamConfig 的 primaryVideoPT + videoPTs（所有未来新订阅者继承正确值）
     *   3. 刷新所有同 streamId 已在线 play 端的 primaryVideoPT（转发时PT翻译正确）
     *
     * @param int    $publisherId  推流端 clientId
     * @param string $streamId     streamId
     * @param int    $actualPT     实际收到的 RTP PT
     * @param string $kind         'video' | 'audio'
     * @param array  $_ignoredPtMap 保留参数，未使用
     * @return void
     */
    public function _refreshPrimaryFromActualPacket(int $publisherId, string $streamId, int $actualPT, string $kind, array $_ignoredPtMap = [], int $actualSSRC = 0): void
    {
        if ($streamId === '' || $actualPT <= 0 || ($kind !== 'video' && $kind !== 'audio')) return;

        $k = "{$streamId}_{$kind}";
        $confirmed = $this->_actualPrimaryByStreamKind[$k] ?? null;
        if (is_array($confirmed)
            && (int)($confirmed['pt'] ?? 0) === $actualPT
            && (int)($confirmed['ssrc'] ?? 0) === $actualSSRC) {
            return;
        }
        unset($this->_primaryRefreshDone[$k]);

        $pub = $this->clients[$publisherId] ?? null;
        if (!$pub || !is_array($pub)) return;
        $metaRole = (string)($pub['meta']['role'] ?? '');
        if ($metaRole !== 'push') return;

        $ptList = $kind === 'video'
            ? (is_array($pub['videoPTs'] ?? null) ? $pub['videoPTs'] : [])
            : (is_array($pub['audioPTs'] ?? null) ? $pub['audioPTs'] : []);
        $currPrimary = $kind === 'video'
            ? (int)($pub['primaryVideoPT'] ?? 0)
            : (int)($pub['primaryAudioPT'] ?? 0);

        $_ptAlreadyInMap = isset($ptList[$actualPT]);
        $_detectedCodec = '';
        $_cloneSourceInfo = null;
        if ($_ptAlreadyInMap && is_array($ptList[$actualPT])) {
            $_info = $ptList[$actualPT];
            if (!empty($_info['codec'])) {
                $_detectedCodec = strtolower(trim((string)$_info['codec']));
            } elseif (!empty($_info['rtpmap'])) {
                $_rm = explode('/', trim((string)$_info['rtpmap']));
                $_detectedCodec = strtolower(trim($_rm[0] ?? ''));
            }
            $_cloneSourceInfo = $_info;
        }
        foreach ($ptList as $_ptDummy => $_i) {
            if (!is_array($_i)) continue;
            $c = '';
            if (!empty($_i['codec'])) $c = strtolower(trim((string)$_i['codec']));
            elseif (!empty($_i['rtpmap'])) {
                $_rm2 = explode('/', trim((string)$_i['rtpmap']));
                $c = strtolower(trim($_rm2[0] ?? ''));
            }
            if ($kind === 'video' && ($c === 'h264' || $c === 'avc')) { $_cloneSourceInfo = $_i; break; }
            if ($kind === 'audio' && $c === 'opus') { $_cloneSourceInfo = $_i; break; }
        }
        if ($_detectedCodec === '') {
            if ($_cloneSourceInfo !== null) {
                $c = '';
                if (!empty($_cloneSourceInfo['codec'])) $c = strtolower(trim((string)$_cloneSourceInfo['codec']));
                elseif (!empty($_cloneSourceInfo['rtpmap'])) {
                    $_rm3 = explode('/', trim((string)$_cloneSourceInfo['rtpmap']));
                    $c = strtolower(trim($_rm3[0] ?? ''));
                }
                $_detectedCodec = $c;
            }
        }
        $_makeInfo = function() use ($kind, $_cloneSourceInfo, $actualPT, $_detectedCodec) {
            if ($_cloneSourceInfo !== null && is_array($_cloneSourceInfo)) {
                $out = $_cloneSourceInfo;
                return $out;
            }
            if ($kind === 'video') {
                return ['rtpmap' => 'H264/90000', 'codec' => 'H264', 'clock' => 90000,
                        'fmtp' => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f'];
            }
            return ['rtpmap' => 'opus/48000/2', 'codec' => 'opus', 'clock' => 48000,
                    'fmtp' => 'minptime=10;useinbandfec=1'];
        };
        $_newInfo = $_makeInfo();
        $_allowed = false;
        if ($kind === 'video') {
            $_allowed = ($_detectedCodec === 'h264' || $_detectedCodec === 'avc');
            if (!$_allowed && empty($_ptAlreadyInMap)) {
                $_allowed = true;
                $_detectedCodec = 'h264';
            }
        } else {
            $_allowed = ($_detectedCodec === 'opus');
            if (!$_allowed && empty($_ptAlreadyInMap)) {
                $_allowed = true;
                $_detectedCodec = 'opus';
            }
        }
        if (!$_allowed) {
            $this->_actualPrimaryByStreamKind[$k] = ['pt' => $actualPT, 'ssrc' => $actualSSRC];
            $this->_log_std("[refreshPrimary  BLOCKED stream={$streamId} kind={$kind}] 实际发包PT={$actualPT}(detectedCodec={$_detectedCodec}) 不是允许的主编码(video仅H264/audio仅OPUS)，"
                            . "**拒绝刷新 primary**（保持原primary={$currPrimary}不变）。请检查 push 端浏览器是否偷偷切了编码！\n");
            return;
        }

        $_patchedPublisher = false;
        $_patchedSfuCfg = false;
        if (!isset($ptList[$actualPT])) {
            $ptList[$actualPT] = $_newInfo;
            $_patchedPublisher = true;
        }
        $this->clients[$publisherId][$kind === 'video' ? 'sourceVideoPT' : 'sourceAudioPT'] = $actualPT;
        $this->clients[$publisherId][$kind === 'video' ? 'sourceVideoSsrc' : 'sourceAudioSsrc'] = $actualSSRC;
        $sfuUpdatedPts = null;
        if (isset($this->_sfuStreamConfig[$streamId]) && is_array($this->_sfuStreamConfig[$streamId])) {
            $cfg = &$this->_sfuStreamConfig[$streamId];
            $cfgKey = $kind === 'video' ? 'videoPTs' : 'audioPTs';
            if (!isset($cfg[$cfgKey]) || !is_array($cfg[$cfgKey])) $cfg[$cfgKey] = [];
            if (!isset($cfg[$cfgKey][$actualPT])) {
                $cfg[$cfgKey][$actualPT] = $_newInfo;
                $_patchedSfuCfg = true;
            }
            $sfuUpdatedPts = $cfg[$cfgKey];
            unset($cfg);
        }
        if ($currPrimary === $actualPT && !$_patchedPublisher && !$_patchedSfuCfg) {
            $this->_primaryRefreshDone[$k] = true;
            $this->_actualPrimaryByStreamKind[$k] = ['pt' => $actualPT, 'ssrc' => $actualSSRC];
            return;
        }
        $this->_log_std("[refreshPrimary  stream={$streamId} kind={$kind}] "
                        . "SDP声明primary={$currPrimary} vs 实际发包PT={$actualPT}不一致 → "
                        . "纠正source primary={$actualPT}，补PT：publisher[" . ($_patchedPublisher?'YES':'no')
                        . "] sfuCfg[" . ($_patchedSfuCfg?'YES':'no')
                        . "]，保留已协商subscriber target PT，detectedCodec={$_detectedCodec}\n");
        $this->_primaryRefreshDone[$k] = true;
        if ($kind === 'video') {
            $this->clients[$publisherId]['primaryVideoPT'] = $actualPT;
            $this->clients[$publisherId]['videoPTs'] = $this->_reorderPTsForSubscriber($ptList, $actualPT);
        } else {
            $this->clients[$publisherId]['primaryAudioPT'] = $actualPT;
            $this->clients[$publisherId]['audioPTs'] = $this->_reorderPTsForSubscriber($ptList, $actualPT);
        }

        if (isset($this->_sfuStreamConfig[$streamId]) && is_array($this->_sfuStreamConfig[$streamId])) {
            $cfg = &$this->_sfuStreamConfig[$streamId];
            if ($kind === 'video') {
                $cfg['primaryVideoPT'] = $actualPT;
                $cfg['sourceVideoPT'] = $actualPT;
                $cfg['sourceVideoSsrc'] = $actualSSRC;
                $cfg['videoPTs'] = $this->_reorderPTsForSubscriber(is_array($cfg['videoPTs'] ?? []) ? $cfg['videoPTs'] : $ptList, $actualPT);
            } else {
                $cfg['primaryAudioPT'] = $actualPT;
                $cfg['sourceAudioPT'] = $actualPT;
                $cfg['sourceAudioSsrc'] = $actualSSRC;
                $cfg['audioPTs'] = $this->_reorderPTsForSubscriber(is_array($cfg['audioPTs'] ?? []) ? $cfg['audioPTs'] : $ptList, $actualPT);
            }
            $this->_log_std("[refreshPrimary] _sfuStreamConfig[{$streamId}] primary" . ($kind==='video'?'V':'A') . " → {$actualPT}. 未来所有新订阅者继承.\n");
            unset($cfg);
        }

        $this->_actualPrimaryByStreamKind[$k] = ['pt' => $actualPT, 'ssrc' => $actualSSRC];
    }

    /**
     * 从指定client的videoPTs/audioPTs中"强制按推流端primaryPT排第一"重新排序，
     * 确保所有订阅者offer里m=video行的第一个PT=推流端primaryVideoPT（RFC3264第一偏好优先协商）。
     * 未出现过的PT保留原顺序。
     */
    private function _reorderPTsForSubscriber(array $ptMap, int $primaryPT): array
    {
        if ($primaryPT <= 0 || !isset($ptMap[$primaryPT])) return $ptMap;
        $out = [$primaryPT => $ptMap[$primaryPT]];
        foreach ($ptMap as $pt => $info) {
            if ($pt === $primaryPT) continue;
            $out[$pt] = $info;
        }
        return $out;
    }

    /**
     * 创建一份全新的 GOP 缓存结构体（所有字段默认值，避免 undefined index）
     * @return array
     */
    private function _newGopCacheEntry(): array
    {
        return [
            'hasIdr'             => false,
            'gop'                => [],
            'lastSpsPps'         => [],
            'lastIdrSeq'         => null,
            'lastPliSentTs'      => 0.0,
            'generation'          => 0,
            'lastBurstGeneration' => [],
            'lastKfBurstSids'     => [],
            'lastPeriodicPliTs'  => 0.0,
            'gopSoftLimitTs'     => null,
            'gopCacheClosed'     => false,
            'lastSpsAt'          => 0.0,
            'lastPpsAt'          => 0.0,
            '_retryKicks'        => [],
        ];
    }

    /**
     * 【对齐 RTMP keyint=2 秒】周期检查：≥2s 就给 publisher 打一次 PLI 强制 IDR
     *   调用位置：每收到一个视频 RTP 包就检查一次（无额外定时开销）
     * @param string $streamId
     * @return void
     */
    private function _ensurePeriodicKeyFrame(string $streamId): void
    {
        if (!isset($this->_gopCacheByStream[$streamId])) {
            $this->_gopCacheByStream[$streamId] = $this->_newGopCacheEntry();
        }
        $gc = $this->_gopCacheByStream[$streamId];
        $now = microtime(true);
        if (!isset($gc['_retryKicks']) || !is_array($gc['_retryKicks'])) {
            $gc['_retryKicks'] = [];
            $this->_gopCacheByStream[$streamId] = $gc;
        }
        $toRemove = [];
        foreach ($gc['_retryKicks'] as $sid => $r) {
            if (!isset($this->clients[$sid]) || !empty($this->clients[$sid]['_liveVidSent'])) {
                $toRemove[] = $sid;
                continue;
            }
            $dt = $now - (float)$r[0];
            $label = null;
            if (empty($r[1]) && $dt >= 0.8) {
                $r[1] = true;
                $label = '800ms';
            } elseif (empty($r[2]) && $dt >= 2.0) {
                $r[2] = true;
                $label = '2000ms';
            } elseif (empty($r[3]) && $dt >= 5.0) {
                $r[3] = true;
                $label = '5000ms';
            }
            if ($label === null) continue;

            $this->_log_std("[秒开 {$label} 重注] subscriber={$sid} streamId={$streamId} dt=" . number_format($dt, 3) . "s → PLI+GOP\n");
            $this->sendPliToPublisher($streamId, false);
            $sent = $this->_burstCachedGopToSubscriber($streamId, (int)$sid);
            if ($sent > 0 && !empty($this->clients[$sid]['_liveVidSent'])) {
                $this->_log_std("[秒开 {$label} 重注] subscriber={$sid} burst {$sent} cached GOP frames\n");
                $toRemove[] = $sid;
            } else {
                $gc = $this->_gopCacheByStream[$streamId] ?? $gc;
                $gc['_retryKicks'][$sid] = $r;
                $this->_gopCacheByStream[$streamId] = $gc;
            }
        }
        if (!empty($toRemove)) {
            $gc = $this->_gopCacheByStream[$streamId];
            foreach ($toRemove as $sid2) {
                if (isset($gc['_retryKicks'][$sid2])) {
                    unset($gc['_retryKicks'][$sid2]);
                }
            }
            $this->_gopCacheByStream[$streamId] = $gc;
        }
    }

    /** 关键帧定期重注兜底周期（秒）：实时直播 GOP=2s，保守 3s 重注一次防画面卡死 */
    private $_kfReinjectIntervalSec = 3.0;

    /** @var array<string,bool> _refreshPrimaryFromActualPacket 幂等标记，key="{$streamId}_{$kind}" */
    private $_primaryRefreshDone = [];
    /** @var array<string,array{pt:int,ssrc:int}> 推流端最近确认的实际 RTP PT/SSRC，key="{$streamId}_{$kind}" */
    private $_actualPrimaryByStreamKind = [];
    /** @var array<string,float> VP8 关键帧 TS 去重，key=streamId，value=RTP timestamp(90kHz) */
    private $_vp8LastKfTsByStream = [];

    private $_dbgMediaPerf = [];

    private function _dbgPerfPipelineStage(string $streamId, string $stage, int $elapsedNs, int $bytes = 0, int $targetCount = 0): void
    {
        if (!isset($this->_dbgMediaPerf['pipeline'][$streamId])) {
            $this->_dbgMediaPerf['pipeline'][$streamId] = ['streamId'=>$streamId,'stages'=>[]];
        }
        if (!isset($this->_dbgMediaPerf['pipeline'][$streamId]['stages'][$stage])) {
            $this->_dbgMediaPerf['pipeline'][$streamId]['stages'][$stage] = ['count'=>0,'bytes'=>0,'targetCountSum'=>0,'nsSum'=>0,'nsMax'=>0];
        }
        $metric = &$this->_dbgMediaPerf['pipeline'][$streamId]['stages'][$stage];
        $metric['count']++;
        $metric['bytes'] += $bytes;
        $metric['targetCountSum'] += $targetCount;
        $metric['nsSum'] += $elapsedNs;
        if ($elapsedNs > $metric['nsMax']) $metric['nsMax'] = $elapsedNs;
        unset($metric);
    }

    private function _dbgPerfPublisherInbound(int $clientId, string $streamId, string $kind, int $bytes, int $timestamp, int $seq, int $marker): void
    {
        if (!isset($this->_dbgMediaPerf['publishers'][$clientId])) {
            $this->_dbgMediaPerf['publishers'][$clientId] = ['clientId'=>$clientId,'streamId'=>$streamId,'video'=>['packetCount'=>0,'markerCount'=>0,'distinctTimestampCount'=>0,'seqGap'=>0,'bytes'=>0,'lastTimestamp'=>null,'lastSeq'=>null],'audio'=>['packetCount'=>0,'bytes'=>0]];
        }
        $publisher = &$this->_dbgMediaPerf['publishers'][$clientId];
        if ($kind === 'video') {
            $video = &$publisher['video'];
            $video['packetCount']++;
            $video['markerCount'] += $marker;
            $video['bytes'] += $bytes;
            if ($video['lastTimestamp'] === null || $video['lastTimestamp'] !== $timestamp) $video['distinctTimestampCount']++;
            if ($video['lastSeq'] !== null && $seq !== (($video['lastSeq'] + 1) & 0xFFFF)) $video['seqGap']++;
            $video['lastTimestamp'] = $timestamp;
            $video['lastSeq'] = $seq;
            unset($video);
        } elseif ($kind === 'audio') {
            $publisher['audio']['packetCount']++;
            $publisher['audio']['bytes'] += $bytes;
        }
        unset($publisher);
    }

    private function _dbgPerfSubscriberVideo(int $clientId, int $bytes, int $rewriteNs, int $protectNs, int $sendNs, bool $ok, ?int $seq = null, ?int $timestamp = null, int $marker = 0): void
    {
        if (!isset($this->_dbgMediaPerf['subscribers'][$clientId])) {
            $this->_dbgMediaPerf['subscribers'][$clientId] = ['clientId'=>$clientId,'packetCount'=>0,'bytes'=>0,'markers'=>0,'seqGaps'=>0,'timestampBackwards'=>0,'sendFailure'=>0,'rewriteNsSum'=>0,'rewriteNsMax'=>0,'protectNsSum'=>0,'protectNsMax'=>0,'sendNsSum'=>0,'sendNsMax'=>0,'lastSeq'=>null,'lastTimestamp'=>null];
        }
        $subscriber = &$this->_dbgMediaPerf['subscribers'][$clientId];
        $subscriber['packetCount']++;
        $subscriber['bytes'] += $bytes;
        $subscriber['markers'] += $marker;
        if ($seq !== null && $subscriber['lastSeq'] !== null) {
            $delta = (($seq - (int)$subscriber['lastSeq'] + 0x8000) & 0xFFFF) - 0x8000;
            if ($delta > 1) $subscriber['seqGaps']++;
        }
        if ($timestamp !== null && $subscriber['lastTimestamp'] !== null) {
            $tsDelta = (($timestamp - (int)$subscriber['lastTimestamp']) & 0xFFFFFFFF);
            if ($tsDelta > 0x80000000) $subscriber['timestampBackwards']++;
        }
        if ($seq !== null) $subscriber['lastSeq'] = $seq;
        if ($timestamp !== null) $subscriber['lastTimestamp'] = $timestamp;
        $subscriber['rewriteNsSum'] += $rewriteNs;
        if ($rewriteNs > $subscriber['rewriteNsMax']) $subscriber['rewriteNsMax'] = $rewriteNs;
        $subscriber['protectNsSum'] += $protectNs;
        if ($protectNs > $subscriber['protectNsMax']) $subscriber['protectNsMax'] = $protectNs;
        $subscriber['sendNsSum'] += $sendNs;
        if ($sendNs > $subscriber['sendNsMax']) $subscriber['sendNsMax'] = $sendNs;
        if (!$ok) $subscriber['sendFailure']++;
        unset($subscriber);
    }

    private function _dbgPerfBurstEvent(string $streamId, string $type): void
    {
        if (!isset($this->_dbgMediaPerf['bursts'][$streamId])) $this->_dbgMediaPerf['bursts'][$streamId] = ['streamId'=>$streamId,'idrCount'=>0,'pliCount'=>0,'gopBurstCount'=>0];
        $key = $type . 'Count';
        $this->_dbgMediaPerf['bursts'][$streamId][$key]++;
    }

    private function _dbgPerfLoopIteration(float $now): void
    {
        if (!isset($this->_dbgMediaPerf['loop'])) {
            $this->_dbgMediaPerf['loop'] = ['lastAt'=>$now,'tickCount'=>0,'gapSumUs'=>0,'gapMaxUs'=>0];
            $this->_dbgMediaPerf['lastReportAt'] = $now;
            $this->_dbgMediaPerf['lastRusage'] = function_exists('getrusage') ? @getrusage() : null;
        }
        $loop = &$this->_dbgMediaPerf['loop'];
        $gapUs = (int)(($now - (float)$loop['lastAt']) * 1000000);
        if ($gapUs < 0) $gapUs = 0;
        $loop['lastAt'] = $now;
        $loop['tickCount']++;
        $loop['gapSumUs'] += $gapUs;
        if ($gapUs > $loop['gapMaxUs']) $loop['gapMaxUs'] = $gapUs;

        if ($gapUs >= 250000) {
            $pushClients = [];
            foreach ($this->clients as $clientId => $client) {
                if (($client['meta']['role'] ?? '') === 'push') $pushClients[] = (int)$clientId;
            }
            if ($pushClients) {
                $this->_log_std("[DEBUG event loop stall] gapMs=" . number_format($gapUs / 1000, 1, '.', '')
                    . " pushClients=" . implode(',', $pushClients) . "\n");
            }
        }

        unset($loop);

        if (($now - (float)$this->_dbgMediaPerf['lastReportAt']) < 1.0) return;
        $usage = function_exists('getrusage') ? @getrusage() : null;
        $previousUsage = $this->_dbgMediaPerf['lastRusage'] ?? null;
        $cpu = null;
        if (is_array($usage) && is_array($previousUsage)) {
            $cpu = ['userDeltaMs'=>(($usage['ru_utime.tv_sec'] ?? 0)-($previousUsage['ru_utime.tv_sec'] ?? 0))*1000+(($usage['ru_utime.tv_usec'] ?? 0)-($previousUsage['ru_utime.tv_usec'] ?? 0))/1000,'systemDeltaMs'=>(($usage['ru_stime.tv_sec'] ?? 0)-($previousUsage['ru_stime.tv_sec'] ?? 0))*1000+(($usage['ru_stime.tv_usec'] ?? 0)-($previousUsage['ru_stime.tv_usec'] ?? 0))/1000];
        }
        $publishers = array_values($this->_dbgMediaPerf['publishers'] ?? []);
        foreach ($publishers as &$publisher) unset($publisher['video']['lastTimestamp'], $publisher['video']['lastSeq']);
        unset($publisher);
        $pipeline = array_values($this->_dbgMediaPerf['pipeline'] ?? []);
        foreach ($pipeline as &$streamPipeline) {
            foreach ($streamPipeline['stages'] as &$stage) {
                $stage['msSum'] = $stage['nsSum'] / 1000000;
                $stage['msMax'] = $stage['nsMax'] / 1000000;
                unset($stage['nsSum'], $stage['nsMax']);
            }
            unset($stage);
        }
        unset($streamPipeline);
        $subscribers = array_values($this->_dbgMediaPerf['subscribers'] ?? []);
        $_obsSubscriberContinuity = [];
        foreach ($subscribers as &$subscriber) {
            $_obsSubscriberContinuity[(int)$subscriber['clientId']] = ['lastSeq'=>$subscriber['lastSeq'],'lastTimestamp'=>$subscriber['lastTimestamp']];
            $subscriber['rewriteMsSum'] = $subscriber['rewriteNsSum'] / 1000000;
            $subscriber['rewriteMsMax'] = $subscriber['rewriteNsMax'] / 1000000;
            $subscriber['protectMsSum'] = $subscriber['protectNsSum'] / 1000000;
            $subscriber['protectMsMax'] = $subscriber['protectNsMax'] / 1000000;
            $subscriber['sendMsSum'] = $subscriber['sendNsSum'] / 1000000;
            $subscriber['sendMsMax'] = $subscriber['sendNsMax'] / 1000000;
            unset($subscriber['rewriteNsSum'], $subscriber['rewriteNsMax'], $subscriber['protectNsSum'], $subscriber['protectNsMax'], $subscriber['sendNsSum'], $subscriber['sendNsMax'], $subscriber['lastSeq'], $subscriber['lastTimestamp']);
        }
        unset($subscriber);
        $loop = $this->_dbgMediaPerf['loop'];



        $this->_dbgMediaPerf = ['lastReportAt'=>$now,'lastRusage'=>$usage,'loop'=>['lastAt'=>$now,'tickCount'=>0,'gapSumUs'=>0,'gapMaxUs'=>0]];
        foreach ($_obsSubscriberContinuity as $_obsClientId => $_obsLast) {
            $this->_dbgMediaPerf['subscribers'][$_obsClientId] = ['clientId'=>$_obsClientId,'packetCount'=>0,'bytes'=>0,'markers'=>0,'seqGaps'=>0,'timestampBackwards'=>0,'sendFailure'=>0,'rewriteNsSum'=>0,'rewriteNsMax'=>0,'protectNsSum'=>0,'protectNsMax'=>0,'sendNsSum'=>0,'sendNsMax'=>0,'lastSeq'=>$_obsLast['lastSeq'],'lastTimestamp'=>$_obsLast['lastTimestamp']];
        }
    }

    /** udp地址映射表 */
    private $udpAddrMap = [];

    /** 客户端计数器 */
    private $clientCounter = 0;

    /** HTTP WHEP 失联资源上次扫描时间 */
    private $lastHttpPlayCleanupAt = 0.0;

    /** Publisher RR 周期调度时间。 */
    private $lastPublisherRrAt = 0.0;

    /** 首页index.html内容 */
    private $indexContent;

    /** 证书路径 */
    private $certPath;

    /** 秘钥路径 */
    private $keyPath;

    /** dtls上下文 */
    private $dtlsContext;

    /** 连接建立事件（WebSocket 升级完成） */
    public $onOpen = null;

    /**
     * 用户设置的回调函数，当接受到消息的时候触发
     * @var callable|null User-registered callback for incoming DataChannel messages.
     *            Signature: function (string $message, int $clientId, WebRTCServer $server): void
     *            If null, server echoes the message back to the sender as a demo.
     */
    public $onmessage = null;

    /**
     * 收到 SRTP 解出的明文 RTP 包时触发（可选）。
     * 不注册则走默认转发逻辑：
     *   - 若推流端 metadata['role'] === 'push'：自动转发给同 metadata['streamId'] 的所有 play 端（SFU 模式）
     *   - 否则 echo：按 PT 判断音/视频，重写 SSRC 为服务端 SSRC，再 protect 发回（echo demo 模式）。
     * 签名：function (int $clientId, string $plainRtp, array $parsedHeader, WebRTCServer $srv): void
     *   $parsedHeader = [v, pt, seq, ts, ssrc, hdrLen, payloadLen]
     * @var callable|null
     */
    public $onRtp = null;

    /** 连接关闭事件（WebSocket 关闭时） */
    public $onClose = null;

    /**
     * 任何信令消息到达时先触发（优先级最高）。
     * 签名：function (int $clientId, array $msg, WebRTCServer $srv, ?bool &$handled): void
     *   - $msg = json_decode($text, true) 的数组，保证是 array
     *   - 用户回调内若把 $handled 引用参数设为 true，则服务端跳过默认 handleSignaling
     *     (offer/candidate/join 等默认处理全部停止)，完全交由用户接管。
     *   - 若 $handled 保持 null/false，则继续走默认分发（join -> onJoin -> 默认处理，offer/candidate 也一样）。
     *
     * 设计意图：用户用这个一个接口就能完全接管信令，无侵入实现任意房间系统。
     */
    public $onSignaling = null;

    /**
     * 客户端发送 {type:"join", role:"push"/"play", streamId:"..."} 时触发。
     * 签名：function (int $clientId, array $joinMsg, WebRTCServer $srv, ?bool &$handled): void
     *   - $joinMsg = type + role + streamId 等完整字段
     *   - 设置 $handled=true 则跳过默认处理（默认会回传 {"type":"joined"} 并存 role/streamId 到 metadata）。
     */
    public $onJoin = null;

    /**
     * 连接被关闭时触发（比 onClose 更语义化，与 onJoin 配对，均在 WebSocket 层面）。
     * 签名：function (int $clientId, WebRTCServer $srv): void
     */
    public $onLeave = null;

    /**
     * 推流端完成 SDP Answer（服务端给 push 端回完 answer）且 metadata['role']==='push' 时触发，
     * 表明一个 Publisher 已就绪可接收媒体。
     * 签名：function (int $clientId, array $context, WebRTCServer $srv): void
     *   $context = [
     *       'streamId'  => string,
     *       'localSsrc' => ['video'=>int, 'audio'=>int],
     *       'videoPTs'  => [...],
     *       'audioPTs'  => [...],
     *   ]
     */
    public $onPublisher = null;

    /**
     * 订阅者 metadata['role']==='play' 完成信令 join（或完成 answer，缺省 SFU 在 join 就触发），
     * 表示一个 Subscriber 已就绪可接收媒体分发。
     * 签名：function (int $clientId, array $context, WebRTCServer $srv): void
     *   $context = ['streamId'=>string, 'pushClientId'=>(?int 当前此流的 push 端)]
     */
    public $onSubscriber = null;

    /**
     * 任意端 Offer 流程走完（接收 offer 并成功 send answer 给该 client 后）触发。
     * 注意：SFU 下 push 端是 offer 发送者；play 端通常也是 offer 发送者（receive-only）。
     * 签名：function (int $clientId, string $remoteSdp, string $localSdp, WebRTCServer $srv): void
     */
    public $onOffer = null;

    /**
     * 服务端收到客户端 answer 时触发（当前实现 play 端作为 offeree 时的场景）。
     * 签名：function (int $clientId, string $answerSdp, WebRTCServer $srv, ?bool &$handled): void
     */
    public $onAnswer = null;

    /**
     * 收到任意端 ICE candidate。
     * 签名：function (int $clientId, array $candidateMsg, WebRTCServer $srv, ?bool &$handled): void
     *   - 设 $handled=true 可跳过默认服务端 candidate 存储。
     */
    public $onCandidate = null;

    /**
     * 某客户端首个 SRTP 包成功 unprotect 时触发（ICE+DTLS+SRTP 链路全通，真正有媒体）。
     * 签名：function (int $clientId, array $firstRtpHeader, WebRTCServer $srv): void
     *   $firstRtpHeader = [pt, seq, ts, ssrc, payloadLen]
     */
    public $onMediaConnected = null;

    public $logFile ;

    /** 持久日志文件句柄（避免每次file_put_contents打开/关闭的开销） */
    private $logFp = null;

    public $wsPort = 8088;

    public $udpPort = 8089;

    public $stunPort=  3478;

    /**
     * 初始化webrtc服务器
     * @param int $wsPort ws服务端口
     * @param int $udpPort udp服务端口
     * @param int $stunPort stun服务端口
     * @param string $logFile 日志文件路径
     * @param string $rootDir 静态文件目录
     */
    public function __construct(int $wsPort =  8088,int $udpPort =  8089,int $stunPort = 3478 ,string $logFile = "",string $rootDir = "" )
    {
        if ($wsPort){
            $this->wsPort = $wsPort;
        }
        if ($udpPort){
            $this->udpPort = $udpPort;
        }
        if ($stunPort){
            $this->stunPort = $stunPort;
        }
        if ($logFile){
            $this->logFile = $logFile;
        }else{
            $this->logFile = __DIR__ . '/server_debug.log';
        }
        @file_put_contents($this->logFile, '');
        /** 静态文件目录 */
        if(empty($rootDir)){
            $rootDir = dirname(__DIR__);
        }
        $this->docRoot = rtrim(strtr($rootDir, '\\', '/'), '/');
        /** 生成证书 */
        $this->generateCertificate();
        /** 创建dtls上下文 */
        $this->createDTLSContext();
    }

    /**
     * 日志类
     * @param string $msg
     * @return void
     * @note 用户可以替换为自己的日志方法
     */
    public function _log_std(string $msg)
    {
        if ($this->isDev){
            fwrite(STDOUT, $msg);
            if ($this->logFp === null && $this->logFile) {
                $this->logFp = @fopen($this->logFile, 'a');
                if ($this->logFp) {
                    @stream_set_write_buffer($this->logFp, 65536);
                }
            }
            if ($this->logFp) {
                @fwrite($this->logFp, $msg);
            }
        }
    }

    /**
     * 启动服务器
     * @return void
     */
    public function start()
    {
        /** 启动ws服务器 */
        $this->startWebSocketServer();
        /** 启动udp服务器 */
        $this->startUDPServer();
        /** 启动stun服务器 */
        $this->startSTUNServer();
        /** 启动服务器轮训 */
        $this->runEventLoop();
    }

    /**
     * 信令消息分发器（默认实现，可被 $onSignaling 回调完全接管）
     * 消息顺序：
     *   1) 任何消息 → 先触发 onSignaling，若 $handled=true → 跳过默认处理
     *   2) type='join'   → 触发 onJoin → 默认存 role/streamId + 回 {"type":"joined"}
     *   3) type='offer'  → 触发 onCandidate 前先检查 handled → 默认 handleOffer() + 触发 onOffer
     *   4) type='answer' → 触发 onAnswer → 若 handled=false 则存远端 answer sdp
     *   5) type='candidate' → 触发 onCandidate → 若 handled=false 存远端 candidate
     *
     * @param $clientId
     * @param $message
     * @return void
     */
    private function handleSignaling($clientId, $message)
    {
        $msg = json_decode($message, true);
        if (!is_array($msg)) return;
        $clientId = (int)$clientId;

        if (isset($this->onSignaling) && is_callable($this->onSignaling)) {
            $handled = null;
            try {
                $_cb = $this->onSignaling;
                $_cb($clientId, $msg, $this, $handled);
            } catch (\Throwable $e) {
                $this->_log_std("Client {$clientId} onSignaling callback exception: " . $e->getMessage() . "\n");
            }
            if ($handled === true) {
                $this->_log_std("Client {$clientId} signaling handled=TRUE via onSignaling, skip default.\n");
                return;
            }
        }

        $type = (string)($msg['type'] ?? '');

        switch ($type) {
            case 'join': {
                $joinHandled = null;
                if (isset($this->onJoin) && is_callable($this->onJoin)) {
                    try {
                        $_cb = $this->onJoin;
                        $_cb($clientId, $msg, $this, $joinHandled);
                    } catch (\Throwable $e) {
                        $this->_log_std("Client {$clientId} onJoin exception: " . $e->getMessage() . "\n");
                    }
                }
                if ($joinHandled !== true) {
                    $role     = (string)($msg['role'] ?? '');
                    $streamId = (string)($msg['streamId'] ?? '');
                    if ($role !== '') $this->setClientMeta($clientId, 'role',     $role);
                    if ($streamId !== '') $this->setClientMeta($clientId, 'streamId', $streamId);
                    $this->_log_std("Client {$clientId} join: role={$role} streamId={$streamId}\n");
                    $this->sendSignaling($clientId, ['type' => 'joined']);
                    if ($role === 'play') {
                        $_pubId = $this->getPublisherIdByStreamId($streamId);
                        $this->_log_std("Client {$clientId} (play) join fireSubscriber: streamId={$streamId} publisherId=" . ($_pubId === null ? 'NULL(无推流端)' : $_pubId) . " clients总数=" . count($this->clients) . "\n");
                        $this->_fireSubscriberIfReady($clientId, $streamId);
                    }
                }
                break;
            }

            case 'offer':
                $this->handleOffer($clientId, $msg);
                break;
            case 'answer': {
                $ansHandled = null;
                $sdp = (string)($msg['sdp'] ?? '');
                if (isset($this->onAnswer) && is_callable($this->onAnswer)) {
                    try {
                        $_cb = $this->onAnswer;
                        $_cb($clientId, $sdp, $this, $ansHandled);
                    } catch (\Throwable $e) {
                        $this->_log_std("Client {$clientId} onAnswer exception: " . $e->getMessage() . "\n");
                    }
                }
                if ($ansHandled !== true) {
                    if ($sdp !== '') {
                        $this->clients[$clientId]['remoteAnswerSdp'] = $sdp;

                        $ufrag = $this->extractSdpAttribute($sdp, 'ice-ufrag');
                        $pwd   = $this->extractSdpAttribute($sdp, 'ice-pwd');
                        $setup = $this->extractSdpAttribute($sdp, 'setup');
                        if ($ufrag !== '') $this->clients[$clientId]['remoteIceUfrag'] = $ufrag;
                        if ($pwd   !== '') {
                            $this->clients[$clientId]['remoteIcePwd']         = $pwd;
                            $this->clients[$clientId]['remoteIcePwdForSTUN']  = $pwd;
                        }
                        if ($setup !== '') $this->clients[$clientId]['remoteSetup']    = $setup;
                        $role4 = (string)$this->getClientMeta($clientId, 'role', '');
                        if ($role4 === 'play' || $role4 === 'subscriber') {
                            $sid4 = (string)$this->getClientMeta($clientId, 'streamId', '');
                            $_pv = $this->clients[$clientId]['primaryVideoPT'] ?? '?';
                            $_pa = $this->clients[$clientId]['primaryAudioPT'] ?? '?';
                            $_vPTs = array_keys(is_array($this->clients[$clientId]['videoPTs'] ?? []) ? $this->clients[$clientId]['videoPTs'] : []);
                            $_aPTs = array_keys(is_array($this->clients[$clientId]['audioPTs'] ?? []) ? $this->clients[$clientId]['audioPTs'] : []);
                            $this->_log_std("Client {$clientId} (play) answer 到达 →  禁止从answer解析PT覆盖 (强制共享值保持不变) streamId={$sid4} primaryV={$_pv} primaryA={$_pa} videoPTs=" . json_encode($_vPTs) . " audioPTs=" . json_encode($_aPTs) . "\n");
                        }
                    }
                    $role = (string)$this->getClientMeta($clientId, 'role', '');
                    $this->_log_std("Client {$clientId} signaling: received answer sdp len=" . strlen($sdp) . " role={$role}\n");
                }
                if (((string)$this->getClientMeta($clientId, 'role', '')) === 'play') {
                    $this->kickFaststartForSubscriber($clientId);
                }
                break;
            }

            case 'candidate': {
                $candHandled = null;
                if (isset($this->onCandidate) && is_callable($this->onCandidate)) {
                    try {
                        $_cb = $this->onCandidate;
                        $_cb($clientId, $msg, $this, $candHandled);
                    } catch (\Throwable $e) {
                        $this->_log_std("Client {$clientId} onCandidate exception: " . $e->getMessage() . "\n");
                    }
                }
                if ($candHandled !== true) {
                    $this->handleCandidate($clientId, $msg);
                    $this->_defaultRelayCandidate($clientId, $msg);
                }
                break;
            }

            default:
                $this->_log_std("Client {$clientId} signaling: unknown type={$type}\n");
        }
    }


    /**
     * 读取某客户端的元数据（role/streamId/roomId 等用户自定义字段都存在这里）。
     * - 约定字段：
     *   role     = 'push' | 'play'   （publisher/subscriber 语义）
     *   streamId = string            （同一条流的 push/play 对应匹配）
     *   其他任意 key 由用户自定义即可。
     *
     * @param int      $clientId
     * @param string|null $key 若传 null 返回整个 metadata 数组（引用）
     * @param mixed    $default
     * @return mixed
     */
    public function &getClientMeta(int $clientId, ?string $key = null, $default = null)
    {
        if (!isset($this->clients[$clientId])) {
            $null = $default;
            return $null;
        }
        if (!isset($this->clients[$clientId]['meta']) || !is_array($this->clients[$clientId]['meta'])) {
            $this->clients[$clientId]['meta'] = [];
        }
        if ($key === null) {
            return $this->clients[$clientId]['meta'];
        }
        if (array_key_exists($key, $this->clients[$clientId]['meta'])) {
            return $this->clients[$clientId]['meta'][$key];
        }
        $null = $default;
        return $null;
    }

    /**
     * 写入客户端元数据
     * @param int $clientId
     * @param string $key
     * @param mixed $value
     * @return bool false = 客户端不存在
     */
    public function setClientMeta(int $clientId, string $key, $value): bool
    {
        if (!isset($this->clients[$clientId])) return false;
        if (!isset($this->clients[$clientId]['meta']) || !is_array($this->clients[$clientId]['meta'])) {
            $this->clients[$clientId]['meta'] = [];
        }
        $this->clients[$clientId]['meta'][$key] = $value;
        return true;
    }

    /** 所有当前 client id 列表（含连接中 / 已连接） */
    public function getClientIds(): array
    {
        return array_keys($this->clients);
    }

    /**
     * 按 metadata 字段筛选客户端 ID 列表
     *   $ids = $srv->getClientsByMeta('role', 'play');     // 所有订阅者
     *   $ids = $srv->getClientsByMeta('streamId', 'room_1'); // 同一流下所有 push/play
     *
     * @param string $key
     * @param mixed  $value 若为 null，只要存在该 key 即命中
     * @return int[]
     */
    public function getClientsByMeta(string $key, $value = null): array
    {
        $out = [];
        foreach ($this->clients as $id => $c) {
            if (!isset($c['meta']) || !is_array($c['meta'])) continue;
            if (!array_key_exists($key, $c['meta'])) continue;
            if ($value === null || $c['meta'][$key] === $value) {
                $out[] = (int)$id;
            }
        }
        return $out;
    }

    /**
     * 查找指定 streamId 下 metadata['role']==='push' 的 clientId（即 publisher）
     * @param string $streamId
     * @return int|null
     */
    public function getPublisherIdByStreamId(string $streamId): ?int
    {
        foreach ($this->clients as $id => $c) {
            $meta = $c['meta'] ?? [];
            if (!is_array($meta)) continue;
            if (($meta['streamId'] ?? null) === $streamId && ($meta['role'] ?? null) === 'push') {
                return (int)$id;
            }
        }
        return null;
    }


    /**
     * 给指定客户端通过 WebSocket 发送一条 JSON 信令消息（自动 json_encode）。
     * 对端直接在 ws.onmessage 中解析。
     * @return bool true = 发送成功（仅代表写入 socket，不代表对端已收到）
     */
    public function sendSignaling(int $clientId, array $msg): bool
    {
        $socket = $this->clients[$clientId]['socket'] ?? null;
        if (!is_resource($socket)) return false;
        $payload = json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($payload === false) return false;
        return (bool)$this->sendWebSocketText($socket, $payload);
    }

    /** 批量发送信令（给多个 clientId） */
    public function broadcastSignaling(array $clientIds, array $msg): int
    {
        $ok = 0;
        foreach ($clientIds as $id) {
            if ($this->sendSignaling((int)$id, $msg)) $ok++;
        }
        return $ok;
    }

    /**
     * 返回所有 SCTP 已 ESTABLISHED (DataChannel 可用) 的客户端 clientId 列表。
     * 可用于：多客户端全局聊天 / 系统通知推送 / 在线列表刷新等。
     * @param int[] $excludeIds 要排除的 clientId（比如发送者自己）
     * @return int[]
     */
    public function getClientsWithDataChannel(array $excludeIds = []): array
    {
        $ex = [];
        foreach ($excludeIds as $v) $ex[(int)$v] = true;
        $ids = [];
        foreach ($this->clients as $id => $c) {
            $id = (int)$id;
            if (isset($ex[$id])) continue;
            if (isset($c['sctp']) && is_array($c['sctp']) && ($c['sctp']['state'] ?? '') === 'ESTABLISHED') {
                $ids[] = $id;
            }
        }
        return $ids;
    }

    /**
     * 返回所有带指定 metadata['streamId'] 且 SCTP 已就绪的客户端列表 (房间聊天辅助)。
     * - 自动包含同 streamId 下 role=push 和 role=play 的所有端；
     * - 适合 push.html / play.html 开启 DataChannel 时的"同房间聊天"场景。
     * @param string $streamId 房间号
     * @param int[]  $excludeIds 排除（比如发送者自己）
     * @return int[]
     */
    public function getClientsInStreamRoom(string $streamId, array $excludeIds = []): array
    {
        if ($streamId === '') return [];
        $ex = [];
        foreach ($excludeIds as $v) $ex[(int)$v] = true;
        $ids = [];
        foreach ($this->clients as $id => $c) {
            $id = (int)$id;
            if (isset($ex[$id])) continue;
            $sid = isset($c['metadata']) && is_array($c['metadata']) ? (string)($c['metadata']['streamId'] ?? '') : '';
            if ($sid !== $streamId) continue;
            if (isset($c['sctp']) && is_array($c['sctp']) && ($c['sctp']['state'] ?? '') === 'ESTABLISHED') {
                $ids[] = $id;
            }
        }
        return $ids;
    }

    /**
     * 批量通过 DataChannel 发送消息。
     * - 等价于对每个 clientId 循环调用 sendDataChannel()，但内部跳过 SCTP 未就绪的端；
     * - 不侵入：start.php 用户只需写 onmessage 回调，不必手写 foreach。
     * @param int[]  $clientIds  目标 clientId 列表
     * @param string $message    文本消息（UTF-8）或二进制字符串
     * @param int    $ppid       51=string(默认) / 53=binary / 56/57=partial reliable
     * @param int    $sid        SCTP stream id（默认 0，浏览器第一个 DataChannel 固定 sid=0）
     * @return int 成功发送数量
     */
    public function broadcastDataChannel(array $clientIds, string $message, int $ppid = 51, int $sid = 0): int
    {
        $sent = 0;
        foreach ($clientIds as $id) {
            if ($this->sendDataChannel((int)$id, $message, $ppid, $sid)) $sent++;
        }
        return $sent;
    }

    /**
     * 获取指定客户端的 SDP PT->kind 映射（给 SFU 分发时用）。
     * 若 offer 还未完成 answer，对应 PT 可能为空。
     * @return array{videoPTs:array, audioPTs:array, localSsrcByKind:array}
     */
    public function getClientTrackInfo(int $clientId): array
    {
        $c = $this->clients[$clientId] ?? [];
        return [
            'videoPTs'       => isset($c['videoPTs']) && is_array($c['videoPTs']) ? $c['videoPTs'] : [],
            'audioPTs'       => isset($c['audioPTs']) && is_array($c['audioPTs']) ? $c['audioPTs'] : [],
            'localSsrcByKind'=> isset($c['localSsrcByKind']) && is_array($c['localSsrcByKind']) ? $c['localSsrcByKind'] : [],
        ];
    }

    /**
     * 把收到的一段明文 RTP（已 unprotect）通过指定 client 的 srtpTx protect + SSRC 重写后发送。
     * - 内部复用 UDP trait 已实现的 protectAndSendRtp()
     * @return bool
     */
    public function forwardRtpToClient(int $targetClientId, string $plainRtp, bool $ssrcRewrite = true): bool
    {
        return $this->protectAndSendRtp($targetClientId, $plainRtp, $ssrcRewrite);
    }

    /**
     * 把一条明文 RTP 广播给同 streamId 下所有 metadata['role']==='play' 的订阅者（SFU 转发核心）。
     * - 默认根据订阅者各自的 answer 中声明的 localSsrcByKind/videoPTs/audioPTs 重写 SSRC；
     * - 跳过来源端本身；
     * - 跳过 srtpTx 未就绪的订阅者；
     * - 返回成功投递的订阅者数。
     *
     * @param string $streamId   要匹配的订阅者 metadata['streamId']
     * @param string $plainRtp   明文 RTP
     * @param int    $excludeClientId 不投递的 client（通常是 push 端自己）
     * @return int 成功投递数量
     */
    public function forwardRtpToAllSubscribers(string $streamId, string $plainRtp, int $excludeClientId = -1): int
    {
        if ($streamId === '' || !is_string($plainRtp) || strlen($plainRtp) < 12) return 0;
        $_dbgForwardPrepareStarted = hrtime(true);
        $n = 0;
        $hPT    = ord($plainRtp[1]) & 0x7F;
        $hSSRC  = unpack('N', substr($plainRtp, 8, 4))[1];
        $hSeq   = unpack('n', substr($plainRtp, 2, 2))[1];
        $hMarker = (ord($plainRtp[1]) >> 7) & 0x1;
        $hTs    = unpack('N', substr($plainRtp, 4, 4))[1];
        $b0     = ord($plainRtp[0]);
        $cc     = $b0 & 0xF;
        $xBit   = ($b0 >> 4) & 0x1;
        $hdrLen = 12 + 4 * $cc;
        if ($xBit && strlen($plainRtp) >= $hdrLen + 4) {
            $_extLen = unpack('n', substr($plainRtp, $hdrLen + 2, 2))[1];
            $hdrLen += 4 + 4 * $_extLen;
        }
        $pktLen = strlen($plainRtp);
        $payloadLen = $pktLen - $hdrLen;

        try {
            $_dbgPBit = ($b0 >> 5) & 0x1;
            $_dbgRawPayloadLen = $pktLen - $hdrLen;
            $_dbgLastByte = $pktLen > 0 ? ord($plainRtp[$pktLen - 1]) : null;
            $_dbgPaddingCount = $_dbgPBit === 1 ? $_dbgLastByte : 0;
            $_dbgPaddingValid = $_dbgPBit === 0 || ($_dbgPaddingCount !== null && $_dbgPaddingCount > 0 && $_dbgPaddingCount <= $_dbgRawPayloadLen);
            $_dbgEffectivePayloadLen = $_dbgPaddingValid ? ($_dbgRawPayloadLen - ($_dbgPBit === 1 ? $_dbgPaddingCount : 0)) : $_dbgRawPayloadLen;
        } catch (\Throwable $_dbgPaddingError) {
        }

        if ($_dbgPBit === 1 && $_dbgPaddingValid === true && $_dbgEffectivePayloadLen === 0) {
            return 0;
        }

        $nowF = microtime(true);
        $nowMs = (int)($nowF * 1000);

        $kind = 'unknown';
        $codecName = '';
        $pubC = $excludeClientId >= 0 ? ($this->clients[$excludeClientId] ?? null) : null;
        $dropRedRtx = false;
        $dropReason = '';
        if ($pubC !== null) {
            $pubVPts = isset($pubC['videoPTs']) && is_array($pubC['videoPTs']) ? $pubC['videoPTs'] : [];
            $pubAPts = isset($pubC['audioPTs']) && is_array($pubC['audioPTs']) ? $pubC['audioPTs'] : [];
            if (isset($pubAPts[$hPT])) {
                $kind = 'audio';
                $ptInfo = $pubAPts[$hPT];
                $c = '';
                if (is_array($ptInfo) && !empty($ptInfo['codec'])) $c = strtolower(trim($ptInfo['codec']));
                elseif (is_array($ptInfo) && !empty($ptInfo['rtpmap'])) {
                    $rm = explode('/', trim($ptInfo['rtpmap']));
                    $c = strtolower(trim($rm[0] ?? ''));
                }
                if ($c !== '') {
                    if (!in_array($c, ['opus','g722','pcmu','pcma','isac','ilbc','speex','gsm','l16','mpa','g726','aac','ac3','eac3'], true)) {
                        $dropRedRtx = true;
                        $dropReason = "audio codec={$c} (red/dtmf/cn)";
                    }
                }
            } elseif (isset($pubVPts[$hPT])) {
                $kind = 'video';
                $ptInfo = $pubVPts[$hPT];
                $c = '';
                if (is_array($ptInfo) && !empty($ptInfo['codec'])) $c = strtolower(trim($ptInfo['codec']));
                if (($c === '' || !in_array($c,['h264','avc','vp8','vp9','av1','h265','hevc'], true))
                    && is_array($ptInfo) && !empty($ptInfo['rtpmap'])) {
                    $rm = explode('/', trim($ptInfo['rtpmap']));
                    $tc = strtolower(trim($rm[0] ?? ''));
                    if (in_array($tc,['h264','avc','vp8','vp9','av1','h265','hevc'], true)) $c = $tc;
                }
                $knownBad = ['red','rtx','ulpfec','flexfec','fec','x-ulpfec','x-red','rtx-red','sfu-fec'];
                if ($c !== '' && in_array($c, $knownBad, true)) {
                    $dropRedRtx = true;
                    $dropReason = "video codec={$c} (rtx/red/fec，已知冗余)";
                } else {
                    $codecName = $c;
                }
            }
        }

        if ($kind === 'unknown' && $payloadLen > 0) {
            $_p0 = ord($plainRtp[$hdrLen] ?? "\x00");
            $_t = $_p0 & 0x1F;
            $_looksH264 = in_array($_t, [1,2,3,4,5,6,7,8,9,10,11,12,24,25,26,27,28,29,30,31], true);
            $_vp8X = (($_p0 >> 7) & 1);
            $_vp8R = (($_p0 >> 6) & 1);
            $_vp8S = (($_p0 >> 4) & 1);
            $_looksVp8 = ($_vp8R === 0) && ($_vp8S === 1 || $_vp8S === 0) && ($_t >= 0 && $_t < 16)
                           && ($payloadLen >= 3 && ($hMarker || $_vp8S));
            $_looksOpus = ($hPT >= 100 && $hPT <= 127) && ($payloadLen >= 4);
            $_looksPcm = ($hPT === 0 || $hPT === 8);

            if ($_looksH264) {
                $kind = 'video';
                $codecName = 'h264';
            } elseif ($_looksVp8) {
                $kind = 'video';
                $codecName = 'vp8';
            } elseif ($_looksOpus) {
                $kind = 'audio';
                $codecName = 'opus';
            } elseif ($_looksPcm) {
                $kind = 'audio';
                $codecName = ($hPT === 0) ? 'pcmu' : 'pcma';
            }
        }

        if ($dropRedRtx) {
            static $_dropCnt = 0;
            $_dropCnt++;
            if (($_dropCnt % 100) === 1) {
                $this->_log_std("[SFU DROP] pt={$hPT} kind={$kind} reason={$dropReason} seq={$hSeq} ssrc={$hSSRC} (total drops={$_dropCnt}, throttled per 100)\n");
            }
            return 0;
        }

        if ($excludeClientId >= 0 && ($kind === 'video' || $kind === 'audio')
            && $hSSRC > 1 && $hSSRC !== 4147483647 && isset($this->clients[$excludeClientId])) {
            if (!isset($this->clients[$excludeClientId]['incomingSsrcByKind'])
                || !is_array($this->clients[$excludeClientId]['incomingSsrcByKind'])) {
                $this->clients[$excludeClientId]['incomingSsrcByKind'] = [];
            }
            $this->clients[$excludeClientId]['incomingSsrcByKind'][$kind] = $hSSRC;
        }

        $targetIds = [];
        foreach ($this->clients as $id => $c) {
            $id = (int)$id;
            if ($id === $excludeClientId) continue;
            $meta = is_array($c['meta'] ?? null) ? $c['meta'] : [];
            if ((string)($meta['streamId'] ?? '') !== $streamId || (string)($meta['role'] ?? '') !== 'play') continue;

            $_hasSrtpTx = !empty($c['srtpTx']);
            $_hasRc = !empty($c['remoteCandidate']);
            $_isHttp = ($c['socket'] ?? null) === null;
            $_wsAlive = isset($c['socket']) && is_resource($c['socket']);
            $_notClosed = !in_array((string)($c['state'] ?? ''), ['closed', 'deleted'], true)
                && (string)($c['dtlsState'] ?? '') !== 'closed';
            if ($_hasSrtpTx && $_hasRc && $_notClosed && ($_isHttp || $_wsAlive)) $targetIds[] = $id;

            $lastSrtpTx = isset($c['_sfuWarnLastSrtpTx']) ? (bool)$c['_sfuWarnLastSrtpTx'] : null;
            $lastHasRc = isset($c['_sfuWarnLastHasRc']) ? (bool)$c['_sfuWarnLastHasRc'] : null;
            if ($lastSrtpTx !== $_hasSrtpTx || $lastHasRc !== $_hasRc) {
                unset($c['_warnedSFUnoTx'], $c['_warnedSFUfail']);
                $c['_sfuWarnLastSrtpTx'] = $_hasSrtpTx;
                $c['_sfuWarnLastHasRc'] = $_hasRc;
                $this->clients[$id] = $c;
            }
        }
        $_matchMode = 'strict-only';

        if ($excludeClientId >= 0 && $kind === 'video') {
            $this->_ensurePeriodicKeyFrame($streamId);
        }

        $isKeyFrame = false;
        if ($kind === 'video' && $payloadLen > 0) {
            $payload = substr($plainRtp, $hdrLen, $payloadLen);
            if ($codecName === 'h264') {

                $fNriType = ord($payload[0]) & 0x1F;

                if (empty($this->_sfuStreamConfig[$streamId]['_dbgActualProfileLevelId'])) {
                    $_dbgSpsProfileBytes = null;
                    $_dbgSpsSource = '';
                    if ($fNriType === 7 && $payloadLen >= 4) {
                        $_dbgSpsProfileBytes = substr($payload, 1, 3);
                        $_dbgSpsSource = 'single-nal-sps';
                    } elseif ($fNriType === 28 && $payloadLen >= 5) {
                        $_dbgFuHeaderM = ord($payload[1]);
                        if ((($_dbgFuHeaderM >> 7) & 0x1) === 1 && ($_dbgFuHeaderM & 0x1F) === 7) {
                            $_dbgSpsProfileBytes = substr($payload, 2, 3);
                            $_dbgSpsSource = 'fu-a-sps-start';
                        }
                    } elseif ($fNriType === 24 && $payloadLen >= 6) {
                        $_dbgStapOffsetM = 1;
                        while (($_dbgStapOffsetM + 2) <= $payloadLen) {
                            $_dbgNalSizeM = (ord($payload[$_dbgStapOffsetM]) << 8) | ord($payload[$_dbgStapOffsetM + 1]);
                            $_dbgStapOffsetM += 2;
                            if ($_dbgNalSizeM <= 0 || ($_dbgStapOffsetM + $_dbgNalSizeM) > $payloadLen) break;
                            if ((ord($payload[$_dbgStapOffsetM]) & 0x1F) === 7 && $_dbgNalSizeM >= 4) {
                                $_dbgSpsProfileBytes = substr($payload, $_dbgStapOffsetM + 1, 3);
                                $_dbgSpsSource = 'stap-a-sps';
                                break;
                            }
                            $_dbgStapOffsetM += $_dbgNalSizeM;
                        }
                    }
                    if (is_string($_dbgSpsProfileBytes) && strlen($_dbgSpsProfileBytes) === 3 && isset($this->_sfuStreamConfig[$streamId])) {
                        $_dbgActualProfileLevelId = strtolower(bin2hex($_dbgSpsProfileBytes));
                        $this->_sfuStreamConfig[$streamId]['_dbgActualProfileLevelId'] = $_dbgActualProfileLevelId;
                        $this->_sfuStreamConfig[$streamId]['h264ProfileLevelId'] = $_dbgActualProfileLevelId;
                        foreach ($this->_sfuStreamConfig[$streamId]['videoPTs'] as &$_profilePtInfo) {
                            if (!is_array($_profilePtInfo)) continue;
                            $_profileCodec = strtolower((string)($_profilePtInfo['codec'] ?? ''));
                            if ($_profileCodec !== 'h264' && $_profileCodec !== 'avc') continue;
                            $_profileFmtp = (string)($_profilePtInfo['fmtp'] ?? '');
                            if (preg_match('/profile-level-id=[0-9a-fA-F]{6}/i', $_profileFmtp)) {
                                $_profileFmtp = preg_replace('/profile-level-id=[0-9a-fA-F]{6}/i', 'profile-level-id=' . $_dbgActualProfileLevelId, $_profileFmtp);
                            } else {
                                $_profileFmtp = rtrim($_profileFmtp, ';') . ';profile-level-id=' . $_dbgActualProfileLevelId;
                            }
                            $_profilePtInfo['fmtp'] = ltrim($_profileFmtp, ';');
                        }
                        unset($_profilePtInfo);
                        $this->_log_std("[H264 profile detected] streamId={$streamId} profile-level-id={$_dbgActualProfileLevelId} source={$_dbgSpsSource}\n");
                    }
                }

                $hasSps = false;
                $hasPps = false;
                $hasIdrNal = false;
                $_isFuAIdrFragment = false;
                $_dbgType = $fNriType;
                $_dbgFuBits = '';

                $fubMtapFix = false;
                if ($fNriType === 29) {
                    if ($payloadLen >= 4) {
                        $fubMtapFix = true;
                        $don = (ord($payload[1]) << 8) | ord($payload[2]);
                        $fuHeader = ord($payload[3]);
                        $fuType   = $fuHeader & 0x1F;
                        $fuStart  = ($fuHeader >> 7) & 0x1;
                        $fuEnd    = ($fuHeader >> 6) & 0x1;
                        if ($fuType === 5) $_isFuAIdrFragment = true;
                        $_dbgFuBits = " FU-B(type=29) DON=$don fuType=$fuType S=$fuStart E=$fuEnd";
                        if ($fuStart && $fuType === 5) $hasIdrNal = true;
                        if ($fuStart && $fuType === 7) $hasSps = true;
                        if ($fuStart && $fuType === 8) $hasPps = true;
                        if ($fuEnd && $hMarker && $fuType === 5) {
                            $gcTmp = $this->_gopCacheByStream[$streamId] ?? null;
                            if ($gcTmp && empty($gcTmp['hasIdr']) && !empty($gcTmp['lastSpsAt']) && !empty($gcTmp['lastPpsAt'])) {
                                $_dt = $nowMs - (int)\max($gcTmp['lastSpsAt'], $gcTmp['lastPpsAt']);
                                if ($_dt >= 0 && $_dt <= 2000) $hasIdrNal = true;
                            }
                        }
                        if ($fuStart && ($fuType === 5 || $fuType === 7 || $fuType === 8)) {
                            $fNriType = $fuType;
                        }
                    }
                } elseif ($fNriType === 28) {
                    if ($payloadLen >= 2) {
                        $fuHeader = ord($payload[1]);
                        $fuType   = $fuHeader & 0x1F;
                        $fuStart  = ($fuHeader >> 7) & 0x1;
                        $fuEnd    = ($fuHeader >> 6) & 0x1;
                        if ($fuType === 5) $_isFuAIdrFragment = true;
                        $_dbgFuBits = " fuType=$fuType S=$fuStart E=$fuEnd";
                        if ($fuStart && ($fuType === 5 || $fuType === 7 || $fuType === 8)) {
                            $fNriType = $fuType;
                        }
                        if ($fuStart && $fuType === 5) $hasIdrNal = true;
                        if ($fuStart && $fuType === 7) $hasSps = true;
                        if ($fuStart && $fuType === 8) $hasPps = true;
                        if ($fuEnd && $hMarker && $fuType === 5) {
                            $gcTmp = $this->_gopCacheByStream[$streamId] ?? null;
                            if ($gcTmp && empty($gcTmp['hasIdr']) && !empty($gcTmp['lastSpsAt']) && !empty($gcTmp['lastPpsAt'])) {
                                $_dt = $nowMs - (int)\max($gcTmp['lastSpsAt'], $gcTmp['lastPpsAt']);
                                if ($_dt >= 0 && $_dt <= 2000) {
                                    $hasIdrNal = true;
                                }
                            }
                        }
                    }
                } elseif ($fNriType === 24) {

                    $p = 1;
                    $_stapFb = false;
                    $_dbgNals = [];
                    while (($p + 2) <= $payloadLen) {
                        $nalSz = (ord($payload[$p]) << 8) | ord($payload[$p + 1]);
                        $p += 2;
                        if ($nalSz <= 0 || ($p + $nalSz) > $payloadLen) break;
                        $nalHdr = ord($payload[$p]);
                        $t = $nalHdr & 0x1F;
                        $_dbgNals[] = $t;
                        if ($t === 5)      { $hasIdrNal = true; $_stapFb = true; }
                        elseif ($t === 7)  { $hasSps    = true; }
                        elseif ($t === 8)  { $hasPps    = true; }
                        $p += $nalSz;
                    }
                    $_dbgFuBits = ' STAP-A[' . implode(',', $_dbgNals) . ']';
                    if ($hasIdrNal) $fNriType = 5;
                } elseif ($fNriType === 7) {
                    $hasSps = true;
                } elseif ($fNriType === 8) {
                    $hasPps = true;
                } elseif ($fNriType === 5) {
                    $hasIdrNal = true;
                }

                if (!$hasIdrNal && $_isFuAIdrFragment && $hMarker && $payloadLen >= 500) {
                    $gcTmp = $this->_gopCacheByStream[$streamId] ?? null;
                    if ($gcTmp && empty($gcTmp['hasIdr']) && !empty($gcTmp['lastSpsAt']) && !empty($gcTmp['lastPpsAt'])) {
                        $_dt = $nowMs - (int)\max($gcTmp['lastSpsAt'], $gcTmp['lastPpsAt']);
                        if ($_dt >= 0 && $_dt <= 1500) {
                            $hasIdrNal = true;
                            $_dbgFuBits .= " [IDR兜底:SPS/PPS<1.5s + marker=1 + len>=500]";
                        }
                    }
                }
                if ($hasSps || $hasPps) {
                    if (!isset($this->_gopCacheByStream[$streamId])) {
                        $this->_gopCacheByStream[$streamId] = $this->_newGopCacheEntry();
                    }
                    $_gc = $this->_gopCacheByStream[$streamId];
                    if ($hasSps) $_gc['lastSpsAt'] = $nowMs;
                    if ($hasPps) $_gc['lastPpsAt'] = $nowMs;
                    $this->_gopCacheByStream[$streamId] = $_gc;
                }
                if ($fNriType === 5 || $hasIdrNal) $isKeyFrame = true;
            } elseif ($codecName === 'vp8') {

                $b_0 = ord($payload[0]);
                $xBit = ($b_0 >> 7) & 0x1;
                $sBit = ($b_0 >> 3) & 0x1;
                $off = 1;
                $kFlag = false;
                if ($xBit) {
                    if ($off < $payloadLen) {
                        $b_i = ord($payload[$off]);
                        $kFlag = (($b_i >> 3) & 0x1) === 1;
                        $hasPicId = (($b_i >> 7) & 0x1);
                        $hasTl0 = (($b_i >> 6) & 0x1);
                        $hasTid = (($b_i >> 5) & 0x1);
                        $off++;
                        if ($hasPicId) {
                            if ($off < $payloadLen) {
                                $p0 = ord($payload[$off]);
                                $off += (($p0 & 0x80) ? 2 : 1);
                            }
                        }
                        if ($hasTl0) $off += 1;
                        if ($hasTid) {
                            if ($off < $payloadLen) {
                                $t0 = ord($payload[$off]);
                                $off += (($t0 & 0x80) ? 2 : 1);
                            }
                        }
                    }
                }
                if ($kFlag) $isKeyFrame = true;

                if (!$isKeyFrame && $sBit && $off < $payloadLen) {

                    $vp8First = ord($payload[$off]);
                    if (($vp8First & 0x01) === 0) {
                        if (($off + 3) <= $payloadLen) {
                            $sync0 = ord($payload[$off + 1]);
                            $sync1 = ord($payload[$off + 2]);
                            $sync2 = ord($payload[$off + 3]);
                            if ($sync0 === 0x9D && $sync1 === 0x01 && $sync2 === 0x2A) {
                                $isKeyFrame = true;
                            } else {
                                $isKeyFrame = true;
                            }
                        } else {
                            $isKeyFrame = true;
                        }
                    }
                }

                if (!$isKeyFrame && $sBit && $hMarker && $payloadLen > 3500) $isKeyFrame = true;

                if ($isKeyFrame) {
                    $lastKfTs = (float)($this->_vp8LastKfTsByStream[$streamId] ?? -1.0);
                    if ($lastKfTs >= 0 && abs($hTs - $lastKfTs) < 27000) {
                        $isKeyFrame = false;
                    }
                    if ($isKeyFrame && $payloadLen < 1600 && !($hMarker && $payloadLen > 1200)) {
                        $isKeyFrame = false;
                    }
                    if ($isKeyFrame) {
                        $this->_vp8LastKfTsByStream[$streamId] = (float)$hTs;
                    }
                }
            } elseif ($codecName === 'vp9' || $codecName === 'hevc' || $codecName === 'h265' || $codecName === 'av1') {
                if ($hMarker && $payloadLen > 6000) $isKeyFrame = true;
            } else {
                if ($hMarker && $payloadLen > 8000) $isKeyFrame = true;
            }
            static $_diagVideo = [];
            if (!isset($_diagVideo[$streamId])) $_diagVideo[$streamId] = ['lastTs'=>null, 'lastLogAt'=>0.0, 'count'=>0];
            if ($isKeyFrame && $_diagVideo[$streamId]['lastTs'] !== $hTs) {
                $_diagVideo[$streamId]['lastTs'] = $hTs;
                $_diagVideo[$streamId]['count']++;
                $_dbgKfNow = microtime(true);
                if (($_dbgKfNow - $_diagVideo[$streamId]['lastLogAt']) >= 5.0) {
                    $_diagVideo[$streamId]['lastLogAt'] = $_dbgKfNow;
                    $this->_log_std("[SFU KF DETECT summary streamId={$streamId}] pushId={$excludeClientId} codec=" . ($codecName?:'?') . " ts={$hTs} lastSeq={$hSeq} keyframes=" . $_diagVideo[$streamId]['count'] . " (max once/5s)\n");
                    $_diagVideo[$streamId]['count'] = 0;
                }
            }
        }

        if ($streamId !== '') {
            if (!isset($this->_gopCacheByStream[$streamId])) {
                $this->_gopCacheByStream[$streamId] = [
                    'hasIdr'        => false,
                    'gop'           => [],
                    'lastSpsPps'    => [],
                    'lastIdrSeq'    => null,
                    'lastPliSentTs' => 0.0,
                    'lastKfBurstSids' => [],
                    '_noIdrSince'   => 0.0,
                    '_hadSubsAt'    => 0.0,
                ];
            }
            $gc = &$this->_gopCacheByStream[$streamId];
            if (!array_key_exists('gopSoftLimitTs', $gc)) $gc['gopSoftLimitTs'] = null;
            if (!array_key_exists('gopCacheClosed', $gc)) $gc['gopCacheClosed'] = false;

            if ($kind === 'video') {
                if ($codecName === 'h264' && $payloadLen > 0) {
                    $payload = substr($plainRtp, $hdrLen, $payloadLen);
                    $fNriType = ord($payload[0]) & 0x1F;
                    if ($fNriType === 28 && $payloadLen >= 2) {
                        $fuType  = ord($payload[1]) & 0x1F;
                        $fuStart = (ord($payload[1]) >> 7) & 0x1;
                        if ($fuStart && ($fuType === 7 || $fuType === 8)) {
                            $fNriType = $fuType;
                        }
                        if ($fuType === 7 || $fuType === 8) {
                            $gc['lastSpsPps'][$fuType] = $plainRtp;
                        }
                    } elseif (($fNriType === 29 || $fNriType === 30) && $payloadLen >= 4) {
                        $fuType  = ord($payload[3]) & 0x1F;
                        $fuStart = (ord($payload[3]) >> 7) & 0x1;
                        if ($fuStart && ($fuType === 7 || $fuType === 8 || $fuType === 5)) {
                            $fNriType = $fuType;
                        }
                        if ($fuType === 7 || $fuType === 8) {
                            $gc['lastSpsPps'][$fuType] = $plainRtp;
                        }
                    } elseif ($fNriType === 24 && $payloadLen >= 3) {
                        $_p = 1;
                        $_stapHasSps = false;
                        $_stapHasPps = false;
                        while (($_p + 2) <= $payloadLen) {
                            $_nalSz = (ord($payload[$_p]) << 8) | ord($payload[$_p + 1]);
                            $_p += 2;
                            if ($_nalSz <= 0 || ($_p + $_nalSz) > $payloadLen) break;
                            $_t = ord($payload[$_p]) & 0x1F;
                            if ($_t === 7) $_stapHasSps = true;
                            elseif ($_t === 8) $_stapHasPps = true;
                            $_p += $_nalSz;
                        }
                        if ($_stapHasSps) {
                            $gc['lastSpsPps'][7] = $plainRtp;
                        }
                        if ($_stapHasPps) {
                            $gc['lastSpsPps'][8] = $plainRtp;
                        }
                    }
                    if ($fNriType === 7 || $fNriType === 8) {
                        $gc['lastSpsPps'][$fNriType] = $plainRtp;
                    }
                }
                if ($isKeyFrame) {
                    if (!isset($gc['gopIdrTs']) || (int)$gc['gopIdrTs'] !== $hTs) {
                        $gc['generation'] = (int)($gc['generation'] ?? 0) + 1;
                        $this->_dbgPerfBurstEvent($streamId, 'idr');
                    }
                    $gc['gop'] = [];
                    if ($codecName === 'h264') {
                        if (!empty($gc['lastSpsPps'][7])) {
                            $gc['gop'][] = $gc['lastSpsPps'][7];
                            if (!empty($gc['lastSpsPps'][8]) && $gc['lastSpsPps'][8] !== $gc['lastSpsPps'][7]) {
                                $gc['gop'][] = $gc['lastSpsPps'][8];
                            }
                        } elseif (!empty($gc['lastSpsPps'][8])) {
                            $gc['gop'][] = $gc['lastSpsPps'][8];
                        }
                    }
                    $gc['gop'][]    = $plainRtp;
                    $gc['hasIdr']   = true;
                    $gc['lastIdrSeq'] = $hSeq;
                    $gc['gopIdrTs'] = $hTs;
                    $gc['gopSoftLimitTs'] = null;
                    $gc['gopCacheClosed'] = false;
                    $gc['_noIdrSince'] = 0.0;
                } elseif ($gc['hasIdr']) {
                    $_gopCount = count($gc['gop']);
                    $_fuEnd = false;
                    if ($codecName === 'h264' && $payloadLen >= 2 && (ord($plainRtp[$hdrLen]) & 0x1F) === 28) {
                        $_fuEnd = ((ord($plainRtp[$hdrLen + 1]) >> 6) & 0x1) === 1;
                    }
                    $_frameEnded = $hMarker === 1 || $_fuEnd;
                    if ($gc['gopSoftLimitTs'] !== null && (int)$gc['gopSoftLimitTs'] !== $hTs) {
                        $_incompleteTs = (int)$gc['gopSoftLimitTs'];
                        $gc['gop'] = array_values(array_filter($gc['gop'], static function (string $_rtp) use ($_incompleteTs): bool {
                            return strlen($_rtp) < 8 || unpack('N', substr($_rtp, 4, 4))[1] !== $_incompleteTs;
                        }));
                        if ((int)($gc['gopIdrTs'] ?? -1) === $_incompleteTs) $gc['hasIdr'] = false;
                        $gc['gopSoftLimitTs'] = null;
                        $gc['gopCacheClosed'] = true;
                    }
                    $_cachePacket = false;
                    if ($_gopCount < 60 && empty($gc['gopCacheClosed'])) {
                        $_cachePacket = true;
                    } elseif (empty($gc['gopCacheClosed']) && $gc['gopSoftLimitTs'] !== null && (int)$gc['gopSoftLimitTs'] === $hTs) {
                        $_cachePacket = true;
                    }

                    if ($_cachePacket) {
                        $gc['gop'][] = $plainRtp;
                        if (count($gc['gop']) >= 60 && $gc['gopSoftLimitTs'] === null) {
                            if ($_frameEnded) {
                                $gc['gopCacheClosed'] = true;
                            } else {
                                $gc['gopSoftLimitTs'] = $hTs;
                            }
                        } elseif ($gc['gopSoftLimitTs'] !== null && $_frameEnded) {
                            $gc['gopSoftLimitTs'] = null;
                            $gc['gopCacheClosed'] = true;
                        }

                        if (count($gc['gop']) >= 180 && $gc['gopSoftLimitTs'] !== null) {
                            $_incompleteTs = (int)$gc['gopSoftLimitTs'];
                            $gc['gop'] = array_values(array_filter($gc['gop'], static function (string $_rtp) use ($_incompleteTs): bool {
                                return strlen($_rtp) < 8 || unpack('N', substr($_rtp, 4, 4))[1] !== $_incompleteTs;
                            }));
                            if ((int)($gc['gopIdrTs'] ?? -1) === $_incompleteTs) {
                                $gc['hasIdr'] = false;
                            }
                            $gc['gopSoftLimitTs'] = null;
                            $gc['gopCacheClosed'] = true;
                            $this->_log_std("[GOP hard limit] streamId={$streamId} removed incomplete timestamp={$_incompleteTs}; cached=" . count($gc['gop']) . "\n");
                        }
                    }
                }
            } elseif ($kind === 'audio' && $gc['hasIdr']) {
            }

            $_nowF2 = microtime(true);
            if ($kind === 'video' && $streamId !== '' && $streamId !== null) {
                if (!empty($targetIds) && !$gc['hasIdr']) {
                    if ((float)$gc['_noIdrSince'] <= 0.0) {
                        $gc['_noIdrSince'] = $_nowF2;
                    }
                    if (($_nowF2 - (float)$gc['_noIdrSince']) > 2.5) {
                        $lastPli = (float)($gc['lastPliSentTs'] ?? 0.0);
                        if (($_nowF2 - $lastPli) >= 0.5) {
                            $this->_log_std("[SFU GOP EMPTY IDR] streamId={$streamId} no-IDR " . number_format($_nowF2 - (float)$gc['_noIdrSince'], 1) . "s hasReadySub → PLI publisherId={$excludeClientId}\n");
                            @$this->sendPliToPublisher($streamId, false);
                        }
                    }
                }
            }

        }

        $_dbgForwardFanoutStarted = hrtime(true);
        $this->_dbgPerfPipelineStage($streamId, 'forwardPrepare', (int)($_dbgForwardFanoutStarted - $_dbgForwardPrepareStarted), strlen($plainRtp), count($targetIds));

        foreach ($targetIds as $id) {
            $id = (int)$id;
            if (!isset($this->clients[$id])) continue;
            $c = $this->clients[$id];
            $hasSrtpTx = !empty($c['srtpTx']);
            $hasRc     = !empty($c['remoteCandidate']);

            if (!$hasSrtpTx) {
                if (empty($c['_warnedSFUnoTx'])) {
                    $c['_warnedSFUnoTx'] = true;
                    $this->_log_std("[SFU forward] subscriberId={$id} streamId={$streamId} SKIP: srtpTx null (DTLS not keyed). hasRc=" . ($hasRc?'yes':'no') . "\n");
                    $this->clients[$id] = $c;
                }
                continue;
            }

            if ($kind === 'video'
                && isset($this->clients[$id]['_burstBoundaryPublisherSeq'], $this->clients[$id]['_burstBoundaryPublisherTs'])
                && (int)$this->clients[$id]['_burstBoundaryPublisherSeq'] === $hSeq
                && (int)$this->clients[$id]['_burstBoundaryPublisherTs'] === $hTs) {
                unset($this->clients[$id]['_burstBoundaryPublisherSeq'], $this->clients[$id]['_burstBoundaryPublisherTs']);
                continue;
            }
            if ($kind === 'video') {
                unset($this->clients[$id]['_burstBoundaryPublisherSeq'], $this->clients[$id]['_burstBoundaryPublisherTs']);
            }
            $ok = $this->protectAndSendRtp($id, $plainRtp, true, $kind, $hPT);
            if ($ok) {
                $n++;

                if ($kind === 'video' && empty($this->clients[$id]['_dbgBurstLiveBoundaryReportedK']) && is_string($this->clients[$id]['_dbgBurstLastVideoRtpK'] ?? null)) {
                    $this->clients[$id]['_dbgBurstLiveBoundaryReportedK'] = true;
                }

                if ($kind === 'video' && $isKeyFrame) {
                    $this->clients[$id]['_liveVidSent'] = true;
                    unset($this->_gopCacheByStream[$streamId]['_retryKicks'][$id]);
                }
            } else {
                if (empty($c['_warnedSFUfail'])) {
                    $c['_warnedSFUfail'] = true;
                    $rc = isset($c['remoteCandidate']) ? "{$c['remoteCandidate']['ip']}:{$c['remoteCandidate']['port']}" : 'null';
                    $this->_log_std("[SFU forward] subscriberId={$id} FAIL (1st): PT={$hPT} kind={$kind} srcSsrc={$hSSRC} srcSeq={$hSeq} mode={$_matchMode} rc={$rc}. See UDP.php protectAndSendRtp above. Subseq FAILs suppressed.\n");
                    $this->clients[$id] = $c;
                }
            }
        }

        $this->_dbgPerfPipelineStage($streamId, 'subscriberFanout', (int)(hrtime(true) - $_dbgForwardFanoutStarted), strlen($plainRtp), count($targetIds));

        static $_zeroSubDiag = [];
        $_zeroState = $n === 0;
        $_zeroNow = microtime(true);
        if (!isset($_zeroSubDiag[$streamId])) $_zeroSubDiag[$streamId] = ['zero'=>null, 'count'=>0, 'lastLog'=>0.0];
        if ($_zeroState) $_zeroSubDiag[$streamId]['count']++;
        $_zeroChanged = $_zeroSubDiag[$streamId]['zero'] !== $_zeroState;
        if ($_zeroChanged || ($_zeroState && ($_zeroNow - $_zeroSubDiag[$streamId]['lastLog']) >= 60.0)) {
            $_zeroSubDiag[$streamId]['zero'] = $_zeroState;
            $_zeroSubDiag[$streamId]['lastLog'] = $_zeroNow;
            $this->_log_std("[SFU subscriber state] streamId={$streamId} zeroSubscribers=" . ($_zeroState?'yes':'no') . " checks=" . $_zeroSubDiag[$streamId]['count'] . " clients=" . count($this->clients) . " targets=" . count($targetIds) . ($_zeroChanged?' stateChanged':' periodic60s') . "\n");
            $_zeroSubDiag[$streamId]['count'] = 0;
        }

        if ($kind === 'video') {
            static $_vidDiag = [];
            if (!isset($_vidDiag[$streamId])) $_vidDiag[$streamId] = ['cnt'=>0, 'lastT'=>0.0, 'lastNsubs'=>0, 'lastSsrcOut'=>0, 'lastPtOut'=>0];
            $_vidDiag[$streamId]['cnt']++;
            if (($_vidDiag[$streamId]['cnt'] === 1) || (($_vidDiag[$streamId]['cnt'] % 3000) === 0)) {

                $firstSubPriVpt = 0; $firstSubPriApt = 0; $firstSubSid = 0; $firstSubVPts='[]';
                foreach ($targetIds as $_idT) {
                    $_idT = (int)$_idT;
                    if (!isset($this->clients[$_idT])) continue;
                    $_ctmp = $this->clients[$_idT];
                    $firstSubSid = $_idT;
                    $firstSubPriVpt = (int)($_ctmp['primaryVideoPT'] ?? 0);
                    $firstSubPriApt = (int)($_ctmp['primaryAudioPT'] ?? 0);
                    $firstSubVPts = isset($_ctmp['videoPTs']) ? json_encode(array_keys($_ctmp['videoPTs'])) : '[]';
                    break;
                }
                $_tgtCount = count($targetIds);
                $_okRatio = ($n === 0) ? '0' : ($n . '/' . $_tgtCount);
                $this->_log_std("[SFU forward VIDEO  stream={$streamId}] #pkt={$_vidDiag[$streamId]['cnt']} srcPT={$hPT} srcSSRC={$hSSRC} kind={$kind} codec={$codecName} marker={$hMarker} seq={$hSeq} => 目标play端数={$_tgtCount} 成功转发={$_okRatio}（首目标sub={$firstSubSid} 其 primaryVideoPT={$firstSubPriVpt} 其videoPTs顺序={$firstSubVPts}）\n");
            }
        }

        return $n;
    }


    /**
     * 把订阅者发来的 RTCP feedback（PLI/FIR/NACK等）relay 给 streamId 对应的 push 端（publisher）。
     * 用 publisher 端 Chrome/WebRTC 编码器收到 PLI/FIR 后会立刻生成新 IDR 关键帧（约 100~300ms）。
     *
     * @param string $streamId
     * @param string $rtcpBody 明文 RTCP 包
     * @return bool 是否找到 publisher 并实际发送成功
     */
    public function relayRtcpToPublisher(string $streamId, string $rtcpBody): bool
    {
        if ($streamId === '' || !is_string($rtcpBody) || strlen($rtcpBody) < 8) return false;
        $pubId = null;
        foreach ($this->clients as $id => $c) {
            $id = (int)$id;
            $m = isset($c['meta']) && is_array($c['meta']) ? $c['meta'] : [];
            if (($m['streamId'] ?? '') === $streamId && ($m['role'] ?? '') === 'push') {
                $pubId = $id;
                break;
            }
        }
        if ($pubId === null) return false;
        return $this->protectAndSendRtcp($pubId, $rtcpBody);
    }

    public static function resolvePublisherVideoSsrc(array $client): array
    {
        $valid = static function ($ssrc): bool {
            $ssrc = (int)$ssrc;
            return $ssrc > 1 && $ssrc !== 4147483647;
        };
        $byKind = is_array($client['incomingSsrcByKind'] ?? null) ? $client['incomingSsrcByKind'] : [];
        if ($valid($byKind['video'] ?? 0)) return [(int)$byKind['video'], 'incomingSsrcByKind'];

        $byPt = is_array($client['incomingSsrcByPt'] ?? null) ? $client['incomingSsrcByPt'] : [];
        $videoPTs = is_array($client['videoPTs'] ?? null) ? array_keys($client['videoPTs']) : [];
        foreach ($videoPTs as $videoPt) {
            if ($valid($byPt[(int)$videoPt] ?? 0)) return [(int)$byPt[(int)$videoPt], 'PT'];
        }

        $meta = is_array($client['meta'] ?? null) ? $client['meta'] : [];
        if ($valid($meta['clientVideoSsrc'] ?? 0)) return [(int)$meta['clientVideoSsrc'], 'metadata'];
        $localByKind = is_array($client['localSsrcByKind'] ?? null) ? $client['localSsrcByKind'] : [];
        if ($valid($localByKind['video'] ?? 0)) return [(int)$localByKind['video'], 'localSsrcByKind'];
        $legacySsrc = $meta['videoSsrc'] ?? ($meta['ssrcVideo'] ?? 0);
        if ($valid($legacySsrc)) return [(int)$legacySsrc, 'metadata'];
        return [0, 'none'];
    }

    /**
     * 【秒开 3/3】SFU 主动向 push 端（浏览器）发送 PLI RTCP (RFC 4585 §6.3 PSFB, FMT=1 Picture Loss Indication)，
     * 浏览器编码器立即生成 IDR 关键帧（通常 100~300ms），所有订阅者下一包就是新 IDR → 秒开。
     *
     * @param string $streamId 要刷新关键帧的流
     * @param bool   $throttle 是否节流（默认 true：同一 stream 500ms 内只发一次 PLI，避免浏览器频繁请求 IDR 爆 CPU）
     * @return bool 实际是否发送了 PLI
     */
    public function sendPliToPublisher(string $streamId, bool $throttle = true): bool
    {
        if ($streamId === '') return false;
        if (!isset($this->_gopCacheByStream[$streamId])) {
            $this->_gopCacheByStream[$streamId] = [
                'hasIdr' => false, 'gop' => [], 'lastSpsPps' => [],
                'lastIdrSeq' => null, 'lastPliSentTs' => 0.0, 'lastKfBurstSids' => [],
            ];
        }
        $gc = &$this->_gopCacheByStream[$streamId];
        $nowF = microtime(true);
        if ($throttle && ($nowF - (float)$gc['lastPliSentTs']) < 0.5) {
            return false;
        }
        $pubId = null;
        $pubSsrc = 0;
        $pubSsrcSource = 'none';
        $publisher = [];
        foreach ($this->clients as $id => $c) {
            $id = (int)$id;
            $m = isset($c['meta']) && is_array($c['meta']) ? $c['meta'] : [];
            if (($m['streamId'] ?? '') === $streamId && ($m['role'] ?? '') === 'push') {
                $pubId = $id;
                $publisher = $c;
                [$pubSsrc, $pubSsrcSource] = self::resolvePublisherVideoSsrc($c);
                break;
            }
        }
        if ($pubId === null) return false;

        static $_obsPliEvidence = [];
        $_obsEvidenceNow = microtime(true);
        if (!isset($_obsPliEvidence[$streamId])) $_obsPliEvidence[$streamId] = ['count'=>0, 'lastAt'=>0.0];
        $_obsPliEvidence[$streamId]['count']++;
        if ($_obsPliEvidence[$streamId]['count'] <= 3 || ($_obsEvidenceNow - $_obsPliEvidence[$streamId]['lastAt']) >= 10.0) {
            $_obsPliEvidence[$streamId]['lastAt'] = $_obsEvidenceNow;
            $_obsEvidenceData = ['streamId'=>$streamId,'publisherId'=>$pubId,'resolvedVideoSsrc'=>$pubSsrc,'source'=>$pubSsrcSource,'incomingSsrcByKind'=>(array)($publisher['incomingSsrcByKind'] ?? []),'incomingSsrcByPt'=>(array)($publisher['incomingSsrcByPt'] ?? []),'publisherVideoPtKeys'=>array_keys((array)($publisher['videoPTs'] ?? []))];
            $this->_log_std('[OBS PLI SSRC POST-FIX] ' . json_encode($_obsEvidenceData) . "\n");
        }

        if ($pubSsrc <= 0) return false;

        $sfuSsrc = 0x53465500;
        $pli = pack('CCnNN',
            (2 << 6) | 1,
            206,
            2,
            $sfuSsrc,
            $pubSsrc
        );

        static $_dbgPliPack = false;
        if (!$_dbgPliPack) {
            $_dbgPliPack = true;
            $l = is_string($pli) ? strlen($pli) : -1;
            $this->_log_std("[PLI PACK DEBUG FIXED] format=CCnNN 5params sfuSsrc=0x".dechex($sfuSsrc)." pubSsrc={$pubSsrc} len=".$l." EXPECT=12 hex=".($l>0?bin2hex($pli):'NULL')." (only first call)\n");
        }
        $cPub = $this->clients[$pubId] ?? null;
        $rcEmpty = true; $srtpTxEmpty = true;
        if ($cPub) {
            $rcEmpty = empty($cPub['remoteCandidate']);
            $srtpTxEmpty = empty($cPub['srtpTx']);
        }
        $ok = $this->protectAndSendRtcp($pubId, $pli);
        if ($ok) {
            $this->_dbgPerfBurstEvent($streamId, 'pli');
            $gc['lastPliSentTs'] = $nowF;
            $this->_log_std("[秒开 PLI SEND] streamId={$streamId} publisherId={$pubId} videoSsrc={$pubSsrc} rcReady=" . ($rcEmpty?'NO':'yes') . " srtpTxReady=" . ($srtpTxEmpty?'NO':'yes') . " → 浏览器将立即出新IDR\n");
        } else {
            $this->_log_std("[秒开 PLI SEND FAIL] streamId={$streamId} publisherId={$pubId} protectAndSendRtcp=false — publisher state: rcEmpty=" . ($rcEmpty?'YES':'no') . " srtpTxEmpty=" . ($srtpTxEmpty?'YES':'no') . " (srtpTx/remoteCandidate 未就绪?)\n");
        }
        return $ok;
    }

    /**
     * 给单个订阅者 burst-send 缓存的最近一份完整 GOP（先立刻出画面（<100ms 显示缓存画面）。
     * 用于：① 订阅者新 join；② 3s 兜底还没出画面的订阅者。
     *
     * @param string $streamId
     * @param int    $subscriberId
     * @return int 成功发送的帧数量
     */
    public function _burstCachedGopToSubscriber(string $streamId, int $subscriberId): int
    {
        if (!isset($this->_gopCacheByStream[$streamId]) || !isset($this->clients[$subscriberId])) return 0;
        $gc = $this->_gopCacheByStream[$streamId];
        $generation = (int)($gc['generation'] ?? 0);
        if (!empty($this->clients[$subscriberId]['_liveVidSent'])
            || $generation <= 0
            || (int)($gc['lastBurstGeneration'][$subscriberId] ?? -1) === $generation
            || empty($gc['hasIdr'])
            || empty($gc['gop'])) return 0;
        $n = 0;
        $this->_log_std("[burst DIAG] streamId={$streamId} sub={$subscriberId} hasIdr=" . ($gc['hasIdr']?'YES':'NO') . " gopCount=" . count($gc['gop']) . " lastSpsPpsKeys=" . json_encode(array_keys(isset($gc['lastSpsPps']) && is_array($gc['lastSpsPps']) ? $gc['lastSpsPps'] : [])) . "\n");
        $_diagNals = [];
        foreach ($gc['gop'] as $_idx => $_rtpF) {
            if ($_idx >= 5) break;
            $_b0 = ord($_rtpF[0]);
            $_cc = $_b0 & 0xF;
            $_hL = 12 + 4 * $_cc;
            if (($_b0 >> 4) & 0x1) {
                if (strlen($_rtpF) >= $_hL + 4) {
                    $_eL = unpack('n', substr($_rtpF, $_hL + 2, 2))[1];
                    $_hL += 4 + 4 * $_eL;
                }
            }
            $_pL = strlen($_rtpF) - $_hL;
            if ($_pL > 0) {
                $_p0 = ord($_rtpF[$_hL]);
                $_nt = $_p0 & 0x1F;
                if ($_nt === 28 && $_pL >= 2) {
                    $_ft = ord($_rtpF[$_hL + 1]) & 0x1F;
                    $_fs = (ord($_rtpF[$_hL + 1]) >> 7) & 1;
                    $_diagNals[] = "FU-A(t={$_ft},S={$_fs})";
                } elseif ($_nt === 24) {
                    $_diagNals[] = "STAP-A";
                } else {
                    $_diagNals[] = "type={$_nt}";
                }
            }
        }
        $this->_log_std("[burst GOP NALs] streamId={$streamId} sub={$subscriberId} first5=[" . implode(', ', $_diagNals) . "]\n");
        $_dbgBurstLastFrameK = null;
        foreach ($gc['gop'] as $rtpFrame) {
            if ($this->protectAndSendRtp($subscriberId, $rtpFrame, true, 'video')) {
                $n++;
                $_dbgBurstLastFrameK = $rtpFrame;
            }
        }
        if (is_string($_dbgBurstLastFrameK)) {
            $_dbgServerVideoSsrcK = (int)($this->clients[$subscriberId]['serverVideoSsrc'] ?? 0);
            $this->clients[$subscriberId]['_dbgBurstLastVideoRtpK'] = $_dbgBurstLastFrameK;
            $this->clients[$subscriberId]['_dbgBurstLastOutSeqK'] = isset($this->clients[$subscriberId]['_outSeq'][$_dbgServerVideoSsrcK]) ? (int)$this->clients[$subscriberId]['_outSeq'][$_dbgServerVideoSsrcK] : null;
            $this->clients[$subscriberId]['_dbgBurstStreamIdK'] = $streamId;
            $this->clients[$subscriberId]['_burstBoundaryPublisherSeq'] = unpack('n', substr($_dbgBurstLastFrameK, 2, 2))[1];
            $this->clients[$subscriberId]['_burstBoundaryPublisherTs'] = unpack('N', substr($_dbgBurstLastFrameK, 4, 4))[1];
        }
        $gopComplete = $n === count($gc['gop']);
        if ($gopComplete && $n > 0 && isset($this->_gopCacheByStream[$streamId], $this->clients[$subscriberId])) {
            $this->clients[$subscriberId]['_liveVidSent'] = true;
            $this->_dbgPerfBurstEvent($streamId, 'gopBurst');
            $this->_gopCacheByStream[$streamId]['lastBurstGeneration'][$subscriberId] = $generation;
            $this->_gopCacheByStream[$streamId]['lastKfBurstSids'][$subscriberId] = microtime(true);
            unset($this->_gopCacheByStream[$streamId]['_retryKicks'][$subscriberId]);
        }
        return $n;
    }

    /**
     * 公共 helper：找 push 端 clientId
     * @param string $streamId
     * @return int|null 找不到时返回 null
     */
    public function getPublisherClientId(string $streamId): ?int
    {
        if ($streamId === '') return null;
        foreach ($this->clients as $id => $c) {
            $id = (int)$id;
            $m = isset($c['meta']) && is_array($c['meta']) ? $c['meta'] : [];
            if (($m['streamId'] ?? '') === $streamId && ($m['role'] ?? '') === 'push') return $id;
        }
        return null;
    }

    /**
     * 尝试给某 play 端 subscriber 做秒开「组合拳」：
     *   - 若 push 端已存在 → sendPliToPublisher()（强制编码器出新 IDR，约 100~300ms 到订阅者）
     *   - 若当前已有缓存 GOP → 立刻 burst-send 缓存 GOP（srtpTx 就绪时）
     * 本方法幂等：同 streamId 下 PLI 500ms 节流；同 subscriber 下 GOP burst 3s 节流
     * @param int $subscriberId
     * @return array{pliSent:bool, gopBurst:int} 实际动作
     */
    public function kickFaststartForSubscriber(int $subscriberId): array
    {
        $res = ['pliSent' => false, 'gopBurst' => 0];
        if (!isset($this->clients[$subscriberId])) return $res;
        $c = $this->clients[$subscriberId];
        $m = isset($c['meta']) && is_array($c['meta']) ? $c['meta'] : [];
        $sidStr = (string)($m['streamId'] ?? '');
        $role = (string)($m['role'] ?? '');
        if ($sidStr === '' || $role !== 'play') return $res;

        if (!isset($this->_gopCacheByStream[$sidStr])) {
            $this->_gopCacheByStream[$sidStr] = $this->_newGopCacheEntry();
        }
        $gc = $this->_gopCacheByStream[$sidStr];
        $generation = (int)($gc['generation'] ?? 0);
        if (!empty($c['_liveVidSent'])) return $res;

        $nowF = microtime(true);
        $hasTx = !empty($c['srtpTx']) && !empty($c['remoteCandidate']);
        if ($hasTx && !empty($gc['hasIdr']) && !empty($gc['gop'])) {
            $res['gopBurst'] = $this->_burstCachedGopToSubscriber($sidStr, $subscriberId);
            if ($res['gopBurst'] > 0) {
                $this->_log_std("[秒开 组合拳] subscriber={$subscriberId} streamId={$sidStr} burst-send cached GOP {$res['gopBurst']} frames generation={$generation}\n");
                return $res;
            }
        }

        $gc = $this->_gopCacheByStream[$sidStr] ?? $gc;
        if (!isset($gc['_retryKicks'][$subscriberId])) {
            $gc['_retryKicks'][$subscriberId] = [$nowF, false, false, false];
            if ($this->getPublisherClientId($sidStr) !== null) {
                $res['pliSent'] = $this->sendPliToPublisher($sidStr, false);
            }
            $this->_log_std("[秒开 三级重注队列] subscriber={$subscriberId} streamId={$sidStr} hasTx=" . ($hasTx?'YES':'no') . " generation={$generation}\n");
        }
        $this->_gopCacheByStream[$sidStr] = $gc;
        return $res;
    }

    /**
     * 获取本服务器地址
     * @return mixed|string
     * @note 正式环境可以替换为你自己的方法，返回公网IP即可
     */
    public function getLocalIP()
    {
        $publicIp = trim((string)$this->publicIp);
        if ($publicIp !== '') return $publicIp;

        $ip = '127.0.0.1';
        foreach (gethostbynamel(gethostname()) as $addr) {
            if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $addr !== '127.0.0.1') {
                $ip = $addr;
                break;
            }
        }

        return $ip;
    }

    /**
     * 发送datachannel数据
     * @param int $clientId 客户id
     * @param string $message 消息内容
     * @param int $ppid 数据传输类型 51可靠传输
     * @param int $sid 流id
     * @return bool
     */
    public function sendDataChannel(int $clientId,string $message,int $ppid = 51,int $sid = 0)
    {
        if (!isset($this->clients[$clientId]['sctp']) || $this->clients[$clientId]['sctp']['state'] !== 'ESTABLISHED') {
            $this->_log_std("Client {$clientId} sendDataChannel: SCTP not ESTABLISHED; drop.\n");
            return false;
        }
        $this->sendDataOverSCTP($clientId, $sid, $message, $ppid);
        return true;
    }

    /**
     * 公共 API：为 SFU 订阅者（play 端 client）生成一份可发送给它的 Offer SDP
     *
     * 实现：复用 generateAnswerSDP() 先基于「publisher 曾经的 offer」生成一份「SFU 作为 answerer」的 SDP 模板
     *       （这会填好 subscriber 需要的 serverVideoSsrc/serverAudioSsrc/videoPTs/audioPTs/localSsrcByKind）
     *       然后把 a=setup 改成 actpass / ice credentials 保持 SFU->subscriber 的本地凭据，返回能作为 Offer 发送的 SDP。
     *
     * 说明：此方法返回的 SDP 里的 SSRC，与 forwardRtpToClient/forwardRtpToAllSubscribers 保护时重写的 SSRC 完全一致，
     *       因此 play 端 setRemoteDescription(offer) 之后收到的 RTP SRTP 解包校验将 100% 通过。
     *
     * @param int $subscriberId 订阅者（play 端） clientId
     * @param int $publisherId  发布者（push 端） clientId（必须已经完成过 handleOffer 且 clients[publisherId]['remoteOfferSdp'] 已保存）
     * @param string $setup     默认 passive（服务器明确扮演 DTLS Server 角色，强制浏览器 answer 为 setup=active 并发送 ClientHello）
     *                          禁止 actpass：纯 recvonly 的 Play 端浏览器遇到 actpass 会故意选 passive，
     *                          结果双方都等对方发 ClientHello → DTLS 永远不启动（debug.log里的纯STUN风暴）
     * @return string|null      返回 SDP 字符串，失败返回 null
     */
    public function makeSfuOfferForSubscriber(int $subscriberId, int $publisherId, string $setup = 'passive'): ?string
    {
        $_subMeta = isset($this->clients[$subscriberId]['meta']) && is_array($this->clients[$subscriberId]['meta']) ? $this->clients[$subscriberId]['meta'] : [];
        $_pubMeta = isset($this->clients[$publisherId]['meta'])   && is_array($this->clients[$publisherId]['meta'])   ? $this->clients[$publisherId]['meta']   : [];
        $_subRole = isset($_subMeta['role']) ? $_subMeta['role'] : '?';
        $_subSid  = isset($_subMeta['streamId']) ? $_subMeta['streamId'] : '?';
        $_pubRole = isset($_pubMeta['role']) ? $_pubMeta['role'] : '?';
        $_pubSid  = isset($_pubMeta['streamId']) ? $_pubMeta['streamId'] : '?';
        $this->_log_std("[makeSfuOfferForSubscriber ENTER] sub={$subscriberId}[role={$_subRole} sid={$_subSid}] pub={$publisherId}[role={$_pubRole} sid={$_pubSid}] setup={$setup}\n");

        if (!isset($this->clients[$publisherId])) {
            $this->_log_std("makeSfuOfferForSubscriber: publisherId={$publisherId} not in clients\n");
            return null;
        }
        if (!isset($this->clients[$subscriberId])) {
            $this->_log_std("makeSfuOfferForSubscriber: subscriberId={$subscriberId} not in clients\n");
            return null;
        }

        $streamId = $_subSid;
        if ($streamId === '' || !isset($this->_sfuStreamConfig[$streamId]) || !is_array($this->_sfuStreamConfig[$streamId])) {
            $this->_log_std("[makeSfuOffer ABORT] streamId={$streamId} 主播未推流 / _sfuStreamConfig 不存在，返回null → 前端应收到stream-not-ready\n");
            return null;
        }
        $cfg = $this->_sfuStreamConfig[$streamId];
        $_vSsrc   = (int)($cfg['serverVideoSsrc'] ?? 0);
        $_aSsrc   = (int)($cfg['serverAudioSsrc'] ?? 0);
        $_cname   = (string)($cfg['cname'] ?? '');
        $_streamUuid      = (string)($cfg['msidStreamId'] ?? '');
        $_videoTrackUuid  = (string)($cfg['msidVideoTrackId'] ?? '');
        $_audioTrackUuid  = (string)($cfg['msidAudioTrackId'] ?? '');
        $_forcePv = (int)($cfg['primaryVideoPT'] ?? 0);
        $_forcePa = (int)($cfg['primaryAudioPT'] ?? 0);
        if ($_vSsrc <= 0 || $_aSsrc <= 0 || $_cname === '' || $_streamUuid === '' || $_videoTrackUuid === '' || $_audioTrackUuid === '') {
            $this->_log_std("[makeSfuOffer ABORT] streamId={$streamId} _sfuStreamConfig 字段缺失，vSSRC={$_vSsrc} aSSRC={$_aSsrc} cname={$_cname}\n");
            return null;
        }
        $this->_log_std("[makeSfuOffer SHARED IDS (from push端共享)] streamId={$streamId} vSSRC={$_vSsrc} aSSRC={$_aSsrc} cname={$_cname}"
                        . " primaryV={$_forcePv} primaryA={$_forcePa} streamId={$_streamUuid}\n");

        $pubOfferSdp = (string)($this->clients[$publisherId]['remoteOfferSdp'] ?? '');
        if ($pubOfferSdp === '') {
            $this->_log_std("makeSfuOfferForSubscriber: publisherId={$publisherId} has no remoteOfferSdp (run handleOffer before publisher becomes ready)\n");
            return null;
        }
        $remoteIceUfrag = (string)($this->clients[$publisherId]['remoteIceUfrag'] ?? '');
        $remoteIcePwd   = (string)($this->clients[$publisherId]['remoteIcePwd']   ?? '');
        $remoteSetup    = (string)($this->clients[$publisherId]['remoteSetup']    ?? 'actpass');
        if ($remoteIceUfrag === '' || $remoteIcePwd === '') {
            $remoteIceUfrag = (string)$this->extractSdpAttribute($pubOfferSdp, 'ice-ufrag');
            $remoteIcePwd   = (string)$this->extractSdpAttribute($pubOfferSdp, 'ice-pwd');
            $remoteSetup    = (string)$this->extractSdpAttribute($pubOfferSdp, 'setup');
            if ($remoteSetup === '') $remoteSetup = 'actpass';
            $this->clients[$publisherId]['remoteIceUfrag'] = $remoteIceUfrag;
            $this->clients[$publisherId]['remoteIcePwd']   = $remoteIcePwd;
            $this->clients[$publisherId]['remoteSetup']    = $remoteSetup;
        }

        $answerInfo = $this->generateAnswerSDP($pubOfferSdp, $remoteIceUfrag, $remoteIcePwd, $remoteSetup, [
            'forceVideoAudioDefault' => true,
            'serverVideoSsrc'  => $_vSsrc,
            'serverAudioSsrc'  => $_aSsrc,
            'cname'            => $_cname,
            'msidStream'       => $_streamUuid,
            'msidVideoTrack'   => $_videoTrackUuid,
            'msidAudioTrack'   => $_audioTrackUuid,
            'h264ProfileLevelId' => (string)($cfg['h264ProfileLevelId'] ?? '42e01f'),
        ]);
        $templateSdp = (string)($answerInfo['sdp'] ?? '');
        $localUfrag  = (string)($answerInfo['ice-ufrag'] ?? '');
        $localPwd    = (string)($answerInfo['ice-pwd']   ?? '');
        if ($templateSdp === '' || $localUfrag === '' || $localPwd === '') {
            $this->_log_std("makeSfuOfferForSubscriber: generateAnswerSDP failed for subscriberId={$subscriberId}\n");
            return null;
        }

        $this->clients[$subscriberId]['localIceUfrag'] = $localUfrag;
        $this->clients[$subscriberId]['localIcePwd']   = $localPwd;
        $this->clients[$subscriberId]['iceUfrag']      = $localUfrag;
        $this->clients[$subscriberId]['icePwd']        = $localPwd;

        $this->clients[$subscriberId]['videoPTs']        = $this->_reorderPTsForSubscriber(
            (isset($cfg['videoPTs']) && is_array($cfg['videoPTs']) ? $cfg['videoPTs'] : []),
            $_forcePv
        );
        $this->clients[$subscriberId]['audioPTs']        = $this->_reorderPTsForSubscriber(
            (isset($cfg['audioPTs']) && is_array($cfg['audioPTs']) ? $cfg['audioPTs'] : []),
            $_forcePa
        );
        $this->clients[$subscriberId]['serverVideoSsrc'] = $_vSsrc;
        $this->clients[$subscriberId]['serverAudioSsrc'] = $_aSsrc;
        $this->clients[$subscriberId]['serverSsrc']      = $_vSsrc;
        $this->clients[$subscriberId]['localSsrcByKind'] = ['video' => $_vSsrc, 'audio' => $_aSsrc];
        $this->clients[$subscriberId]['primaryVideoPT']  = $_forcePv;
        $this->clients[$subscriberId]['primaryAudioPT']  = $_forcePa;

        $_pubForFix = $this->clients[$publisherId] ?? null;
        if (is_array($_pubForFix)) {
            $_pvPub = (int)($_pubForFix['primaryVideoPT'] ?? 0);
            $_paPub = (int)($_pubForFix['primaryAudioPT'] ?? 0);

            $_getPtInfo = function (int $pt, string $kind, array $pClone): ?array {
                $ptMap = $kind === 'video'
                    ? (is_array($pClone['videoPTs'] ?? null) ? $pClone['videoPTs'] : [])
                    : (is_array($pClone['audioPTs'] ?? null) ? $pClone['audioPTs'] : []);
                if (isset($ptMap[$pt]) && is_array($ptMap[$pt])) return $ptMap[$pt];
                if ($kind === 'video') {
                    return ['rtpmap' => 'H264/90000', 'codec' => 'H264', 'clock' => 90000,
                            'fmtp' => 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f'];
                }
                return ['rtpmap' => 'opus/48000/2', 'codec' => 'opus', 'clock' => 48000,
                        'fmtp' => 'minptime=10;useinbandfec=1'];
            };
            $_subFixChanged = false;
            if ($_pvPub > 0) {
                if (!isset($this->clients[$subscriberId]['videoPTs'][$_pvPub])) {
                    $_info = $_getPtInfo($_pvPub, 'video', $_pubForFix);
                    if ($_info !== null) {
                        $this->clients[$subscriberId]['videoPTs'][$_pvPub] = $_info;
                        $_subFixChanged = true;
                    }
                }
                if (((int)($this->clients[$subscriberId]['primaryVideoPT'] ?? 0)) !== $_pvPub) {
                    $this->clients[$subscriberId]['primaryVideoPT'] = $_pvPub;
                    $_forcePv = $_pvPub;
                    $_subFixChanged = true;
                }
            }
            if ($_paPub > 0) {
                if (!isset($this->clients[$subscriberId]['audioPTs'][$_paPub])) {
                    $_info = $_getPtInfo($_paPub, 'audio', $_pubForFix);
                    if ($_info !== null) {
                        $this->clients[$subscriberId]['audioPTs'][$_paPub] = $_info;
                        $_subFixChanged = true;
                    }
                }
                if (((int)($this->clients[$subscriberId]['primaryAudioPT'] ?? 0)) !== $_paPub) {
                    $this->clients[$subscriberId]['primaryAudioPT'] = $_paPub;
                    $_forcePa = $_paPub;
                    $_subFixChanged = true;
                }
            }
            if ($_subFixChanged) {
                $this->clients[$subscriberId]['videoPTs'] = $this->_reorderPTsForSubscriber(
                    is_array($this->clients[$subscriberId]['videoPTs']) ? $this->clients[$subscriberId]['videoPTs'] : [],
                    (int)$this->clients[$subscriberId]['primaryVideoPT']
                );
                $this->clients[$subscriberId]['audioPTs'] = $this->_reorderPTsForSubscriber(
                    is_array($this->clients[$subscriberId]['audioPTs']) ? $this->clients[$subscriberId]['audioPTs'] : [],
                    (int)$this->clients[$subscriberId]['primaryAudioPT']
                );
                $this->_log_std("[makeSfuOffer 兜底注入 sub={$subscriberId}] 继承 publisherId={$publisherId} 实际 primaries: "
                                . "videoPT=" . $this->clients[$subscriberId]['primaryVideoPT']
                                . " audioPT=" . $this->clients[$subscriberId]['primaryAudioPT']
                                . " vPTs=" . json_encode(array_keys($this->clients[$subscriberId]['videoPTs']))
                                . " aPTs=" . json_encode(array_keys($this->clients[$subscriberId]['audioPTs'])) . "\n");
            }
        }

        $_needRewriteSdpMline = true;
        $_newVorderForRewrite = array_values(array_map('intval',
            array_keys(is_array($this->clients[$subscriberId]['videoPTs']) ? $this->clients[$subscriberId]['videoPTs'] : [])));
        $_newAorderForRewrite = array_values(array_map('intval',
            array_keys(is_array($this->clients[$subscriberId]['audioPTs']) ? $this->clients[$subscriberId]['audioPTs'] : [])));

        $this->_log_std("makeSfuOfferForSubscriber(sub={$subscriberId}, pub={$publisherId}) [共享 primaries 强制写入完成] primaryV={$_forcePv} primaryA={$_forcePa}"
                        . " vPTs=" . json_encode(array_keys($this->clients[$subscriberId]['videoPTs']))
                        . " aPTs=" . json_encode(array_keys($this->clients[$subscriberId]['audioPTs'])) . "\n");

        $offerSdp = $templateSdp;
        $offerSdp = preg_replace_callback(
            '/^a=(sendonly|recvonly|sendrecv|inactive)(\r?)(\n|$)/m',
            static function (array $m): string {
                switch ($m[1]) {
                    case 'sendonly': $direction = 'recvonly'; break;
                    case 'recvonly': $direction = 'sendonly'; break;
                    default:         $direction = $m[1];
                }
                return 'a=' . $direction . $m[2] . $m[3];
            },
            $offerSdp
        );
        if (!is_string($offerSdp)) $offerSdp = $templateSdp;
        $offerSdp = preg_replace('/a=setup:[^\r\n]*/', 'a=setup:' . $setup, $offerSdp, 1);
        if (!is_string($offerSdp)) $offerSdp = $templateSdp;

        $offerSdp = preg_replace_callback(
            '/^m=(video|audio)([^\r\n]*)$/m',
            static function(array $m) use ($_newVorderForRewrite, $_newAorderForRewrite) {
                $parts = preg_split('/\s+/', trim((string)$m[2]));
                if (!is_array($parts) || count($parts) < 3) return $m[0];
                $targetPts = $m[1] === 'video' ? $_newVorderForRewrite : $_newAorderForRewrite;
                if (empty($targetPts)) return $m[0];
                return 'm=' . $m[1] . ' ' . implode(' ', array_slice($parts, 0, 3)) . ' ' . implode(' ', $targetPts);
            },
            (string)$offerSdp
        );
        if (!is_string($offerSdp) || $offerSdp === '') $offerSdp = $templateSdp;
        $this->clients[$subscriberId]['outVideoPT'] = (int)($this->clients[$subscriberId]['primaryVideoPT'] ?? 0);
        $this->clients[$subscriberId]['outAudioPT'] = (int)($this->clients[$subscriberId]['primaryAudioPT'] ?? 0);

        $this->_log_std("=== SFU OFFER to sub={$subscriberId} (len=" . strlen($offerSdp) . ") ===\n" . $offerSdp . "=== END SFU OFFER ===\n");

        return $offerSdp;
    }

    /**
     * 移除客户端
     * @param $id
     * @return void
     */
    private function removeClient($id)
    {
        if (!isset($this->clients[$id])) return;
        $id = (int)$id;

        $_snap = $this->clients[$id];
        $_role     = (string)($_snap['meta']['role'] ?? '?');
        $_streamId = (string)($_snap['meta']['streamId'] ?? '');
        $_rc       = $_snap['remoteCandidate'] ?? null;
        $_rcAddr   = $_rc ? "{$_rc['ip']}:{$_rc['port']}" : 'none';
        $_hasSrtpTx = empty($_snap['srtpTx']) ? 'no' : 'yes';
        $_hasSrtpRx = empty($_snap['srtpRx']) ? 'no' : 'yes';
        $_state    = (string)($_snap['state'] ?? '?');
        $_dtls     = (string)($_snap['dtlsState'] ?? '?');
        $_hasWs    = isset($_snap['socket']) && is_resource($_snap['socket']) ? 'alive' : 'closed';
        $_vssrc    = $_snap['serverVideoSsrc'] ?? '?';
        $_assrc    = $_snap['serverAudioSsrc'] ?? '?';
        $_lastSeen = isset($_snap['lastSeenAt']) ? number_format(microtime(true) - (float)$_snap['lastSeenAt'], 1) . 's' : 'never';
        $this->_log_std("[removeClient ⚡ START] id={$id} role={$_role} streamId={$_streamId} state={$_state} dtls={$_dtls} ws={$_hasWs} rc={$_rcAddr} srtpTx={$_hasSrtpTx} srtpRx={$_hasSrtpRx} vSSRC={$_vssrc} aSSRC={$_assrc} lastSeen={$_lastSeen} clientsBefore=" . count($this->clients) . "\n");

        if (isset($this->onLeave) && is_callable($this->onLeave)) {
            try {
                $_cb = $this->onLeave;
                $_cb((int)$id, $this);
            } catch (\Throwable $e) {
                $this->_log_std("[removeClient  onLeave EXCEPTION] id={$id}: " . $e->getMessage() . "\n");
            }
        }

        if ($_role === 'push' && $_streamId !== '') {
            $this->_log_std("[removeClient  PUSH端离开 触发全体观众踢下线] streamId={$_streamId} publisherId={$id} 开始收集play端...\n");

            $_victims = [];
            foreach ($this->clients as $_cid => $_c) {
                $_cid = (int)$_cid;
                if ($_cid === $id) continue;
                $_meta = $_c['meta'] ?? [];
                if (!is_array($_meta)) continue;
                if (($_meta['streamId'] ?? '') === $_streamId && in_array(($_meta['role'] ?? ''), ['play', 'subscriber'], true)) {
                    $_victims[] = $_cid;
                }
            }

            foreach ($_victims as $_vid) {
                if (!isset($this->clients[$_vid])) continue;
                $_sock = $this->clients[$_vid]['socket'] ?? null;
                if (is_resource($_sock)) {
                    $this->sendSignaling($_vid, ['type' => 'publisher-left', 'streamId' => $_streamId, 'message' => '主播已停止推流，节目已下线']);
                }
            }

            if (isset($this->_sfuStreamConfig[$_streamId])) {
                unset($this->_sfuStreamConfig[$_streamId]);
                $this->_log_std("[removeClient  PUSH端离开] 销毁 _sfuStreamConfig[{$_streamId}]（下次推流生成全新的MSID/SSRC/CNAME/PT）\n");
            }
            if (isset($this->_gopCacheByStream[$_streamId])) {
                unset($this->_gopCacheByStream[$_streamId]);
                $this->_log_std("[removeClient  PUSH端离开] 销毁 _gopCacheByStream[{$_streamId}]（清空旧GOP防止串到下一次直播）\n");
            }

            $_pDoneCleaned = 0;
            foreach (['_video','_audio'] as $_kSfx) {
                $_kKey = $_streamId . $_kSfx;
                if (isset($this->_primaryRefreshDone[$_kKey])) {
                    unset($this->_primaryRefreshDone[$_kKey]);
                    $_pDoneCleaned++;
                }
                unset($this->_actualPrimaryByStreamKind[$_kKey]);
            }
            if ($_pDoneCleaned > 0) {
                $this->_log_std("[removeClient  PUSH端离开] 清理 _primaryRefreshDone[{$_streamId}]* ({$_pDoneCleaned} entries)（下次推流强制重新探测实际PT）\n");
            }

            if (isset($this->_vp8LastKfTsByStream[$_streamId])) {
                unset($this->_vp8LastKfTsByStream[$_streamId]);
                $this->_log_std("[removeClient  PUSH端离开] 清理 _vp8LastKfTsByStream[{$_streamId}]（下次推流TS重新基线，防止KF误判）\n");
            }

            foreach ($_victims as $_vid) {
                if (!isset($this->clients[$_vid])) continue;
                $this->_log_std("[removeClient  PUSH端离开] → 踢 play 端 clientId={$_vid}\n");
                $this->removeClient($_vid);
            }
            $this->_log_std("[removeClient  PUSH端离开 DONE] streamId={$_streamId} 踢了 " . count($_victims) . " 个观众，共享缓存已清空\n");
        }

        $_gopCleaned = 0;
        foreach ($this->_gopCacheByStream as $_sidStr => $_gcRef) {
            $dirty = false;
            if (isset($_gcRef['_retryKicks']) && isset($_gcRef['_retryKicks'][$id])) {
                unset($_gcRef['_retryKicks'][$id]);
                $dirty = true;
            }
            if (isset($_gcRef['lastKfBurstSids']) && isset($_gcRef['lastKfBurstSids'][$id])) {
                unset($_gcRef['lastKfBurstSids'][$id]);
                $dirty = true;
            }
            if (isset($_gcRef['lastBurstGeneration'][$id])) {
                unset($_gcRef['lastBurstGeneration'][$id]);
                $dirty = true;
            }
            if ($dirty) {
                $this->_gopCacheByStream[$_sidStr] = $_gcRef;
                $_gopCleaned++;
            }
        }
        if ($_gopCleaned > 0) $this->_log_std("[removeClient GOP cache] id={$id}: cleaned _retryKicks+lastKfBurstSids in {$_gopCleaned} stream entries\n");

        $_srtpCleaned = 0;
        if (isset($this->clients[$id])) {
            if (!empty($this->clients[$id]['srtpTx'])) {
                try {
                    if (is_object($this->clients[$id]['srtpTx']) && method_exists($this->clients[$id]['srtpTx'], '__destruct')) {
                        $this->clients[$id]['srtpTx'] ->__destruct();
                    }
                } catch (\Throwable $_) {}
                $this->clients[$id]['srtpTx'] = null;
                $_srtpCleaned++;
            }
            if (!empty($this->clients[$id]['srtpRx'])) {
                try {
                    if (is_object($this->clients[$id]['srtpRx']) && method_exists($this->clients[$id]['srtpRx'], '__destruct')) {
                        $this->clients[$id]['srtpRx']->__destruct();
                    }
                } catch (\Throwable $_) {}
                $this->clients[$id]['srtpRx'] = null;
                $_srtpCleaned++;
            }

            $this->clients[$id]['srtpKeyed'] = false;
            $this->clients[$id]['serverVideoSsrc'] = 0;
            $this->clients[$id]['serverAudioSsrc'] = 0;
            $this->clients[$id]['serverSsrc'] = 0;
            $this->clients[$id]['localSsrcByKind'] = [];
            $this->clients[$id]['videoPTs'] = [];
            $this->clients[$id]['audioPTs'] = [];
            $this->clients[$id]['primaryVideoPT'] = 0;
            $this->clients[$id]['primaryAudioPT'] = 0;
            $this->clients[$id]['remoteCandidate'] = null;
            $this->clients[$id]['localIceUfrag'] = '';
            $this->clients[$id]['localIcePwd'] = '';
            $this->clients[$id]['remoteIceUfrag'] = '';
            $this->clients[$id]['remoteIcePwd'] = '';
            $this->clients[$id]['remoteOfferSdp'] = '';
            $this->clients[$id]['remoteAnswerSdp'] = '';

            $this->clients[$id]['meta'] = [];
            $this->clients[$id]['dtlsState'] = 'closed';
            $this->clients[$id]['dtls'] = null;
            $this->clients[$id]['state'] = 'closed';
            $this->clients[$id]['sctpState'] = null;
            $this->clients[$id]['sctp'] = null;
            $this->clients[$id]['_sctpNextTsns'] = null;
        }
        if ($_srtpCleaned > 0) $this->_log_std("[removeClient  SRTP] id={$id}: destroyed srtpTx+srtpRx ({$_srtpCleaned} refs reset to null)\n");

        if (isset($this->clients[$id]['socket']) && is_resource($this->clients[$id]['socket'])) {
            @stream_socket_shutdown($this->clients[$id]['socket'], STREAM_SHUT_RDWR);
            @fclose($this->clients[$id]['socket']);
            $this->clients[$id]['socket'] = null;
        }

        $_udpRemoved = 0;
        if (!empty($this->udpAddrMap) && is_array($this->udpAddrMap)) {
            foreach ($this->udpAddrMap as $_addrStr => $_cidRef) {
                if ((int)$_cidRef === $id) {
                    unset($this->udpAddrMap[$_addrStr]);
                    $_udpRemoved++;
                }
            }
        }
        if ($_udpRemoved > 0) $this->_log_std("[removeClient 📡 UDP map] id={$id}: removed {$_udpRemoved} addr->clientId mappings\n");

        if (isset($this->onClose) && is_callable($this->onClose)) {
            try {
                $_cb2 = $this->onClose;
                $_cb2((int)$id, $this);
            } catch (\Throwable $e) {
                $this->_log_std("[removeClient  onClose EXCEPTION] id={$id}: " . $e->getMessage() . "\n");
            }
        }

        if (isset($this->clients[$id])) {
            unset($this->clients[$id]);
        }
        $this->_log_std("[removeClient  DONE] id={$id} 彻底移除完毕. 剩余 clients 总数=" . count($this->clients) . " (任何与此id相关的转发/GOP缓存/UDP映射全清)\n");
    }

    private function sendPublisherReceiverReports(float $now): void
    {
        if (($now - $this->lastPublisherRrAt) < 1.0) return;
        $this->lastPublisherRrAt = $now;

        foreach ($this->clients as $clientId => $client) {
            $meta = is_array($client['meta'] ?? null) ? $client['meta'] : [];
            if ((string)($meta['role'] ?? '') !== 'push'
                || (string)($client['dtlsState'] ?? '') !== 'connected'
                || empty($client['srtpTx'])
                || empty($client['remoteCandidate'])
                || empty($client['_publisherRtpRx'])
                || !is_array($client['_publisherRtpRx'])) continue;

            $sent = 0;
            $failed = 0;
            $obsRr = is_array($client['_obsRrAggregate'] ?? null) ? $client['_obsRrAggregate'] : ['lastReportAt'=>$now,'rrCount'=>0,'sent'=>0,'failed'=>0,'ssrcs'=>[]];

            foreach ($client['_publisherRtpRx'] as $sourceSsrc => $rx) {
                $extendedMax = (int)$rx['cycles'] + (int)$rx['maxSeq'];
                $expected = $extendedMax - (int)$rx['baseSeq'] + 1;
                $received = (int)$rx['received'];
                $lost = max(-0x800000, min(0x7FFFFF, $expected - $received));
                $expectedInterval = $expected - (int)$rx['expectedPrior'];
                $receivedInterval = $received - (int)$rx['receivedPrior'];
                $lostInterval = $expectedInterval - $receivedInterval;
                $fractionLost = ($expectedInterval > 0 && $lostInterval > 0)
                    ? min(255, intdiv($lostInterval << 8, $expectedInterval))
                    : 0;
                $client['_publisherRtpRx'][$sourceSsrc]['expectedPrior'] = $expected;
                $client['_publisherRtpRx'][$sourceSsrc]['receivedPrior'] = $received;

                $lost24 = $lost < 0 ? $lost + 0x1000000 : $lost;
                $sr = is_array($client['_publisherRtcpSr'][$sourceSsrc] ?? null) ? $client['_publisherRtcpSr'][$sourceSsrc] : [];
                $lsr = (int)($sr['lsr'] ?? 0);
                $dlsr = $lsr !== 0 ? min(0xFFFFFFFF, (int)max(0, floor(($now - (float)$sr['receivedAt']) * 65536))) : 0;
                $rr = pack('CCnNN', 0x81, 201, 7, 0x53465500, (int)$sourceSsrc)
                    . chr($fractionLost)
                    . chr(($lost24 >> 16) & 0xFF) . chr(($lost24 >> 8) & 0xFF) . chr($lost24 & 0xFF)
                    . pack('NNNN', $extendedMax & 0xFFFFFFFF, (int)round((float)$rx['jitter']) & 0xFFFFFFFF, $lsr & 0xFFFFFFFF, $dlsr & 0xFFFFFFFF);
                $rrOk = $this->protectAndSendRtcp((int)$clientId, $rr);
                if ($rrOk) $sent++; else $failed++;

                $kind = 'unknown';
                $incomingByKind = is_array($client['incomingSsrcByKind'] ?? null) ? $client['incomingSsrcByKind'] : [];
                if ((int)($incomingByKind['video'] ?? 0) === (int)$sourceSsrc) $kind = 'video';
                elseif ((int)($incomingByKind['audio'] ?? 0) === (int)$sourceSsrc) $kind = 'audio';
                else {
                    $incomingByPt = is_array($client['incomingSsrcByPt'] ?? null) ? $client['incomingSsrcByPt'] : [];
                    foreach ($incomingByPt as $rrPt => $rrSsrc) {
                        if ((int)$rrSsrc !== (int)$sourceSsrc) continue;
                        if (isset($client['videoPTs'][(int)$rrPt])) $kind = 'video';
                        elseif (isset($client['audioPTs'][(int)$rrPt])) $kind = 'audio';
                        break;
                    }
                }
                $obsRr['rrCount']++; $obsRr[$rrOk ? 'sent' : 'failed']++;
                $obsRr['ssrcs'][(string)$sourceSsrc] = ['ssrc'=>(int)$sourceSsrc,'kind'=>$kind,'extendedMax'=>$extendedMax,'expected'=>$expected,'received'=>$received,'lost'=>$lost,'fractionLost'=>$fractionLost,'jitter'=>(int)round((float)$rx['jitter']),'lsr'=>$lsr,'dlsr'=>$dlsr];

            }

            $log = is_array($client['_publisherRrLog'] ?? null) ? $client['_publisherRrLog'] : ['sent'=>0, 'failed'=>0, 'lastAt'=>$now];
            $log['sent'] += $sent;
            $log['failed'] += $failed;
            if (($now - (float)$log['lastAt']) >= 10.0) {
                $this->_log_std("[publisher RR summary] client={$clientId} streamId=" . (string)($meta['streamId'] ?? '') . " sent={$log['sent']} failed={$log['failed']} (max once/10s)\n");
                $log = ['sent'=>0, 'failed'=>0, 'lastAt'=>$now];
            }
            $client['_publisherRrLog'] = $log;

            if (($now - (float)$obsRr['lastReportAt']) >= 10.0) {
                $obsRr = ['lastReportAt'=>$now,'rrCount'=>0,'sent'=>0,'failed'=>0,'ssrcs'=>[]];
            }
            $client['_obsRrAggregate'] = $obsRr;

            if (isset($this->clients[$clientId])) $this->clients[$clientId] = $client;
        }
    }

    /** 每秒回收已建立 UDP 路径且连续 60 秒无入站活动的 HTTP WHEP 播放资源。 */
    private function cleanupStaleHttpPlayClients(float $now): void
    {
        if (($now - $this->lastHttpPlayCleanupAt) < 1.0) return;
        $this->lastHttpPlayCleanupAt = $now;

        $staleIds = [];
        foreach ($this->clients as $id => $client) {
            $meta = is_array($client['meta'] ?? null) ? $client['meta'] : [];
            if (($client['socket'] ?? null) !== null
                || (string)($meta['role'] ?? '') !== 'play'
                || empty($client['remoteCandidate'])) {
                continue;
            }
            $createdAt = (float)($client['createdAt'] ?? $now);
            $lastSeenAt = (float)($client['lastSeenAt'] ?? $createdAt);
            if (($now - $createdAt) >= 60.0 && ($now - $lastSeenAt) >= 60.0) {
                $staleIds[] = (int)$id;
            }
        }

        foreach ($staleIds as $id) {
            if (!isset($this->clients[$id])) continue;
            $lastSeenAt = (float)($this->clients[$id]['lastSeenAt'] ?? $now);
            $this->_log_std("[WHEP stale cleanup] clientId={$id} inactive=" . number_format($now - $lastSeenAt, 1) . "s\n");
            $this->removeClient($id);
        }
    }

    /**
     * 主服务器轮训
     * @return mixed
     */
    private function runEventLoop()
    {
        $_dbgObsReport = static function (string $hypothesisId, string $location, string $msg, array $data): void {
        };

        while (true) {

            $this->_dbgPerfLoopIteration(microtime(true));
            $readStreams = [$this->wsServer];

            if ($this->udpSocket && is_resource($this->udpSocket)) {
                $readStreams[] = $this->udpSocket;
            }
            if ($this->stunSocket && is_resource($this->stunSocket)) {
                $readStreams[] = $this->stunSocket;
            }

            foreach ($this->clients as $client) {
                if (isset($client['socket']) && $client['socket'] && is_resource($client['socket'])) {
                    $readStreams[] = $client['socket'];
                }
            }

            $writeStreams = null;
            $exceptStreams = null;
            $ready = @stream_select($readStreams, $writeStreams, $exceptStreams, 0, 1);
            if ($ready === false) {
                usleep(1);
                continue;
            }

            if ($ready > 0 && in_array($this->wsServer, $readStreams, true)) {
                $clientSocket = @stream_socket_accept($this->wsServer, 0);
                if ($clientSocket) {
                    stream_set_blocking($clientSocket, false);
                    $clientId = ++$this->clientCounter;
                    $this->clients[$clientId] = [
                        'socket' => $clientSocket,
                        'state' => 'http',
                        'buffer' => '',
                        'remoteSdp' => null,
                        'remoteCandidate' => null,
                        'dtlsState' => 'waiting',
                        '_dbgObsAcceptedAt' => microtime(true),
                        '_dbgObsReadCount' => 0,
                        '_dbgObsHeaderReported' => false,
                        '_dbgObsPostWaitReported' => false,
                    ];

                    $_dbgObsReport('E', 'src/WebRTCServer.php:http-accept', 'HTTP client accepted', ['clientId'=>$clientId,'acceptedAtMs'=>(int)($this->clients[$clientId]['_dbgObsAcceptedAt']*1000)]);

                    $_total = count($this->clients);
                    $this->_log_std("New client {$clientId} connected (当前总连接数={$_total})\n");
                    if (isset($this->onOpen) && is_callable($this->onOpen)) {
                        try {
                            $_cb = $this->onOpen;
                            $_cb("client#{$clientId}", $clientId, $this);
                        } catch (\Throwable $e) {
                            $this->_log_std("Client {$clientId} onOpen callback exception: " . $e->getMessage() . "\n");
                        }
                    }
                }
            }

            foreach ($this->clients as $id => $client) {
                if (!isset($client['socket'])) continue;

                if ($client['socket'] && in_array($client['socket'], $readStreams, true)) {
                    $chunk = @fread($client['socket'], 65536);
                    if ($chunk === '' || $chunk === false) {

                        $_dbgCloseBuffer = (string)($this->clients[$id]['buffer'] ?? '');
                        $_dbgCloseRequestLine = '';
                        if (preg_match('/^([^\r\n]+)/', $_dbgCloseBuffer, $_dbgCloseLineMatch)) $_dbgCloseRequestLine = $_dbgCloseLineMatch[1];
                        $_dbgObsReport('A,E', 'src/WebRTCServer.php:http-empty-read-close', 'HTTP fread empty before removeClient', ['clientId'=>(int)$id,'durationMs'=>(int)((microtime(true)-(float)($this->clients[$id]['_dbgObsAcceptedAt'] ?? microtime(true)))*1000),'state'=>(string)($this->clients[$id]['state'] ?? ''),'bufferLen'=>strlen($_dbgCloseBuffer),'hasHeaderTerminator'=>strpos($_dbgCloseBuffer, "\r\n\r\n") !== false,'requestLine'=>$_dbgCloseRequestLine]);

                        if (isset($this->onClose) && is_callable($this->onClose)) {
                            try {
                                $_cb = $this->onClose;
                                $_cb($id, $this);
                            } catch (\Throwable $e) { /* ignore */ }
                        }
                        $this->removeClient($id);
                        continue;
                    }

                    $this->clients[$id]['buffer'] .= $chunk;

                    $this->clients[$id]['_dbgObsReadCount'] = (int)($this->clients[$id]['_dbgObsReadCount'] ?? 0) + 1;
                    if ($this->clients[$id]['_dbgObsReadCount'] <= 3) {
                        $_dbgChunkPrefix = substr($chunk, 0, 256);
                        $_dbgPreviousBuffer = substr($this->clients[$id]['buffer'], 0, -strlen($chunk));
                        $_dbgRedactedPrefix = preg_match('/Authorization\s*:[^\r\n]*$/i', $_dbgPreviousBuffer)
                            ? '[REDACTED AUTHORIZATION CONTINUATION]'
                            : preg_replace('/(Authorization\s*:\s*)([^\r\n]*)/i', '$1[REDACTED]', $_dbgChunkPrefix);
                        $_dbgSafeAscii = preg_replace('/[^\x20-\x7E]/', '.', (string)$_dbgRedactedPrefix);
                        $_dbgObsReport('A', 'src/WebRTCServer.php:http-fread', 'HTTP fread chunk', ['clientId'=>(int)$id,'readNumber'=>$this->clients[$id]['_dbgObsReadCount'],'chunkLen'=>strlen($chunk),'bufferLen'=>strlen($this->clients[$id]['buffer']),'chunkPrefixHex'=>bin2hex((string)$_dbgRedactedPrefix),'chunkPrefixSafeAscii'=>$_dbgSafeAscii]);
                    }

                    if ($this->clients[$id]['state'] === 'http') {
                        if (strpos($this->clients[$id]['buffer'], "\r\n\r\n") === false) continue;

                        $parsed = $this->parseHttpHeaders($this->clients[$id]['buffer']);
                        $headers = $parsed['headers'];

                        if (empty($this->clients[$id]['_dbgObsHeaderReported'])) {
                            $this->clients[$id]['_dbgObsHeaderReported'] = true;
                            $_dbgHeaderEnd = strpos($this->clients[$id]['buffer'], "\r\n\r\n");
                            $_dbgRequestLine = (string)($parsed['requestLine'] ?? '');
                            $_dbgMethod = ''; $_dbgPath = ''; $_dbgHttpVersion = '';
                            if (preg_match('#^([A-Z]+)\s+(\S+)\s+HTTP/(\S+)$#', $_dbgRequestLine, $_dbgRequestMatch)) { $_dbgMethod=$_dbgRequestMatch[1]; $_dbgPath=$_dbgRequestMatch[2]; $_dbgHttpVersion=$_dbgRequestMatch[3]; }
                            $_dbgAuthorization = (string)($headers['authorization'] ?? '');
                            $_dbgAuthorizationScheme = '';
                            if ($_dbgAuthorization !== '' && preg_match('/^([^\s]+)/', $_dbgAuthorization, $_dbgAuthMatch)) $_dbgAuthorizationScheme = $_dbgAuthMatch[1];
                            $_dbgObsReport('B,D', 'src/WebRTCServer.php:http-complete-header', 'First complete HTTP header', ['clientId'=>(int)$id,'requestLine'=>$_dbgRequestLine,'method'=>$_dbgMethod,'path'=>$_dbgPath,'httpVersion'=>$_dbgHttpVersion,'contentLength'=>$headers['content-length'] ?? null,'transferEncoding'=>$headers['transfer-encoding'] ?? null,'expect'=>$headers['expect'] ?? null,'contentType'=>$headers['content-type'] ?? null,'userAgent'=>$headers['user-agent'] ?? null,'accept'=>$headers['accept'] ?? null,'origin'=>$headers['origin'] ?? null,'authorizationPresent'=>$_dbgAuthorization !== '','authorizationScheme'=>$_dbgAuthorizationScheme,'headerEnd'=>$_dbgHeaderEnd,'bodyBytesAvailable'=>strlen($this->clients[$id]['buffer'])-($_dbgHeaderEnd+4)]);
                        }

                        if (!empty($headers['upgrade']) && strtolower($headers['upgrade']) === 'websocket') {
                            $key = $headers['sec-websocket-key'] ?? '';
                            $accept = base64_encode(hash('sha1', $key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
                            $response = "HTTP/1.1 101 Switching Protocols\r\n";
                            $response .= "Upgrade: websocket\r\n";
                            $response .= "Connection: Upgrade\r\n";
                            $response .= "Sec-WebSocket-Accept: {$accept}\r\n";
                            $response .= "\r\n";
                            @fwrite($client['socket'], $response);
                            $this->clients[$id]['state'] = 'signaling';
                            $this->clients[$id]['buffer'] = '';
                            $this->_log_std("Client {$id} WebSocket signaling connected\n");
                            continue;
                        }

                        $requestLine = $parsed['requestLine'] ?? '';
                        $method = 'GET';
                        $urlPath = '/';
                        if (preg_match('#^([A-Z]+)\s+(\S+)\s+HTTP/#', $requestLine, $mm)) {
                            $method  = strtoupper($mm[1]);
                            $urlPath = $mm[2];
                        }
                        if (($qPos = strpos($urlPath, '?')) !== false) $urlPath = substr($urlPath, 0, $qPos);
                        if (($qPos = strpos($urlPath, '#')) !== false) $urlPath = substr($urlPath, 0, $qPos);
                        $urlPath = preg_replace('#/+#', '/', str_replace('\\', '/', $urlPath));
                        $requestHost = strtolower(trim((string)($headers['host'] ?? '')));
                        if (preg_match('/^\[([^]]+)\](?::\d+)?$/', $requestHost, $hostMatch)) {
                            $requestHost = $hostMatch[1];
                        } elseif (substr_count($requestHost, ':') === 1) {
                            $requestHost = explode(':', $requestHost, 2)[0];
                        }
                        $preferLoopback = in_array($requestHost, ['127.0.0.1', 'localhost', '::1'], true);

                        if (in_array($method, ['OPTIONS','HEAD','POST','DELETE','PATCH'], true)) $_dbgObsReport('A,C', 'src/WebRTCServer.php:http-route-entry', 'HTTP method entered routing', ['clientId'=>(int)$id,'method'=>$method,'path'=>$urlPath,'routeDecision'=>$method === 'POST' ? 'non-get-head-handler' : 'get-head-handler']);

                        $unsafe  = false;
                        foreach (explode('/', ltrim($urlPath, '/')) as $seg) {
                            if ($seg === '..' || $seg === "\0") { $unsafe = true; break; }
                        }

                        $content = '';
                        $contentType = 'text/html; charset=utf-8';
                        $status = '200 OK';
                        $hit = 'index';

                        if ($method !== 'GET' && $method !== 'HEAD') {
                            $contentLength = isset($headers['content-length']) ? (int)$headers['content-length'] : 0;
                            $hdrEnd = strpos($this->clients[$id]['buffer'], "\r\n\r\n");
                            $body = '';
                            if ($hdrEnd !== false) {
                                $body = substr($this->clients[$id]['buffer'], $hdrEnd + 4);
                            }
                            if ($method === 'POST' && $contentLength > strlen($body)) {

                                if (empty($this->clients[$id]['_dbgObsPostWaitReported'])) {
                                    $this->clients[$id]['_dbgObsPostWaitReported'] = true;
                                    $_dbgObsReport('B', 'src/WebRTCServer.php:post-body-wait', 'POST waiting for declared body', ['clientId'=>(int)$id,'method'=>$method,'path'=>$urlPath,'contentLength'=>$contentLength,'bodyLength'=>strlen($body),'bufferLen'=>strlen($this->clients[$id]['buffer'])]);
                                }

                                continue;
                            }

                            if ($method === 'DELETE' && preg_match('#^/whip/(\d+)$#', $urlPath, $md)) {
                                $resId = (int)$md[1];
                                $exists = isset($this->clients[$resId])
                                    && (($this->clients[$resId]['meta']['role'] ?? '') === 'push');

                                $_dbgObsReport('A', 'src/WebRTCServer.php:whip-delete', 'WHIP resource DELETE before publisher removal', ['httpClientId'=>(int)$id,'resourceClientId'=>$resId,'resourceExists'=>$exists,'resourceRole'=>(string)($this->clients[$resId]['meta']['role'] ?? ''),'streamId'=>(string)($this->clients[$resId]['meta']['streamId'] ?? ''),'resourceLastSeenMs'=>isset($this->clients[$resId]['lastSeenAt']) ? (int)((microtime(true)-(float)$this->clients[$resId]['lastSeenAt'])*1000) : null,'userAgent'=>(string)($headers['user-agent'] ?? ''),'requestLine'=>$requestLine]);
                                $this->_log_std("[DEBUG WHIP DELETE] httpClient={$id} resource={$resId} exists=" . ($exists ? 'yes' : 'no') . " streamId=" . (string)($this->clients[$resId]['meta']['streamId'] ?? '') . " userAgent=" . (string)($headers['user-agent'] ?? '') . "\n");

                                $response = $exists
                                    ? "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
                                    : "HTTP/1.1 404 Not Found\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                @fwrite($client['socket'], $response);
                                if ($exists) $this->removeClient($resId);
                                $this->removeClient($id);
                                continue;
                            }

                            if (preg_match('#^/whip/(\d+)/(?:candidate|ice)$#', $urlPath, $mc)) {
                                $resId = (int)$mc[1];
                                $candidate = trim($body);
                                if ($candidate !== '' && ($json = json_decode($candidate, true)) && is_array($json) && isset($json['candidate'])) {
                                    $candidate = (string)$json['candidate'];
                                }
                                if ($candidate !== '') {
                                    $this->_log_std("[WHIP CAND] res={$resId} candidate=" . substr($candidate, 0, 120) . "\n");
                                    if (isset($this->clients[$resId])) {
                                        if (!isset($this->clients[$resId]['remoteCandidate']) || !is_array($this->clients[$resId]['remoteCandidate'])) {
                                            $this->clients[$resId]['remoteCandidate'] = [];
                                        }
                                        $this->clients[$resId]['remoteCandidate']['candidate'] = $candidate;
                                        $this->clients[$resId]['remoteCandidate']['sdpMid'] = (string)($headers['sdp-mid'] ?? '0');
                                        $this->clients[$resId]['remoteCandidate']['sdpMLineIndex'] = (int)($headers['sdp-mline-index'] ?? 0);
                                    }
                                    $response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                                    @fwrite($client['socket'], $response);
                                    $this->removeClient($id);
                                    continue;
                                }
                            }

                            if (preg_match('#^/whep/(\d+)/(?:candidate|ice)$#', $urlPath, $mc2)) {
                                $resId = (int)$mc2[1];
                                $candidate = trim($body);
                                if ($candidate !== '' && ($json = json_decode($candidate, true)) && is_array($json) && isset($json['candidate'])) {
                                    $candidate = (string)$json['candidate'];
                                }
                                if ($candidate !== '') {
                                    $this->_log_std("[WHEP CAND] res={$resId} candidate=" . substr($candidate, 0, 120) . "\n");
                                    if (isset($this->clients[$resId])) {
                                        if (!isset($this->clients[$resId]['remoteCandidate']) || !is_array($this->clients[$resId]['remoteCandidate'])) {
                                            $this->clients[$resId]['remoteCandidate'] = [];
                                        }
                                        $this->clients[$resId]['remoteCandidate']['candidate'] = $candidate;
                                        $this->clients[$resId]['remoteCandidate']['sdpMid'] = (string)($headers['sdp-mid'] ?? '0');
                                        $this->clients[$resId]['remoteCandidate']['sdpMLineIndex'] = (int)($headers['sdp-mline-index'] ?? 0);
                                    }
                                    $response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                                    @fwrite($client['socket'], $response);
                                    $this->removeClient($id);
                                    continue;
                                }
                            }

                            if (preg_match('#^/whip(?:/([^/]+))?$#', $urlPath, $mm)) {
                                $streamId = isset($mm[1]) ? rawurldecode($mm[1]) : '';
                                $offer = (string)trim($body);
                                $this->_log_std("[WHIP OFFER] streamId={$streamId} offerLen=" . strlen($offer) . "\n");

                                if (strpos($offer, 'm=') === false) {
                                    $status = '400 Bad Request';
                                    $content = 'Invalid SDP Offer';
                                    $response = "HTTP/1.1 {$status}\r\n";
                                    $response .= "Content-Type: text/plain\r\n";
                                    $response .= "Access-Control-Allow-Origin: *\r\n";
                                    $response .= "Content-Length: " . strlen($content) . "\r\n";
                                    $response .= "Connection: close\r\n\r\n" . $content;
                                    @fwrite($client['socket'], $response);
                                    $this->removeClient($id);
                                    continue;
                                }

                                $ans = $this->handleHttpOffer('push', $streamId, $offer, false, $preferLoopback);
                                if (empty($ans['sdp'])) {
                                    $status = '400 Bad Request';
                                    $content = 'Failed to generate SDP Answer';
                                    $response = "HTTP/1.1 {$status}\r\n";
                                    $response .= "Access-Control-Allow-Origin: *\r\n";
                                    $response .= "Content-Type: text/plain\r\n";
                                    $response .= "Content-Length: " . strlen($content) . "\r\n";
                                    $response .= "Connection: close\r\n\r\n" . $content;
                                    @fwrite($client['socket'], $response);
                                    $this->removeClient($id);
                                    continue;
                                }

                                $status = '201 Created';
                                $content = $ans['sdp'];
                                $contentType = 'application/sdp';
                                $resourceUrl = "/whip/{$ans['clientId']}";
                                $response = "HTTP/1.1 {$status}\r\n";
                                $response .= "Content-Type: {$contentType}\r\n";
                                $response .= "Access-Control-Allow-Origin: *\r\n";
                                $response .= "Content-Length: " . strlen($content) . "\r\n";
                                $response .= "Location: {$resourceUrl}\r\n";
                                $response .= "ETag: \"" . md5($content) . "\"\r\n";
                                $response .= "Connection: close\r\n\r\n";
                                $response .= $content;
                                @fwrite($client['socket'], $response);
                                $this->_log_std("[WHIP] Created resource {$resourceUrl}\n");
                                $this->removeClient($id);
                                continue;
                            }

                            if (preg_match('#^/whep(?:/([^/]+))?$#', $urlPath, $mm2)) {
                                $streamId = isset($mm2[1]) ? rawurldecode($mm2[1]) : '';
                                $offer = (string)trim($body);
                                $this->_log_std("[WHEP OFFER] streamId={$streamId} offerLen=" . strlen($offer) . "\n");

                                $pubId = $this->getPublisherIdByStreamId($streamId);
                                if ($pubId === null) {
                                    $status = '404 Not Found';
                                    $content = 'Stream not available';
                                    $response = "HTTP/1.1 {$status}\r\n";
                                    $response .= "Content-Type: text/plain\r\n";
                                    $response .= "Access-Control-Allow-Origin: *\r\n";
                                    $response .= "Content-Length: " . strlen($content) . "\r\n";
                                    $response .= "Connection: close\r\n\r\n" . $content;
                                    @fwrite($client['socket'], $response);
                                    $this->removeClient($id);
                                    continue;
                                }

                                if (strpos($offer, 'm=') === false) {
                                    $status = '400 Bad Request';
                                    $content = 'Invalid SDP Offer';
                                    $response = "HTTP/1.1 {$status}\r\n";
                                    $response .= "Content-Type: text/plain\r\n";
                                    $response .= "Access-Control-Allow-Origin: *\r\n";
                                    $response .= "Content-Length: " . strlen($content) . "\r\n";
                                    $response .= "Connection: close\r\n\r\n" . $content;
                                    @fwrite($client['socket'], $response);
                                    $this->removeClient($id);
                                    continue;
                                }

                                $ans = $this->handleHttpOffer('play', $streamId, $offer, true, $preferLoopback);
                                if (empty($ans['sdp'])) {
                                    $status = '400 Bad Request';
                                    $content = 'Failed to generate SDP Answer';
                                    $response = "HTTP/1.1 {$status}\r\n";
                                    $response .= "Content-Type: text/plain\r\n";
                                    $response .= "Access-Control-Allow-Origin: *\r\n";
                                    $response .= "Content-Length: " . strlen($content) . "\r\n";
                                    $response .= "Connection: close\r\n\r\n" . $content;
                                    @fwrite($client['socket'], $response);
                                    $this->removeClient($id);
                                    continue;
                                }

                                $status = '201 Created';
                                $content = $ans['sdp'];
                                $contentType = 'application/sdp';
                                $resourceUrl = "/whep/{$ans['clientId']}";
                                $response = "HTTP/1.1 {$status}\r\n";
                                $response .= "Content-Type: {$contentType}\r\n";
                                $response .= "Content-Length: " . strlen($content) . "\r\n";
                                $response .= "Access-Control-Allow-Origin: *\r\n";
                                $response .= "Location: {$resourceUrl}\r\n";
                                $response .= "ETag: \"" . md5($content) . "\"\r\n";
                                $response .= "Connection: close\r\n\r\n";
                                $response .= $content;
                                @fwrite($client['socket'], $response);
                                $this->_log_std("[WHEP] Created resource {$resourceUrl}\n");
                                $this->removeClient($id);
                                continue;
                            }

                            if ($method === 'DELETE') {
                                if (preg_match('#^/whip/(\d+)$#', $urlPath, $md)) {
                                    $resId = (int)$md[1];
                                    if (isset($this->clients[$resId])) {
                                        $this->_log_std("[WHIP DELETE] resource={$resId}\n");
                                        $this->removeClient($resId);
                                        $response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                                        @fwrite($client['socket'], $response);
                                        $this->removeClient($id);
                                        continue;
                                    } else {
                                        $status = '404 Not Found';
                                        $content = '<h1>404 Not Found</h1>';
                                        $hit = 'whip:delete:notfound';
                                    }
                                }
                                if (preg_match('#^/whep/(\d+)$#', $urlPath, $md2)) {
                                    $resId = (int)$md2[1];
                                    if (isset($this->clients[$resId])) {
                                        $this->_log_std("[WHEP DELETE] resource={$resId}\n");
                                        $this->removeClient($resId);
                                        $response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                                        @fwrite($client['socket'], $response);
                                        $this->removeClient($id);
                                        continue;
                                    } else {
                                        $status = '404 Not Found';
                                        $content = '<h1>404 Not Found</h1>';
                                        $hit = 'whep:delete:notfound';
                                    }
                                }

                                $status = '404 Not Found';
                                $content = '<h1>404 Not Found</h1>';
                                $hit = '404:delete';
                            }

                            if ($method === 'POST') {
                                $status = '404 Not Found';
                                $content = '<h1>404 Not Found</h1>';
                                $hit = '404:post';
                            }

                            $response = "HTTP/1.1 {$status}\r\n";
                            $response .= "Content-Type: {$contentType}\r\n";
                            $response .= "Content-Length: " . strlen($content) . "\r\n";
                            $response .= "Access-Control-Allow-Origin: *\r\n";
                            $response .= "Connection: close\r\n\r\n";
                            if ($method !== 'HEAD') $response .= $content;
                            @fwrite($client['socket'], $response);
                            $this->_log_std("[HTTP {$method}] {$urlPath} -> {$status} ({$hit})\n");
                            $this->removeClient($id);
                            continue;
                        }

                        if ($unsafe) {
                            $status = '400 Bad Request';
                            $content = '<h1>400 Bad Request</h1>';
                            $hit = '400(unsafe)';
                        }
                        elseif ($urlPath === '/' || $urlPath === '' || $urlPath === '/index.html') {
                            $content = (string)@file_get_contents($this->docRoot . '/index.html');
                            $hit = 'index.html';
                        }
                        else {
                            $abs = $this->docRoot . '/' . ltrim($urlPath, '/');
                            $ext = strtolower(pathinfo($abs, PATHINFO_EXTENSION));
                            $mimeMap = [
                                'html' => 'text/html; charset=utf-8',
                                'htm'  => 'text/html; charset=utf-8',
                                'js'   => 'application/javascript; charset=utf-8',
                                'css'  => 'text/css; charset=utf-8',
                                'json' => 'application/json; charset=utf-8',
                                'png'  => 'image/png',
                                'jpg'  => 'image/jpeg',
                                'jpeg' => 'image/jpeg',
                                'gif'  => 'image/gif',
                                'svg'  => 'image/svg+xml',
                                'ico'  => 'image/x-icon',
                                'webp' => 'image/webp',
                                'wasm' => 'application/wasm',
                            ];
                            if (is_file($abs) && is_readable($abs) && isset($mimeMap[$ext])) {
                                $content = (string)@file_get_contents($abs);
                                $contentType = $mimeMap[$ext];
                                $hit = "static:{$urlPath}";
                            } else {
                                $status = '404 Not Found';
                                $content = '<h1>404 Not Found</h1><p>Try: <a href="/push.html">push.html</a> / <a href="/play.html">play.html</a></p>';
                                $hit = '404:' . $urlPath;
                            }
                        }

                        $response = "HTTP/1.1 {$status}\r\n";
                        $response .= "Content-Type: {$contentType}\r\n";
                        $response .= "Content-Length: " . strlen($content) . "\r\n";
                        $response .= "Access-Control-Allow-Origin: *\r\n";
                        $response .= "Cache-Control: no-store\r\n";
                        $response .= "Connection: close\r\n\r\n";
                        if ($method !== 'HEAD') $response .= $content;
                        @fwrite($client['socket'], $response);
                        $this->_log_std("[HTTP {$method}] {$urlPath} -> {$status} ({$hit}, len=" . strlen($content) . ")\n");
                        $this->removeClient($id);
                        continue;
                    }

                    if ($this->clients[$id]['state'] === 'signaling' || $this->clients[$id]['state'] === 'connecting' || $this->clients[$id]['state'] === 'connected') {
                        $buffer = $this->clients[$id]['buffer'];
                        while (true) {
                            $decoded = $this->decodeWebSocketPayload($buffer);
                            if (!$decoded['complete']) break;

                            $buffer = $decoded['remaining'];

                            if ($decoded['opcode'] === 'close') {
                                if (isset($this->onClose) && is_callable($this->onClose)) {
                                    try {
                                        $_cb = $this->onClose;
                                        $_cb($id, $this);
                                    } catch (\Throwable $e) { /* ignore */ }
                                }
                                $this->removeClient($id);
                                break;
                            }

                            if ($decoded['opcode'] === 'text') {
                                $this->handleSignaling($id, $decoded['payload']);
                            }
                        }
                        $this->clients[$id]['buffer'] = $buffer;
                    }
                }
            }

            if ($ready > 0 && in_array($this->udpSocket, $readStreams, true)) {
                $_udpDrainStartedAt = microtime(true);
                $_udpDrainPackets = $this->drainUdpBurst(64, 0.002);
                $_udpDrainElapsed = microtime(true) - $_udpDrainStartedAt;
                if (!isset($this->_dbgMediaPerf['udpDrain'])) {
                    $this->_dbgMediaPerf['udpDrain'] = ['calls'=>0,'totalPackets'=>0,'maxBatch'=>0,'hitPacketLimit'=>0,'hitTimeLimit'=>0];
                }
                $this->_dbgMediaPerf['udpDrain']['calls']++;
                $this->_dbgMediaPerf['udpDrain']['totalPackets'] += $_udpDrainPackets;
                if ($_udpDrainPackets > $this->_dbgMediaPerf['udpDrain']['maxBatch']) $this->_dbgMediaPerf['udpDrain']['maxBatch'] = $_udpDrainPackets;
                if ($_udpDrainPackets >= 64) $this->_dbgMediaPerf['udpDrain']['hitPacketLimit']++;
                if ($_udpDrainElapsed >= 0.002) $this->_dbgMediaPerf['udpDrain']['hitTimeLimit']++;

                static $_dbgUdpDrainLogAt = 0.0;
                if ($_udpDrainPackets >= 64 && (microtime(true) - $_dbgUdpDrainLogAt) >= 1.0) {
                    $_dbgUdpDrainLogAt = microtime(true);
                    $this->_log_std("[DEBUG UDP drain saturated] packets={$_udpDrainPackets}"
                        . " elapsedMs=" . number_format($_udpDrainElapsed * 1000, 3, '.', '')
                        . " packetLimitHits=" . $this->_dbgMediaPerf['udpDrain']['hitPacketLimit']
                        . " timeLimitHits=" . $this->_dbgMediaPerf['udpDrain']['hitTimeLimit'] . "\n");
                }

            }

            $this->handleSTUN();

            $now = microtime(true);
            $this->cleanupStaleHttpPlayClients($now);

            $this->sendPublisherReceiverReports($now);

            $this->flushSctpOutboundQueues();
        }
    }

    /**
     * 每轮事件循环末尾：ESTABLISHED 客户端的 SCTP 出站队列刷新（避免 SACK 超时重传）
     * 子实现若未定义该方法（老版本 trait 未提供），提供空实现占位防止 fatal。
     * @return void
     */
    private function flushSctpOutboundQueues()
    {

        if (method_exists($this, '_flushSctpQueuesImpl')) {
            $this->_flushSctpQueuesImpl();
        }
    }
}
