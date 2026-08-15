<?php

namespace Xiaosongshu\Webrtc\Core;

use Exception;

/**
 * @purpose SRTP协议
 * @author yanglong
 * 音视频媒体传输协议
 */
class SRTP
{
    const PROFILE_AES128_CM_SHA1_80 = 0x0001;
    const USE_OPENSSL_AES_ICM = true;

    const LABEL_RTP_ENC  = 0x00;
    const LABEL_RTP_AUTH = 0x01;
    const LABEL_RTP_SALT = 0x02;
    const LABEL_RTCP_ENC  = 0x03;
    const LABEL_RTCP_AUTH = 0x04;
    const LABEL_RTCP_SALT = 0x05;

    /** @var string 16B AES-128 session enc key (label 0x00) */
    public $rtpEncKey;
    /** @var string 20B HMAC-SHA1 session auth key (label 0x01) */
    public $rtpAuthKey;
    /** @var string 14B session salt (label 0x02) */
    public $rtpSalt;
    /** @var string 16B = rtpSalt || 0x0000，AES-ICM offset base (RFC 3711 §4.1.1 Eq.(6)) */
    public $offset16;
    /** @var array<string> rtpEncKey 对应的 11 个 AES-128 round key */
    private $rtpEncRoundKeys = [];
    /** @var string round key cache 对应的原始 session key */
    private $rtpEncRoundKeysKey = '';

    public $rtcpEncKey  = '';
    public $rtcpAuthKey = '';
    public $rtcpSalt    = '';
    public $rtcpOffset16 = '';

    /** @var int 最近一次操作的 SSRC (public for diagnostics) */
    public $ssrc = 0;
    /** @var int 截断后的 HMAC tag 长度 = 80/8 = 10 */
    public $tagLen = 10;

    /** @var int 成功 unprotect() 次数 */
    public $rxPackets = 0;
    /** @var int 成功 protect() 次数 */
    public $txPackets = 0;

    /** @var array<int, int> ssrc => 32-bit ROC */
    private $rocBySsrc     = [];
    /** @var array<int, int> ssrc => 最近 16-bit seq seen（-1 表示尚未初始化） */
    private $lastSeqBySsrc = [];

    /** @var int SRTCP 发送侧 31-bit index 计数器（RFC 3711 §3.4，单调递增） */
    private $srtcpIndex = 0;

    /**
     * 可选诊断 logger（callable）：若外部设置，则 unprotect / unprotectRtcp 失败路径会
     *   输出 hex dump，便于定位 SRTP/SRTCP 认证失败 / 解密失败的根因。
     *   签名：function(string $msg): void
     *   不设置时 SRTP 行为完全不变（默认 null = 静默）。
     * @var callable|null
     */
    public $logger = null;

    /**
     * 内部诊断：通过 logger 输出 hex dump（若 logger 已设置）。
     *   每个失败类型默认最多输出 3 次，避免刷屏。
     */
    private function _diagDump(string $tag, string $pkt, string $extra = ''): void
    {
        if ($this->logger === null) return;
        static $_counts = [];
        if (!isset($_counts[$tag])) $_counts[$tag] = 0;
        if ($_counts[$tag] >= 3) return;
        $_counts[$tag]++;
        $len = strlen($pkt);
        $dumpLen = min(64, $len);
        $hex = trim(chunk_split(bin2hex(substr($pkt, 0, $dumpLen)), 2, ' '));
        $msg = "[SRTP DIAG {$tag} #occurrence={$_counts[$tag]}] len={$len} dumped={$dumpLen} extra={$extra}\n  hex={$hex}\n";
        try {
            ($this->logger)($msg);
        } catch (\Throwable $e) {
            // ignore logger errors
        }
    }

    /**
     * @param string $masterKey  16 bytes (key from RFC 5764 EXTRACTOR-dtls_srtp)
     * @param string $masterSalt 14 bytes (salt from RFC 5764 EXTRACTOR-dtls_srtp)
     * @throws Exception
     */
    public function __construct($masterKey, $masterSalt)
    {
        if (!is_string($masterKey) || strlen($masterKey) !== 16) {
            throw new Exception("SRTP: masterKey MUST be 16 bytes AES-128 key");
        }
        if (!is_string($masterSalt) || strlen($masterSalt) !== 14) {
            throw new Exception("SRTP: masterSalt MUST be 14 bytes (112-bit RFC 3711 salt)");
        }
        $combined30 = $masterKey . $masterSalt;
        $this->deriveSessionKeys($combined30);
        $this->offset16     = $this->rtpSalt  . "\x00\x00";
        $this->rtcpOffset16 = ($this->rtcpSalt !== '') ? ($this->rtcpSalt . "\x00\x00") : '';
    }

    private function deriveSessionKeys($combined30)
    {
        $this->rtpEncKey  = $this->kdfGenerate($combined30, self::LABEL_RTP_ENC,  16);
        $this->rtpAuthKey = $this->kdfGenerate($combined30, self::LABEL_RTP_AUTH, 20);
        $this->rtpSalt    = $this->kdfGenerate($combined30, self::LABEL_RTP_SALT, 14);
        $this->rtcpEncKey  = $this->kdfGenerate($combined30, self::LABEL_RTCP_ENC,  16);
        $this->rtcpAuthKey = $this->kdfGenerate($combined30, self::LABEL_RTCP_AUTH, 20);
        $this->rtcpSalt    = $this->kdfGenerate($combined30, self::LABEL_RTCP_SALT, 14);
    }

    /**
     * RFC 3711 §4.3.1 / §4.3.3 AES-CM PRF:
     *   PRF_n(master_key, master_salt || label) = AES-128-ICM(counter, key=master_key)
     *
     *   IV/counter layout (与 libsrtp crypto/cipher/aes_icm_ossl.c 完全一致)：
     *     counter[16] = (master_salt || 0x0000)  XOR  ( 0x00*7 || label || 0x00*8 )
     *   即 label 放在 16 字节 counter 的第 8 字节 (index 7，最左字节为 index 0)。
     */
    private function kdfGenerate($combined30, $label, $length)
    {
        $masterKey  = substr($combined30, 0, 16);
        $masterSalt = substr($combined30, 16, 14);
        $offset = $masterSalt . "\x00\x00";
        $nonce  = str_repeat("\x00", 16);
        $nonce[7] = chr($label & 0xFF);
        $counter = $offset ^ $nonce;
        $zeroes  = str_repeat("\x00", $length);
        return self::_aesIcmXor($masterKey, $counter, $zeroes);
    }

    private function getRoc($ssrc)     { return $this->rocBySsrc[(int)$ssrc]     ?? 0; }
    private function getLastSeq($ssrc) { return $this->lastSeqBySsrc[(int)$ssrc] ?? -1; }
    private function setRoc($ssrc, $v)     { $this->rocBySsrc[(int)$ssrc]     = (int)$v; }
    private function setLastSeq($ssrc, $v) { $this->lastSeqBySsrc[(int)$ssrc] = (int)$v; }

    /**
     * 发送侧：按 SSRC 维护 32-bit ROC / 16-bit seq，返回 48-bit pkt_index。
     * RFC 3711 §3.3.1 发送侧规则：当前 SEQ 相对 last SEQ 跨半窗(0x8000)，视为 SEQ wrap → ROC+1。
     *
     * @param int $ssrc
     * @param int $seq16 传入 RTP 头的 16-bit sequence number
     * @return int 48-bit packet index = (ROC << 16) | SEQ
     */
    public function nextPacketIndexPerSsrc($ssrc, $seq16)
    {
        $ssrc  = (int)$ssrc;
        $seq16 = (int)$seq16 & 0xFFFF;
        $last  = $this->getLastSeq($ssrc);
        $roc   = $this->getRoc($ssrc);
        $packetRoc = $roc;
        $advanceState = $last < 0;
        if ($last >= 0) {
            if ($seq16 < $last && ($last - $seq16) > 0x8000) {
                $packetRoc = $roc + 1;
                $advanceState = true;
            } elseif ($seq16 > $last && ($seq16 - $last) > 0x8000) {
                $packetRoc = $roc > 0 ? $roc - 1 : 0;
            } elseif ($seq16 > $last) {
                $advanceState = true;
            }
        }
        if ($advanceState) {
            $this->setLastSeq($ssrc, $seq16);
            $this->setRoc($ssrc, $packetRoc);
        }
        return ($packetRoc << 16) | $seq16;
    }

    /**
     * RFC 3711 §3.1 / §3.1.1 构造 128-bit IV/counter
     *   (14B session_salt || 0x0000)  XOR  (0x0000 || SSRC_BE || ROC_BE || (SEQ_BE << 16))
     *
     * 与 libsrtp 行为完全一致：16 字节 IV = offset16 XOR ( 00_00 || SSRC_4 || ROC_4 || (SEQ<<16)_4 )
     */
    public function buildIcmCounter($ssrc, $packetIndex64)
    {
        $roc32 = ($packetIndex64 >> 16) & 0xFFFFFFFF;
        $seq16 = $packetIndex64 & 0xFFFF;
        $iv  = pack('N', 0);
        $iv .= pack('N', (int)$ssrc & 0xFFFFFFFF);
        $iv .= pack('N', $roc32);
        $iv .= pack('N', ($seq16 << 16) & 0xFFFFFFFF);
        return $this->offset16 ^ $iv;
    }

    /**
     * AES-128-CTR 输出与 data 等长 keystream，然后 XOR。加密 <-> 解密对称。
     */
    private function icmXor($counter, $data)
    {
        if (self::USE_OPENSSL_AES_ICM) {
            $native = self::_opensslAesIcmXor($this->rtpEncKey, $counter, $data);
            if ($native !== null) return $native;
        }

        if ($this->rtpEncRoundKeysKey !== $this->rtpEncKey) {
            $this->rtpEncRoundKeys = self::_aes128ExpandKey($this->rtpEncKey);
            $this->rtpEncRoundKeysKey = $this->rtpEncKey;
        }
        return self::_aesIcmXorWithRoundKeys($this->rtpEncRoundKeys, $counter, $data);
    }

    private function parseRtpHeader($rtp)
    {
        if (!is_string($rtp) || strlen($rtp) < 12) {
            throw new Exception("SRTP: RTP too short (<12)");
        }
        $b0 = ord($rtp[0]);
        $b1 = ord($rtp[1]);
        $v  = ($b0 >> 6) & 0x3;
        $p  = ($b0 >> 5) & 0x1;
        $x  = ($b0 >> 4) & 0x1;
        $cc = $b0 & 0xF;
        $m  = ($b1 >> 7) & 0x1;
        $pt = $b1 & 0x7F;
        $seq = unpack('n', substr($rtp, 2, 2))[1];
        $ts  = unpack('N', substr($rtp, 4, 4))[1];
        $ssrcVal = unpack('N', substr($rtp, 8, 4))[1];
        $hdrLen = 12 + 4 * $cc;
        if ($x) {
            if (strlen($rtp) < $hdrLen + 4) {
                throw new Exception("SRTP: RTP with X flag but too short for extension header");
            }
            $extLen = unpack('n', substr($rtp, $hdrLen + 2, 2))[1];
            $hdrLen += 4 + 4 * $extLen;
        }
        return [
            'v'=>$v,'p'=>$p,'x'=>$x,'cc'=>$cc,'m'=>$m,'pt'=>$pt,
            'seq'=>$seq,'ts'=>$ts,'ssrc'=>$ssrcVal,'hdrLen'=>$hdrLen,
        ];
    }

    /**
     * RFC 3711 §3.1 + §3.4，libsrtp srtp_protect() 等价流程：
     *   1. 解析 RTP → seq / ssrc / pt → pkt_index → ROC
     *   2. payload = AES-ICM(counter, payload) — RTP header 保持明文
     *   3. tag = TRUNC_80(HMAC-SHA1(auth_key, srtp_packet || ROC_BE_4B))
     *
     * @param string $rtp plain RTP packet
     * @return string SRTP packet = RTP header + encrypted payload + 10B HMAC tag
     * @throws Exception
     */
    public function protect($rtp)
    {
        if (!is_string($rtp)) {
            throw new Exception("SRTP::protect input must be string");
        }
        $h = $this->parseRtpHeader($rtp);
        $rtpLen = strlen($rtp);
        $encStart = $h['hdrLen'];
        $encLen = $rtpLen - $encStart;
        if ($encLen < 0) throw new Exception("SRTP::protect bad RTP hdrLen > total len");

        $this->ssrc = (int)$h['ssrc'];
        $packetIndex = $this->nextPacketIndexPerSsrc($h['ssrc'], $h['seq']);
        $roc32 = ($packetIndex >> 16) & 0xFFFFFFFF;

        $srtp = $rtp;
        if ($encLen > 0) {
            $counter = $this->buildIcmCounter($h['ssrc'], $packetIndex);
            $cipherPayload = $this->icmXor($counter, substr($rtp, $encStart, $encLen));
            $srtp = substr($rtp, 0, $encStart) . $cipherPayload;
        }

        $authInput = $srtp . pack('N', $roc32);
        $fullMac = hash_hmac('sha1', $authInput, $this->rtpAuthKey, true);
        $tag = substr($fullMac, 0, $this->tagLen);
        $this->txPackets++;
        return $srtp . $tag;
    }

    /**
     * RFC 3711 §3.2 + §3.3，libsrtp srtp_unprotect() 等价流程：
     *   1. 剥离 10B tag，解析 RTP 头
     *   2. 根据已知 last_seq/ROC 推算 est_roc（RFC 3711 Appendix A 伪代码）
     *   3. HMAC 校验（同样 input = srtp_body || ROC_4B）
     *   4. 校验通过 → AES-ICM 解密 payload → 更新 per-SSRC ROC/seq
     *
     * @param string $srtp incoming SRTP packet (with 10B tag)
     * @return string|false plain RTP on success, false on bad packet / replay / auth failure
     */
    public function unprotect($srtp)
    {
        if (!is_string($srtp)) return false;
        $minLen = 12 + $this->tagLen;
        if (strlen($srtp) < $minLen) {
            $this->_diagDump('UNPROTECT_TOO_SHORT', is_string($srtp) ? $srtp : '', 'minLen=' . $minLen . ' actual=' . strlen($srtp));
            return false;
        }

        $tag      = substr($srtp, -$this->tagLen);
        $srtpBody = substr($srtp, 0, strlen($srtp) - $this->tagLen);

        try {
            $h = $this->parseRtpHeader($srtpBody);
        } catch (Exception $e) {
            $this->_diagDump('UNPROTECT_HDR_PARSE_FAIL', $srtp, 'err=' . $e->getMessage());
            return false;
        }
        if ($h['v'] !== 2) {
            $this->_diagDump('UNPROTECT_BAD_VERSION', $srtp, 'v=' . $h['v']);
            return false;
        }

        $ssrc = (int)$h['ssrc'];
        $bodyLen = strlen($srtpBody);

        $last = $this->getLastSeq($ssrc);
        $localRoc = $this->getRoc($ssrc);
        if ($last < 0) {
            $rocGuess = $localRoc;
            $est = ($rocGuess << 16) | ((int)$h['seq'] & 0xFFFF);
        } else {
            $seq = (int)$h['seq'] & 0xFFFF;
            if ($seq < $last && ($last - $seq) > 0x8000) {
                $rocGuess = $localRoc + 1;
            } elseif ($seq > $last && ($seq - $last) > 0x8000) {
                $rocGuess = $localRoc > 0 ? $localRoc - 1 : 0;
            } else {
                $rocGuess = $localRoc;
            }
            $est = ($rocGuess << 16) | $seq;
        }
        $this->ssrc = $ssrc;
        $roc32 = ($est >> 16) & 0xFFFFFFFF;

        $authInput = $srtpBody . pack('N', $roc32);
        $fullMac = hash_hmac('sha1', $authInput, $this->rtpAuthKey, true);
        $calcTag = substr($fullMac, 0, $this->tagLen);
        if (!hash_equals($calcTag, $tag)) {
            $this->_diagDump('UNPROTECT_AUTH_FAIL', $srtp,
                'ssrc=' . $ssrc . ' seq=' . $h['seq'] . ' roc=' . $roc32 .
                ' lastSeq=' . $last . ' localRoc=' . $localRoc .
                ' calcTag=' . bin2hex($calcTag) . ' recvTag=' . bin2hex($tag));
            return false;
        }

        $encStart = $h['hdrLen'];
        $encLen = $bodyLen - $encStart;
        if ($encLen < 0) {
            $this->_diagDump('UNPROTECT_BAD_ENCLEN', $srtp, 'hdrLen=' . $encStart . ' bodyLen=' . $bodyLen);
            return false;
        }
        $rtp = $srtpBody;
        if ($encLen > 0) {
            $counter = $this->buildIcmCounter($ssrc, $est);
            $plainPayload = $this->icmXor($counter, substr($srtpBody, $encStart, $encLen));
            $rtp = substr($srtpBody, 0, $encStart) . $plainPayload;
        }

        $seq = (int)$h['seq'] & 0xFFFF;
        $localIndex = $last < 0 ? -1 : (($localRoc << 16) | $last);
        if ($last < 0 || $est > $localIndex) {
            $this->setRoc($ssrc, $roc32);
            $this->setLastSeq($ssrc, $seq);
        }
        $this->rxPackets++;
        return $rtp;
    }

    /**
     * RTCP -> SRTCP 简化实现：
     *   - 保留 RTCP header (前 8 字节) 明文
     *   - payload 用 rtcpEncKey AES-ICM 加密
     *   - 追加 E-bit + 31-bit 单调递增 SRTCP index
     *   - tag = TRUNC_80(HMAC-SHA1(rtcpAuthKey, srtcpBody || srtcpIndexWord))
     *
     * @param string $rtcp plain RTCP packet (必须 >= 8 字节，含 header+payload)
     * @return string|false SRTCP packet = RTCP(header plain + encrypted payload) + 10B HMAC tag
     */
    public function protectRtcp($rtcp)
    {
        if (!is_string($rtcp) || strlen($rtcp) < 8) return false;
        if ($this->rtcpEncKey === '' || $this->rtcpAuthKey === '' || $this->rtcpSalt === '') return false;

        $ssrcVal = unpack('N', substr($rtcp, 4, 4))[1];
        $hdrLen  = 8;
        $bodyLen = strlen($rtcp);
        $encStart = $hdrLen;
        $encLen   = $bodyLen - $encStart;
        $srtcp    = $rtcp;
        $packetSrtcpIndex = $this->srtcpIndex;
        $srtcpIndexWord = pack('N', 0x80000000 | $packetSrtcpIndex);
        $this->srtcpIndex = ($this->srtcpIndex + 1) & 0x7FFFFFFF;

        if ($encLen > 0) {
            $counter = $this->_buildSrtcpIcmCounter($ssrcVal, $packetSrtcpIndex);
            $cipher = $this->_rtcpIcmXor($counter, substr($rtcp, $encStart, $encLen));
            for ($i = 0; $i < $encLen; $i++) {
                $srtcp[$encStart + $i] = $cipher[$i];
            }
        }

        $authInput = $srtcp . $srtcpIndexWord;
        $fullMac = hash_hmac('sha1', $authInput, $this->rtcpAuthKey, true);
        $tag = substr($fullMac, 0, $this->tagLen);
        return $authInput . $tag;
    }

    /**
     * @param string $srtcp SRTCP packet (with 10B tag)
     * @return string|false plain RTCP on success, false on bad len/auth
     */
    public function unprotectRtcp($srtcp)
    {
        if (!is_string($srtcp)) return false;

        $minLen = 8 + 4 + $this->tagLen;
        if (strlen($srtcp) < $minLen) {
            $this->_diagDump('UNPROTECT_SRTCP_TOO_SHORT', is_string($srtcp) ? $srtcp : '', 'minLen=' . $minLen . ' actual=' . strlen($srtcp));
            return false;
        }
        if ($this->rtcpEncKey === '' || $this->rtcpAuthKey === '' || $this->rtcpSalt === '') {
            $this->_diagDump('UNPROTECT_SRTCP_NO_KEYS', $srtcp, 'rtcpKeys 未派生');
            return false;
        }

        $tag      = substr($srtcp, -$this->tagLen);
        $body     = substr($srtcp, 0, strlen($srtcp) - $this->tagLen);
        $bodyLen  = strlen($body);

        $srtcpIndexWord = substr($body, $bodyLen - 4, 4);
        $srtcpIndexRaw  = unpack('N', $srtcpIndexWord)[1];
        $isEncrypted    = ($srtcpIndexRaw >> 31) & 0x1;
        $srtcpIndex     = $srtcpIndexRaw & 0x7FFFFFFF;

        $rtcpBody = substr($body, 0, $bodyLen - 4);
        $ssrcVal  = unpack('N', substr($rtcpBody, 4, 4))[1];

        $authInput = $rtcpBody . $srtcpIndexWord;
        $fullMac   = hash_hmac('sha1', $authInput, $this->rtcpAuthKey, true);
        $calcTag   = substr($fullMac, 0, $this->tagLen);
        if (!hash_equals($calcTag, $tag)) {

            $_pt  = ord($rtcpBody[1]) & 0xFF;
            $_fmt = ord($rtcpBody[0]) & 0x1F;
            $this->_diagDump('UNPROTECT_SRTCP_AUTH_FAIL', $srtcp,
                'ssrc=' . $ssrcVal . ' pt=' . $_pt . ' fmt=' . $_fmt .
                ' srtcpIndex=' . $srtcpIndex . ' isEnc=' . $isEncrypted .
                ' calcTag=' . bin2hex($calcTag) . ' recvTag=' . bin2hex($tag));
            return false;
        }

        $hdrLen = 8;
        $encStart = $hdrLen;
        $encLen   = strlen($rtcpBody) - $hdrLen;
        $rtcp = $rtcpBody;
        if ($encLen > 0 && $isEncrypted) {
            $counter = $this->_buildSrtcpIcmCounter($ssrcVal, $srtcpIndex);
            $plain = $this->_rtcpIcmXor($counter, substr($rtcpBody, $encStart, $encLen));
            for ($i = 0; $i < $encLen; $i++) {
                $rtcp[$encStart + $i] = $plain[$i];
            }
        }
        return $rtcp;
    }

    /**
     * 判断 1 字节 payload type 是否为 RTCP (RFC 5761 §4, PT ∈ [192, 223])
     * （用于 RFC 5761 复用端口区分 RTP / RTCP）
     */
    public static function isRtcpPt(int $pt): bool
    {
        return $pt >= 192 && $pt <= 223;
    }

    /**
     * RFC 3711 §4.1.2 SRTCP IV 构造 (AES-128-CM, 128-bit counter):
     *   IV = (k_s << 16) XOR (SSRC << 64) XOR (srtcp_index << 16)
     *   16-byte mask = [00*4 || SSRC_4B || 00*2 || SRTCP_INDEX_4B || 00*2]
     *
     * 旧 bug：mask 只有 14 字节 (00*6 || SSRC_4 || INDEX_4)，PHP 字符串 XOR
     * 截断到较短者 → IV 变 14 字节 → openssl_encrypt 报 "IV passed is only
     * 14 bytes long, cipher expects 16" → SRTCP 加密实际失败（兜底手工 ECB
     * 也因 counter[14..15] 越界而错误）。
     */
    private function _buildSrtcpIcmCounter(int $ssrc, int $index): string
    {
        $base = $this->rtcpOffset16;
        if ($base === '') $base = str_repeat("\x00", 16);
        $mask = pack('N', 0)                         // bytes 0-3:   0x00000000
              . pack('N', $ssrc & 0xFFFFFFFF)       // bytes 4-7:   SSRC (<<64)
              . pack('n', 0)                         // bytes 8-9:   0x0000
              . pack('N', $index & 0x7FFFFFFF)        // bytes 10-13: SRTCP index (<<16)
              . pack('n', 0);                         // bytes 14-15: 0x0000
        return $base ^ $mask;
    }

    /** AES-ICM 异或流加密 (SRTCP 用 rtcpEncKey) */
    private function _rtcpIcmXor(string $counter, string $data): string
    {
        return self::_aesIcmXor($this->rtcpEncKey, $counter, $data);
    }

    private static function _opensslAesIcmXor(string $key16, string $counter16, string $data): ?string
    {
        static $verified = null;
        if ($data === '') return '';
        if ($verified === false
            || !function_exists('openssl_encrypt')
            || strlen($key16) !== 16
            || strlen($counter16) !== 16) {
            return null;
        }
        $result = @openssl_encrypt(
            $data,
            'aes-128-ctr',
            $key16,
            OPENSSL_RAW_DATA,
            $counter16
        );
        if (!is_string($result) || strlen($result) !== strlen($data)) {
            $verified = false;
            return null;
        }
        if ($verified === null) {
            $verified = hash_equals(self::_aesIcmXor($key16, $counter16, $data), $result);
            if (!$verified) return null;
        }
        return $result;
    }

    /**
     * AES S-box (FIPS-197 Figure 7 / libsrtp aes.c)
     */
    private static function _aesSbox(): array
    {
        static $sbox = null;
        if ($sbox !== null) return $sbox;
        $sbox = [
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
        ];
        return $sbox;
    }

    /**
     * AES-128 key expansion (FIPS-197 §5.2): 11 个 16B round key。
     * 返回 array<string> 长度 11，每个 16 bytes（column-major，与 AES state 一致）。
     */
    private static function _aes128ExpandKey(string $key16): array
    {
        $sbox = self::_aesSbox();
        $rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

        $w = [];
        for ($i = 0; $i < 4; $i++) {
            $w[$i] = [
                ord($key16[4*$i+0]),
                ord($key16[4*$i+1]),
                ord($key16[4*$i+2]),
                ord($key16[4*$i+3]),
            ];
        }
        for ($i = 4; $i < 44; $i++) {
            $t = $w[$i-1];
            if ($i % 4 === 0) {
                $t = [$t[1], $t[2], $t[3], $t[0]];
                for ($j = 0; $j < 4; $j++) $t[$j] = $sbox[$t[$j]];
                $t[0] ^= $rcon[$i/4 - 1];
            }
            $w[$i] = [
                $w[$i-4][0] ^ $t[0],
                $w[$i-4][1] ^ $t[1],
                $w[$i-4][2] ^ $t[2],
                $w[$i-4][3] ^ $t[3],
            ];
        }
        $roundKeys = [];
        for ($r = 0; $r < 11; $r++) {
            $rk = '';
            for ($c = 0; $c < 4; $c++) {
                $wi = $r * 4 + $c;
                $rk .= chr($w[$wi][0]) . chr($w[$wi][1]) . chr($w[$wi][2]) . chr($w[$wi][3]);
            }
            $roundKeys[$r] = $rk;
        }
        return $roundKeys;
    }

    /**
     * AES-128 单块加密 (FIPS-197 §5.1, Nr=10)。
     * state column-major: state[r + 4*c] = in[r + 4*c]。
     */
    private static function _aes128EncryptBlock(string $block16, array $roundKeys): string
    {
        $sbox = self::_aesSbox();
        $state = [];
        for ($i = 0; $i < 16; $i++) $state[$i] = ord($block16[$i]);

        $rk0 = $roundKeys[0];
        for ($i = 0; $i < 16; $i++) $state[$i] ^= ord($rk0[$i]);

        for ($round = 1; $round <= 10; $round++) {
            for ($i = 0; $i < 16; $i++) $state[$i] = $sbox[$state[$i]];

            $newState = array_fill(0, 16, 0);
            for ($r = 0; $r < 4; $r++) {
                for ($c = 0; $c < 4; $c++) {
                    $newState[$r + 4*$c] = $state[$r + 4*(($c + $r) & 3)];
                }
            }
            $state = $newState;

            if ($round < 10) {

                for ($c = 0; $c < 4; $c++) {
                    $i = 4 * $c;
                    $s0 = $state[$i]; $s1 = $state[$i+1];
                    $s2 = $state[$i+2]; $s3 = $state[$i+3];
                    $t0 = ($s0 & 0x80) ? ((($s0 << 1) ^ 0x1b) & 0xff) : (($s0 << 1) & 0xff);
                    $t1 = ($s1 & 0x80) ? ((($s1 << 1) ^ 0x1b) & 0xff) : (($s1 << 1) & 0xff);
                    $t2 = ($s2 & 0x80) ? ((($s2 << 1) ^ 0x1b) & 0xff) : (($s2 << 1) & 0xff);
                    $t3 = ($s3 & 0x80) ? ((($s3 << 1) ^ 0x1b) & 0xff) : (($s3 << 1) & 0xff);
                    $state[$i]   = $t0 ^ ($t1 ^ $s1) ^ $s2 ^ $s3;
                    $state[$i+1] = $s0 ^ $t1 ^ ($t2 ^ $s2) ^ $s3;
                    $state[$i+2] = $s0 ^ $s1 ^ $t2 ^ ($t3 ^ $s3);
                    $state[$i+3] = ($t0 ^ $s0) ^ $s1 ^ $s2 ^ $t3;
                }
            }

            $rk = $roundKeys[$round];
            for ($i = 0; $i < 16; $i++) $state[$i] ^= ord($rk[$i]);
        }

        $out = '';
        for ($i = 0; $i < 16; $i++) $out .= chr($state[$i]);
        return $out;
    }

    /**
     * AES-128-ICM (libsrtp AES Counter Mode, RFC 3711 §3.1)：
     *   counter 16 字节，每块 keystream 后仅 [14:15] 16-bit +1
     *   （byte15 溢出 0xff→0x00 时进位到 byte14，不再向 byte13 进位）。
     *   keystream = AES_encrypt(counter)，与 data XOR。
     *
     * @param string $key16     16-byte AES-128 key
     * @param string $counter16  16-byte initial counter (IV)
     * @param string $data       任意长数据
     * @return string            与 data 等长
     */
    private static function _aesIcmXor(string $key16, string $counter16, string $data): string
    {
        if ($data === '') return '';
        return self::_aesIcmXorWithRoundKeys(self::_aes128ExpandKey($key16), $counter16, $data);
    }

    /**
     * 使用已展开的 AES-128 round keys 执行 AES-ICM，counter 与异或语义同 _aesIcmXor()。
     */
    private static function _aesIcmXorWithRoundKeys(array $roundKeys, string $counter16, string $data): string
    {
        $len = strlen($data);
        if ($len === 0) return '';
        $out = '';
        $off = 0;
        $remaining = $len;
        $c = $counter16;
        while ($remaining > 0) {
            $ks = self::_aes128EncryptBlock($c, $roundKeys);
            $take = ($remaining < 16) ? $remaining : 16;
            for ($i = 0; $i < $take; $i++) {
                $out .= $data[$off + $i] ^ $ks[$i];
            }
            $off += $take;
            $remaining -= $take;
            if ($remaining > 0) {

                $b15 = ord($c[15]) + 1;
                if ($b15 > 0xff) {
                    $b15 = 0;
                    $c[14] = chr((ord($c[14]) + 1) & 0xff);
                }
                $c[15] = chr($b15 & 0xff);
            }
        }
        return $out;
    }
}
