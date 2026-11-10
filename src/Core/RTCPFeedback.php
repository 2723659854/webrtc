<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose 接收端 RTCP 带宽反馈：TWCC（RFC 8888）+ REMB
 * @note  仅用于「本端是接收方、对端是发送方」的场景（浏览器/OBS/ffmpeg 推流到服务端）。
 *        全部逻辑都是可关闭的：
 *          - transportWideCcIntervalSec = 0 → 不在 SDP 宣告 transport-cc，也不发反馈
 *          - rembIntervalSec = 0           → 不在 SDP 宣告 goog-remb，也不发 REMB
 *        并且只有对端 offer 里确实宣告了对应能力时才会启用（协商成功才启用）。
 */
trait RTCPFeedback
{
    /**
     * TWCC 反馈发送间隔（秒）。0 = 关闭（默认）。
     *
     * 默认关闭的原因（实测，见报告）：在 answer 里宣告 transport-cc 会让 Chrome 发送端
     * 从「按 REMB/RR 爬升」切换到「发送端 GoogCC」，而本机（127.0.0.1 回环 + PHP 单线程收包）
     * 的到达时间序列会被判为 delay overuse，目标码率被反复 ×0.8 一路压到 30kbps 地板。
     * 该现象与反馈内容无关：完全不发 TWCC、20ms 间隔、复合 RTCP、delta 全 0 都一样崩。
     * 因此默认只在 SDP 宣告 goog-remb（Chrome/OBS/ffmpeg 都支持），需要实验时把它设为 >0 即可一键开启。
     * @var float
     */
    public $transportWideCcIntervalSec = 0.0;

    /**
     * REMB 发送间隔（秒）。0 = 关闭。
     * 100ms 让只协商了 goog-remb 的客户端（Chrome/OBS/ffmpeg）在数秒内完成爬升；
     * 反馈流量约每 100ms 一个小包，可忽略。
     * @var float
     */
    public $rembIntervalSec = 0.1;

    /** 接收端带宽估计下限（bps），用于避免一开始报 0 让发送端停在极低码率 */
    public $rtcpFeedbackMinBitrateBps = 300000;

    /** 接收端带宽估计上限（bps） */
    public $rtcpFeedbackMaxBitrateBps = 20000000;

    /** 无损期间每次反馈允许的估算增长系数（1.08 = 每次反馈上涨 8%） */
    public $rtcpFeedbackGrowthFactor = 1.08;

    /** 一次 TWCC 反馈最多覆盖的状态数；超过则提前发一包，避免报文过大 */
    private $_twccMaxWindow = 4096;

    /** TWCC 到达记录最多保留多少条（防止长时间不发送导致内存膨胀） */
    private $_twccMaxPending = 8192;

    /**
     * 用 generateAnswerSDP() 的结果初始化该客户端的反馈状态。
     * 未协商成功（对端没宣告 / 配置关闭）时不创建状态，后续完全走旧逻辑。
     *
     * @param int   $clientId
     * @param array $answerInfo generateAnswerSDP() 的返回值
     * @return void
     */
    private function _twccInitFromAnswer(int $clientId, array $answerInfo): void
    {
        $twccEnabled = !empty($answerInfo['twccEnabled']) && (int)($answerInfo['twccExtId'] ?? 0) > 0;
        $rembEnabled = !empty($answerInfo['rembEnabled']);
        if (!$twccEnabled && !$rembEnabled) {
            return;
        }
        $now = microtime(true);
        $this->clients[$clientId]['_twcc'] = [
            'enabled'      => $twccEnabled,
            'extId'        => (int)($answerInfo['twccExtId'] ?? 0),
            'rembEnabled'  => $rembEnabled,
            'recv'         => [],
            'highestExt'   => null,
            'lastArrival'  => 0.0,
            'lastFeedbackAt' => $now,
            'lastRembAt'   => $now,
            'fbCount'      => 0,
            'estBps'       => 0.0,
            'obsBps'       => 0.0,
            'bytesAcc'     => 0,
            'accStart'     => 0.0,
            'pktCount'     => 0,
            'fbSent'       => 0,
            'lastLogAt'    => 0.0,
            'deltasTotal'  => 0,
            'chunksTotal'  => 0,
            'firstLogDone' => false,
            'seqTrack'     => [],
            'lossPct'      => 0.0,
        ];
        $this->_log_std("[TWCC] client={$clientId} feedback state init: twcc=" . ($twccEnabled ? "ON(extId={$answerInfo['twccExtId']})" : 'off')
            . " remb=" . ($rembEnabled ? "ON({$this->rembIntervalSec}s)" : 'off')
            . " twccInterval={$this->transportWideCcIntervalSec}s\n");
    }

    /**
     * 入站 RTP 到达记录（仅对被协商为 transport-cc 的推流端调用）。
     *
     * @param int    $clientId
     * @param string $rtp 明文 RTP
     * @param float  $now 到达时间（秒，microtime(true)）
     * @return void
     */
    private function _twccOnRtpArrival(int $clientId, string $rtp, float $now): void
    {
        if (!isset($this->clients[$clientId]['_twcc'])) {
            return;
        }
        $st = $this->clients[$clientId]['_twcc'];
        if (empty($st['enabled'])) {
            // 只协商了 REMB：累计字节 + 用 RTP 序号估算丢包（REMB-only 客户端没有 TWCC 状态）
            if (!empty($st['rembEnabled'])) {
                $st['bytesAcc'] = (int)$st['bytesAcc'] + strlen($rtp);
                if ((float)$st['accStart'] <= 0.0) $st['accStart'] = $now;
                $this->_twccTrackRtpSeq($st, $rtp);
                $this->clients[$clientId]['_twcc'] = $st;
                $this->_twccMaybeSendFeedback($clientId, $now);
            }
            return;
        }

        $seq = $this->_twccExtractSeq($rtp, (int)$st['extId']);
        if ($seq === null) {
            $this->clients[$clientId]['_twcc'] = $st;
            $this->_twccMaybeSendFeedback($clientId, $now);
            return;
        }

        $highest = $st['highestExt'];
        if ($highest === null) {
            $ext = $seq;
            $highest = $seq;
        } else {
            $delta = (($seq - ($highest & 0xFFFF) + 0x8000) & 0xFFFF) - 0x8000;
            $ext = $highest + $delta;
            if ($delta > 0) $highest = $ext;
        }

        // 太旧的包（乱序很久才到）直接丢弃，避免状态窗口无限大
        if ($highest - $ext > $this->_twccMaxPending) {
            $this->clients[$clientId]['_twcc'] = $st;
            $this->_twccMaybeSendFeedback($clientId, $now);
            return;
        }

        if (!isset($st['recv'][$ext])) {
            $st['recv'][$ext] = $now;
            $st['pktCount'] = (int)$st['pktCount'] + 1;
        }
        $st['highestExt'] = $highest;

        $st['bytesAcc'] = (int)$st['bytesAcc'] + strlen($rtp);
        if ((float)$st['accStart'] <= 0.0) $st['accStart'] = $now;

        // 待反馈包太多时立刻发一包，避免积压
        if (count($st['recv']) >= $this->_twccMaxWindow) {
            $this->clients[$clientId]['_twcc'] = $st;
            $this->_twccSendTransportCc($clientId, $now);
            return;
        }

        $this->clients[$clientId]['_twcc'] = $st;
        $this->_twccMaybeSendFeedback($clientId, $now);
    }

    /**
     * 到点则发送 TWCC / REMB
     * @param int   $clientId
     * @param float $now
     * @return void
     */
    private function _twccMaybeSendFeedback(int $clientId, float $now): void
    {
        if (!isset($this->clients[$clientId]['_twcc'])) return;
        $st = $this->clients[$clientId]['_twcc'];

        $twccInterval = (float)$this->transportWideCcIntervalSec;
        if (!empty($st['enabled']) && is_finite($twccInterval) && $twccInterval > 0
            && !empty($st['recv']) && ($now - (float)$st['lastFeedbackAt']) >= $twccInterval) {
            $this->clients[$clientId]['_twcc'] = $st;
            $this->_twccSendTransportCc($clientId, $now);
            $st = $this->clients[$clientId]['_twcc'];
        }

        $rembInterval = (float)$this->rembIntervalSec;
        if (!empty($st['rembEnabled']) && is_finite($rembInterval) && $rembInterval > 0
            && ($now - (float)$st['lastRembAt']) >= $rembInterval) {
            $this->clients[$clientId]['_twcc'] = $st;
            $this->_twccSendRemb($clientId, $now);
        }
    }

    /**
     * 组包并发送一个 RTCP transport-cc（RTPFB PT=205, FMT=15）
     * @param int   $clientId
     * @param float $now
     * @return void
     */
    private function _twccSendTransportCc(int $clientId, float $now): void
    {
        $st = $this->clients[$clientId]['_twcc'];
        $prevFbAt = (float)$st['lastFeedbackAt'];
        $recv = $st['recv'];
        if (empty($recv)) {
            $st['lastFeedbackAt'] = $now;
            $this->clients[$clientId]['_twcc'] = $st;
            return;
        }

        ksort($recv);
        $seqs = array_keys($recv);
        $base = (int)$seqs[0];
        $maxSeq = (int)$seqs[count($seqs) - 1];
        if (($maxSeq - $base) >= $this->_twccMaxWindow) {
            $base = $maxSeq - $this->_twccMaxWindow + 1;
        }

        // 参考时间 = 窗口内第一个已收到包的到达时间，按 64ms 量化；
        // 首个 recv delta 相对参考时间（而不是固定为 0），避免最多 64ms 的时间误差。
        $refArrival = null;
        for ($ext = $base; $ext <= $maxSeq; $ext++) {
            if (isset($recv[$ext])) { $refArrival = (float)$recv[$ext]; break; }
        }
        if ($refArrival === null) {
            $st['recv'] = [];
            $st['lastFeedbackAt'] = $now;
            $this->clients[$clientId]['_twcc'] = $st;
            return;
        }
        $refTicks = (int)floor($refArrival * 1000.0 / 64.0);
        $refTime = $refTicks & 0xFFFFFF;

        $statuses = [];
        $deltaBytes = '';
        $prevArrival = $refTicks * 0.064; // 参考时间对应的微秒基准（秒）
        $deltasMade = 0;
        $lostCount = 0;
        $zeroDeltas = 0;
        $maxTicks = 0;
        $largeDeltas = 0;
        for ($ext = $base; $ext <= $maxSeq; $ext++) {
            if (!isset($recv[$ext])) {
                $statuses[] = 0;
                $lostCount++;
                continue;
            }
            $arrival = (float)$recv[$ext];
            // recv delta 单位 = 250us（draft-holmer-01 §3.1.5）
            $ticks = (int)round(($arrival - $prevArrival) * 1000000.0 / 250.0);
            $prevArrival = $arrival;
            if ($ticks === 0) $zeroDeltas++;
            if ($ticks > $maxTicks) $maxTicks = $ticks;
            if ($ticks >= 0 && $ticks <= 0xFF) {
                // 小 delta：1 字节无符号，0..255 个 250us tick（0..63.75ms）
                $statuses[] = 1;
                $deltaBytes .= chr($ticks & 0xFF);
            } else {
                // 大/负 delta：2 字节有符号，250us tick，范围 ±8191.75ms
                if ($ticks < -32768) $ticks = -32768;
                if ($ticks > 32767) $ticks = 32767;
                $statuses[] = 2;
                $largeDeltas++;
                $deltaBytes .= pack('n', $ticks & 0xFFFF);
            }
            $deltasMade++;
        }

        $chunks = $this->_twccBuildRunLengthChunks($statuses);
        if ($chunks === '') {
            $st['recv'] = [];
            $st['lastFeedbackAt'] = $now;
            $this->clients[$clientId]['_twcc'] = $st;
            return;
        }

        $payload = pack('nn', $base & 0xFFFF, count($statuses))
            . substr(pack('N', $refTime), 1, 3)
            . chr(((int)$st['fbCount']) & 0xFF)
            . $chunks
            . $deltaBytes;

        // RTCP 报文长度必须是 4 字节倍数；用 0 填充（解析方按 Packet Status Count 停止）
        $pad = (4 - ((12 + strlen($payload)) % 4)) % 4;
        if ($pad > 0) $payload .= str_repeat("\x00", $pad);

        $senderSsrc = 0x53465500;
        $totalLen = 12 + strlen($payload);
        $pkt = pack('CCnNN', 0x8F, 205, intdiv($totalLen, 4) - 1, $senderSsrc, 0) . $payload;

        $ok = $this->protectAndSendRtcp($clientId, $pkt);

        $st = $this->clients[$clientId]['_twcc'];
        $st['recv'] = [];
        $st['lastFeedbackAt'] = $now;
        $st['fbCount'] = ((int)$st['fbCount'] + 1) & 0xFF;
        $st['fbSent'] = (int)$st['fbSent'] + 1;
        $st['deltasTotal'] = (int)$st['deltasTotal'] + $deltasMade;
        $st['chunksTotal'] = (int)$st['chunksTotal'] + intdiv(strlen($chunks), 2);
        $st['lastArrival'] = (float)$prevArrival;

        // 观测码率（仅用于日志/参考）与丢包率（状态 0 的占比）
        $total = count($statuses);
        $loss = $total > 0 ? $lostCount / $total : 0.0;
        $obs = 0.0;
        $elapsed = $now - (float)$st['accStart'];
        if ($elapsed > 0.02) {
            $obs = ((int)$st['bytesAcc'] * 8.0) / $elapsed;
            $st['bytesAcc'] = 0;
            $st['accStart'] = $now;
        }
        $this->_twccUpdateEstimate($st, $loss, $obs);
        $this->clients[$clientId]['_twcc'] = $st;

        if (!$st['firstLogDone'] || ($now - (float)$st['lastLogAt']) >= 2.0) {
            $st['firstLogDone'] = true;
            $st['lastLogAt'] = $now;
            $this->clients[$clientId]['_twcc'] = $st;
            $spanMs = ($prevArrival - $refArrival) * 1000.0;
            $winMs = ($now - $prevFbAt) * 1000.0;
            $this->_log_std(sprintf(
                "[TWCC OUT] client=%d ok=%s base=%d count=%d chunks=%d bytes=%d deltas=%d fb#%d loss=%.1f%% obs=%.0fbps est=%.0fbps ref=%d span=%.1fms win=%.1fms zero=%d large=%d maxtick=%d\n",
                $clientId, $ok ? 'yes' : 'NO', $base & 0xFFFF, $total,
                intdiv(strlen($chunks), 2), strlen($pkt), $deltasMade, (int)$st['fbCount'],
                (float)$st['lossPct'], (float)$st['obsBps'], (float)$st['estBps'],
                $refTime, $spanMs, $winMs, $zeroDeltas, $largeDeltas, $maxTicks
            ));
        }
    }

    /**
     * 组包并发送 REMB（PSFB PT=206, FMT=15）
     * @param int   $clientId
     * @param float $now
     * @return void
     */
    private function _twccSendRemb(int $clientId, float $now): void
    {
        $st = $this->clients[$clientId]['_twcc'];

        // TWCC 在跑时 estBps 已由 100ms 的 TWCC 窗口更新；仅 REMB 模式下在这里更新
        if (empty($st['enabled'])) {
            $loss = $this->_twccRtpLoss($st);
            $obs = 0.0;
            $elapsed = $now - (float)$st['accStart'];
            if ($elapsed > 0.02) {
                $obs = ((int)$st['bytesAcc'] * 8.0) / $elapsed;
                $st['bytesAcc'] = 0;
                $st['accStart'] = $now;
            }
            $this->_twccUpdateEstimate($st, $loss, $obs);
            foreach ($st['seqTrack'] as $ssrc => $track) {
                $st['seqTrack'][$ssrc]['recv'] = 0;
                $st['seqTrack'][$ssrc]['expect'] = 0;
            }
        }

        $bps = (float)$st['estBps'];
        $floor = (float)$this->rtcpFeedbackMinBitrateBps;
        $ceil = (float)$this->rtcpFeedbackMaxBitrateBps;
        if ($bps < $floor) $bps = $floor;
        if ($bps > $ceil) $bps = $ceil;

        $ssrcs = [];
        foreach ((array)($this->clients[$clientId]['incomingSsrcByPt'] ?? []) as $s) {
            $s = (int)$s;
            if ($s > 0) $ssrcs[$s] = true;
        }
        $ssrcs = array_slice(array_keys($ssrcs), 0, 16);
        if (empty($ssrcs)) {
            $st['lastRembAt'] = $now;
            $this->clients[$clientId]['_twcc'] = $st;
            return;
        }

        $exp = 0;
        $mant = (int)round($bps);
        while ($mant > 0x3FFFF) {
            $mant = ($mant + 1) >> 1;
            $exp++;
        }
        $mant &= 0x3FFFF;

        $body = 'REMB'
            . chr(count($ssrcs) & 0xFF)
            . chr((($exp & 0x3F) << 2) | (($mant >> 16) & 0x03))
            . chr(($mant >> 8) & 0xFF)
            . chr($mant & 0xFF);
        foreach ($ssrcs as $s) $body .= pack('N', $s);

        $senderSsrc = 0x53465500;
        $totalLen = 12 + strlen($body);
        $pkt = pack('CCnNN', 0x8F, 206, intdiv($totalLen, 4) - 1, $senderSsrc, 0) . $body;

        $ok = $this->protectAndSendRtcp($clientId, $pkt);

        $st['lastRembAt'] = $now;
        $st['estBps'] = $bps;
        $this->clients[$clientId]['_twcc'] = $st;

        static $_rembLastLog = [];
        if (!isset($_rembLastLog[$clientId]) || ($now - $_rembLastLog[$clientId]) >= 2.0) {
            $_rembLastLog[$clientId] = $now;
            $this->_log_std(sprintf(
                "[REMB OUT] client=%d ok=%s bps=%d exp=%d mant=%d ssrcs=[%s] hex=%s\n",
                $clientId, $ok ? 'yes' : 'NO', (int)$bps, $exp, $mant, implode(',', $ssrcs), bin2hex(substr($pkt, 0, 24))
            ));
        }
    }

    /**
     * 更新接收端带宽估计（无损增、丢包降、2%~10% 保持）。
     * 不使用「观测到达码率」作为估计上限：发送端被自身 pacer/应用限速时观测值会偏低，
     * 用它当上限会让估计锁死在低值（实测会导致目标码率一路下探）。
     *
     * @param array $st   客户端反馈状态（引用语义，调用方需要回写）
     * @param float $loss 本窗口丢包率 0..1
     * @param float $obs  本窗口观测到达码率 bps，仅用于日志
     * @return void
     */
    private function _twccUpdateEstimate(array &$st, float $loss, float $obs): void
    {
        $floor = (float)$this->rtcpFeedbackMinBitrateBps;
        $ceil = (float)$this->rtcpFeedbackMaxBitrateBps;
        $growth = (float)$this->rtcpFeedbackGrowthFactor;
        if (!is_finite($growth) || $growth < 1.0) $growth = 1.08;

        $prev = (float)$st['estBps'];
        if ($prev <= 0) $prev = $floor;

        if ($loss > 0.10) {
            $target = $prev * 0.85;
        } elseif ($loss > 0.02) {
            $target = $prev;
        } else {
            $target = $prev * $growth;
        }
        if ($target < $floor) $target = $floor;
        if ($target > $ceil) $target = $ceil;

        $st['estBps'] = $target;
        $st['obsBps'] = $obs;
        $st['lossPct'] = $loss * 100.0;
    }

    /**
     * REMB-only 模式下用 RTP 序号统计每个 SSRC 的收包/期望包数。
     * TWCC 模式下不走这里（丢包率由 TWCC 状态位直接给出）。
     *
     * @param array  $st
     * @param string $rtp
     * @return void
     */
    private function _twccTrackRtpSeq(array &$st, string $rtp): void
    {
        if (strlen($rtp) < 12) return;
        $ssrc = unpack('N', substr($rtp, 8, 4))[1];
        $seq = unpack('n', substr($rtp, 2, 2))[1];
        if (!isset($st['seqTrack'][$ssrc])) {
            $st['seqTrack'][$ssrc] = ['hi' => $seq, 'recv' => 1, 'expect' => 1];
            return;
        }
        $t = $st['seqTrack'][$ssrc];
        $delta = (($seq - ((int)$t['hi'] & 0xFFFF) + 0x8000) & 0xFFFF) - 0x8000;
        if ($delta > 0) {
            $t['hi'] = (int)$t['hi'] + $delta;
            $t['expect'] = (int)$t['expect'] + $delta;
            $t['recv'] = (int)$t['recv'] + 1;
        } elseif ($delta === 0) {
            $t['recv'] = (int)$t['recv'] + 1;
        }
        $st['seqTrack'][$ssrc] = $t;
    }

    /**
     * 取窗口内「期望包数最多」的 SSRC 的丢包率作为整体丢包估计（RTX 等旁路流自然被忽略）。
     *
     * @param array $st
     * @return float 0..1
     */
    private function _twccRtpLoss(array $st): float
    {
        $best = 0;
        $loss = 0.0;
        foreach ((array)($st['seqTrack'] ?? []) as $t) {
            $expect = (int)($t['expect'] ?? 0);
            $recv = (int)($t['recv'] ?? 0);
            if ($expect < 5 || $expect <= $best) continue;
            $best = $expect;
            $loss = max(0.0, 1.0 - $recv / $expect);
        }
        return $loss;
    }

    /**
     * 把 packet status 数组编码成 draft-holmer-rmcat-transport-wide-cc-extensions-01 §3.1.3 的
     * Run Length Chunk：|T=0 (1bit)|S (2bit)|Run Length (13bit)|
     * 注意 S 在高位（bit14-13），run length 是「原始个数」，不是个数减一。
     *
     * @param array<int,int> $statuses 0=未收到 1=收到(1字节delta) 2=收到(2字节delta)
     * @return string
     */
    private function _twccBuildRunLengthChunks(array $statuses): string
    {
        $out = '';
        $n = count($statuses);
        $i = 0;
        while ($i < $n) {
            $sym = (int)$statuses[$i];
            $run = 1;
            $maxRun = min(8191, $n - $i);
            while ($run < $maxRun && (int)$statuses[$i + $run] === $sym) {
                $run++;
            }
            $chunk = (($sym & 0x03) << 13) | ($run & 0x1FFF);
            $out .= pack('n', $chunk);
            $i += $run;
        }
        return $out;
    }

    /**
     * 从 RTP 头扩展中取出 transport-wide sequence number
     * @param string $rtp
     * @param int    $extId
     * @return int|null
     */
    private function _twccExtractSeq(string $rtp, int $extId): ?int
    {
        $len = strlen($rtp);
        if ($len < 16 || $extId <= 0) return null;
        $b0 = ord($rtp[0]);
        if (($b0 & 0x10) === 0) return null;
        $off = 12 + 4 * ($b0 & 0x0F);
        if ($off + 4 > $len) return null;
        $profile = unpack('n', substr($rtp, $off, 2))[1];
        $words = unpack('n', substr($rtp, $off + 2, 2))[1];
        $p = $off + 4;
        $end = min($len, $p + 4 * $words);

        if ($profile === 0xBEDE) {
            while ($p < $end) {
                $hdr = ord($rtp[$p++]);
                if ($hdr === 0) continue;
                $id = ($hdr >> 4) & 0x0F;
                if ($id === 15) break;
                $dl = ($hdr & 0x0F) + 1;
                if ($p + $dl > $end) break;
                if ($id === $extId) {
                    if ($dl === 1) return ord($rtp[$p]);
                    return (ord($rtp[$p]) << 8) | ord($rtp[$p + 1]);
                }
                $p += $dl;
            }
            return null;
        }

        if ($profile === 0x1000 || $profile === 0x1001) {
            while ($p + 2 <= $end) {
                $id = ord($rtp[$p]);
                $dl = ord($rtp[$p + 1]);
                $p += 2;
                if ($p + $dl > $end) break;
                if ($id === $extId) {
                    if ($dl === 0) return null;
                    if ($dl === 1) return ord($rtp[$p]);
                    return (ord($rtp[$p]) << 8) | ord($rtp[$p + 1]);
                }
                $p += $dl;
            }
        }
        return null;
    }
}
