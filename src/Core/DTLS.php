<?php

namespace Xiaosongshu\Webrtc\Core;

/**
 * @purpose DTLS协议
 * @author yanglong
 */
trait DTLS
{

    /**
     * 生成证书
     * @return void
     */
    private function generateCertificate()
    {
        /** 构建证书目录 */
        $certDir = __DIR__ . '/certs';
        if (!file_exists($certDir)) mkdir($certDir, 0755, true);

        /** 设置证书路径 */
        $this->certPath = $certDir . '/server.crt';
        $this->keyPath = $certDir . '/server.key';
        $configPath = $certDir . '/openssl.cnf';

        /** 初始化配置内容*/
        if (!file_exists($configPath)) {
            $configLines = [
                '[req]',
                'default_bits = 2048',
                'prompt = no',
                'default_md = sha256',
                'distinguished_name = dn',
                'x509_extensions = v3_req',
                '',
                '[dn]',
                'CN = localhost',
                '',
                '[v3_req]',
                'subjectKeyIdentifier = hash',
                'basicConstraints = CA:FALSE',
                'keyUsage = critical, digitalSignature, keyEncipherment',
                'extendedKeyUsage = serverAuth',
                'subjectAltName = DNS:localhost, IP:127.0.0.1'
            ];
            file_put_contents($configPath, implode("\n", $configLines));
        }

        /** 生成证书 */
        if (!file_exists($this->certPath) || !file_exists($this->keyPath) || filesize($this->keyPath) == 0) {
            $config = [
                'config' => $configPath,
                'private_key_type' => defined('OPENSSL_KEYTYPE_RSA') ? OPENSSL_KEYTYPE_RSA : 1,
                'private_key_bits' => 2048
            ];

            /** 生成密钥 */
            $key = openssl_pkey_new($config);
            if (!$key) {
                $this->_log_std("Failed to generate SSL key\n");
                return;
            }

            /** 导出密钥 */
            $pemKey = '';
            $exportResult = openssl_pkey_export($key, $pemKey, null, $config);
            if ($exportResult) {
                file_put_contents($this->keyPath, $pemKey);
                $this->_log_std("Private key exported successfully, length: " . strlen($pemKey) . "\n");
            } else {
                $this->_log_std("Failed to export private key, openssl error: " . openssl_error_string() . "\n");
                return;
            }

            $dn = ['CN' => 'localhost'];
            $csr = openssl_csr_new($dn, $key, $config);
            $cert = openssl_csr_sign($csr, null, $key, 365, $config);

            openssl_x509_export($cert, $certPem);
            file_put_contents($this->certPath, $certPem);

            $this->_log_std("Certificate generated: {$this->certPath}\n");
        }

        if (file_exists($this->certPath) && file_exists($this->keyPath)) {
            $this->_log_std("Using certificate: {$this->certPath}\n");
        }
    }

    /**
     * 创建dtls上下文
     * @return void
     */
    private function createDTLSContext()
    {
        $this->dtlsContext = stream_context_create([
            'ssl' => [
                /** 设置证书地址 */
                'local_cert' => $this->certPath,
                'local_pk' => $this->keyPath,
                /** 允许自签名 */
                'allow_self_signed' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'disable_compression' => true,
            ]
        ]);
    }

    /**
     * dtls解析
     * @param string $data
     * @return array|null
     */
    private function parseDTLSRecord(string $data)
    {
        if (strlen($data) < 13) return null;

        $contentType = ord($data[0]);
        $version = substr($data, 1, 2);
        $epoch = unpack('n', substr($data, 3, 2))[1];
        $seqHigh = unpack('n', substr($data, 5, 2))[1];
        $seqLow = unpack('N', substr($data, 7, 4))[1];
        $seq = ($seqHigh << 32) | $seqLow;
        $length = unpack('n', substr($data, 11, 2))[1];
        $fragment = substr($data, 13, $length);

        return [
            'contentType' => $contentType,
            'version' => $version,
            'epoch' => $epoch,
            'seq' => $seq,
            'length' => $length,
            'fragment' => $fragment
        ];
    }

    /**
     * DTLS 协议拆包与解密引擎
     * @param $clientId
     * @param $data
     * @return void
     */
    private function handleDTLS($clientId, $data)
    {
        $offset = 0;
        while ($offset < strlen($data)) {
            $remaining = strlen($data) - $offset;
            if ($remaining < 13) break;

            /** 解析dtls */
            $record = $this->parseDTLSRecord(substr($data, $offset));
            if (!$record) break;

            $recordTotalLen = 13 + $record['length'];
            $this->_log_std("Client {$clientId} DTLS Record: type={$record['contentType']}, version=" . bin2hex($record['version']) . ", epoch={$record['epoch']}, seq={$record['seq']}, len={$record['length']}, offset={$offset}\n");

            /** 是否加密 握手阶段是明文，数据传输阶段是密文 */
            $isEncrypted = ($record['epoch'] >= 1) && isset($this->clients[$clientId]['encryption']);


            //todo 如果浏览器将一个完整的握手消息拆成 2 个独立的 UDP 包发来，当前逻辑（每次接收仅处理当前包的数据）无法跨包重组碎片，会导致握手失败
            if ($record['contentType'] === 22) {/** Handshake（握手）*/
                if ($isEncrypted) {
                    $plaintext = $this->decryptDTLSRecord(
                        $clientId,
                        $record['fragment'],
                        $record['epoch'],
                        $record['seq'],
                        0x16,
                        $record['version']
                    );
                    if ($plaintext === false || $plaintext === null) {
                        $this->_log_std("Client {$clientId} Failed to decrypt handshake record (epoch={$record['epoch']}, seq={$record['seq']})\n");
                        /** 握手失败，导出数据 */

                        if ($this->isDev){
                            if ($record['epoch'] == 1 && $record['seq'] == 0 && !defined('DECRYPT_DUMP_DONE')) {
                                define('DECRYPT_DUMP_DONE', true);
                                /** 获取客户端 */
                                $c = $this->clients[$clientId];
                                $ecDetails = null;
                                if (isset($c['ecdhKey']) && is_object($c['ecdhKey'])) {
                                    $d = openssl_pkey_get_details($c['ecdhKey']);
                                    $ecDetails = $d['ec'] ?? null;
                                }
                                $dump = [
                                    'clientId' => $clientId,
                                    'fragment_hex' => bin2hex($record['fragment']),
                                    'epoch' => $record['epoch'],
                                    'seq' => $record['seq'],
                                    'record_version_hex' => bin2hex($record['version']),
                                    'clientRandom_hex' => bin2hex($c['clientRandom'] ?? ''),
                                    'serverRandom_hex' => bin2hex($c['serverRandom'] ?? ''),
                                    'preMasterSecret_hex' => bin2hex($c['preMasterSecret'] ?? ''),
                                    'preMasterSecretAlt_hex' => bin2hex($c['preMasterSecretAlt'] ?? ''),
                                    'handshakeHash_hex' => bin2hex($c['handshakeHash'] ?? ''),
                                    'sessionHashSnapshot_hex' => bin2hex($c['sessionHashSnapshot'] ?? ''),
                                    'cipherSuite_hex' => bin2hex($c['cipherSuite'] ?? ''),
                                    'masterSecretLegacy_hex' => bin2hex($c['masterSecretLegacy'] ?? ''),
                                    'masterSecretExtended_hex' => bin2hex($c['masterSecretExtended'] ?? ''),
                                    'masterHashAlgo' => $c['masterHashAlgo'] ?? 'sha256',
                                    'serverEcdheEc' => $ecDetails ? [
                                        'x' => bin2hex($ecDetails['x'] ?? ''),
                                        'y' => bin2hex($ecDetails['y'] ?? ''),
                                        'd' => isset($ecDetails['d']) ? bin2hex($ecDetails['d']) : '',
                                    ] : null,
                                    'clientEcReceivedPoint' => bin2hex($c['clientEcPubPoint'] ?? ''),
                                ];
                                $out = "<?php\n\$dump = " . var_export($dump, true) . ";\n";
                                @file_put_contents(__DIR__ . '/tmp_decrypt_dump.php', $out);
                                $this->_log_std("Client {$clientId} !!! DECRYPT DUMP WRITTEN to tmp_decrypt_dump.php (size=" . strlen($out) . ")\n");
                            }
                        }
                    } else {
                        $this->_log_std("Client {$clientId} Decrypted handshake (len=" . strlen($plaintext) . ")\n");
                        /** 处理Dtls握手 */
                        $this->handleDTLSHandshake($clientId, $plaintext);
                    }
                } else {
                    /** 明文握手 */
                    $this->handleDTLSHandshake($clientId, $record['fragment']);
                }
            } elseif ($record['contentType'] === 21) { /** Alert（告警） */
                $alertLevel = ord($record['fragment'][0]);
                $alertDesc = ord($record['fragment'][1]);
                $alertNames = [0 => 'close_notify', 10 => 'unexpected_message', 20 => 'bad_record_mac', 21 => 'decryption_failed_reserved', 22 => 'record_overflow', 30 => 'decompression_failure', 40 => 'handshake_failure', 41 => 'no_certificate_reserved', 42 => 'bad_certificate', 43 => 'unsupported_certificate', 44 => 'certificate_revoked', 45 => 'certificate_expired', 46 => 'certificate_unknown', 47 => 'illegal_parameter', 48 => 'unknown_ca', 49 => 'access_denied', 50 => 'decode_error', 51 => 'decrypt_error', 60 => 'export_restriction_reserved', 70 => 'protocol_version', 71 => 'insufficient_security', 80 => 'internal_error', 86 => 'user_canceled', 90 => 'no_renegotiation'];
                $descName = isset($alertNames[$alertDesc]) ? $alertNames[$alertDesc] : "unknown($alertDesc)";
                $this->_log_std("Client {$clientId} DTLS ALERT: level={$alertLevel}, desc={$alertDesc} ({$descName})\n");
            } elseif ($record['contentType'] === 20) { /** ChangeCipherSpec（变更密码规格） */
                $this->_log_std("Client {$clientId} DTLS ChangeCipherSpec\n");
                /** 更换密码 */
                $this->handleChangeCipherSpec($clientId);
            } elseif ($record['contentType'] === 23) { /** Application Data（应用数据） */
                if ($isEncrypted) {
                    $decrypted = $this->decryptDTLSRecord(
                        $clientId,
                        $record['fragment'],
                        $record['epoch'],
                        $record['seq'],
                        0x17,
                        $record['version']
                    );
                    if ($decrypted) {
                        $this->_log_std("Client {$clientId} DTLS Application Data (decrypted, len=" . strlen($decrypted) . ")\n");
                        /** 处理sctp数据 */
                        $this->handleSCTP($clientId, $decrypted);
                    }
                }
            }

            $offset += $recordTotalLen;
        }
    }


    /**
     * DTLS更换密码
     * @param $clientId
     * @return void
     * @throws \Random\RandomException
     */
    private function handleChangeCipherSpec($clientId)
    {
        $clientRandom = $this->clients[$clientId]['clientRandom'] ?? '';
        $serverRandom = $this->clients[$clientId]['serverRandom'] ?? '';

        $this->clients[$clientId]['clientCCSSent'] = true;
        if (isset($this->clients[$clientId]['encryption'])) {
            $this->_log_std("Client {$clientId} Client CCS re-received (duplicate), ignore\n");
            return;
        }

        $cipherSuite = $this->clients[$clientId]['cipherSuite'];
        $cs = bin2hex($cipherSuite);
        $keyLen = ($cs === 'c02b') ? 32 : 16;
        $hashAlgo = ($cs === 'c02b') ? 'sha384' : 'sha256';
        $ivLen = 4;
        $cipherAlgo = ($cs === 'c02b') ? 'aes-256-gcm' : 'aes-128-gcm';


        $pms = $this->clients[$clientId]['preMasterSecret'] ?? '';
        $pmsAlt = $this->clients[$clientId]['preMasterSecretAlt'] ?? null;
        $snapTls4 = $this->clients[$clientId]['sessionHashSnapshotTLS4'] ?? ($this->clients[$clientId]['sessionHashSnapshot'] ?? '');
        $snapDtls12 = $this->clients[$clientId]['sessionHashSnapshotDTLS12'] ?? ($this->clients[$clientId]['sessionHashSnapshot'] ?? '');
        $msCandidates = [];
        $allPms = ['pms' => $pms];
        if (is_string($pmsAlt) && strlen($pmsAlt) === 32) {
            $allPms['pmsAlt'] = $pmsAlt;
        }
        foreach ($allPms as $pmsName => $onePms) {
            if (strlen($onePms) === 32) {

                $msCandidates[$pmsName . '_ext_snapTLS4'] = $this->tls12PRF($onePms, "extended master secret", hash($hashAlgo, $snapTls4, true), 48, $hashAlgo);
                $msCandidates[$pmsName . '_ext_snapDTLS12'] = $this->tls12PRF($onePms, "extended master secret", hash($hashAlgo, $snapDtls12, true), 48, $hashAlgo);
                $hhCurTls4 = $this->clients[$clientId]['handshakeHash'] ?? '';
                $hhCurDtls12 = $this->clients[$clientId]['handshakeHashDTLS12'] ?? '';
                if ($hhCurTls4 !== '' && $hhCurTls4 !== $snapTls4) {
                    $msCandidates[$pmsName . '_ext_hhashCurTLS4'] = $this->tls12PRF($onePms, "extended master secret", hash($hashAlgo, $hhCurTls4, true), 48, $hashAlgo);
                }
                if ($hhCurDtls12 !== '' && $hhCurDtls12 !== $snapDtls12) {
                    $msCandidates[$pmsName . '_ext_hhashCurDTLS12'] = $this->tls12PRF($onePms, "extended master secret", hash($hashAlgo, $hhCurDtls12, true), 48, $hashAlgo);
                }
                $msCandidates[$pmsName . '_ext_snap'] = $msCandidates[$pmsName . '_ext_snapDTLS12'];
                $msCandidates[$pmsName . '_ext_cr_sr'] = $this->tls12PRF($onePms, "extended master secret", $clientRandom . $serverRandom, 48, $hashAlgo);
                $msCandidates[$pmsName . '_ext_cr_sr_rev'] = $this->tls12PRF($onePms, "extended master secret", $serverRandom . $clientRandom, 48, $hashAlgo);
                $msCandidates[$pmsName . '_legacy'] = $this->tls12PRF($onePms, "master secret", $clientRandom . $serverRandom, 48, $hashAlgo);
                $msCandidates[$pmsName . '_inv_legacy'] = $this->tls12PRF($onePms, "master secret", $serverRandom . $clientRandom, 48, $hashAlgo);
            }
        }
        if (empty($msCandidates)) {
            $msCandidates['ext_snapTLS4'] = $this->clients[$clientId]['masterSecretExtendedTLS4'] ?? '';
            $msCandidates['ext_snapDTLS12'] = $this->clients[$clientId]['masterSecretExtendedDTLS12'] ?? '';
            $msCandidates['ext_snap'] = $msCandidates['ext_snapDTLS12'];
            if (empty($msCandidates['ext_snapTLS4'])) {
                $msCandidates['ext_snap'] = $this->clients[$clientId]['masterSecretExtended'] ?? '';
            }
            $msCandidates['legacy'] = $this->clients[$clientId]['masterSecretLegacy'] ?? '';
        }

        $seedVariants = [
            'sr_cr' => $serverRandom . $clientRandom,
            'cr_sr' => $clientRandom . $serverRandom,
        ];

        $kbLen = $keyLen * 2 + $ivLen * 2;
        $kbLenExtra = $keyLen * 2 + 8 * 2;
        $splitPermutations = [

            'std' => [0, $keyLen, $keyLen, $keyLen, 2 * $keyLen, $ivLen, 2 * $keyLen + $ivLen, $ivLen, $kbLen],
            'civ_first' => [2 * $ivLen, $keyLen, 2 * $ivLen + $keyLen, $keyLen, 0, $ivLen, $ivLen, $ivLen, $kbLen],
            'swp_keys' => [$keyLen, $keyLen, 0, $keyLen, 2 * $keyLen, $ivLen, 2 * $keyLen + $ivLen, $ivLen, $kbLen],
            'swp_iv' => [0, $keyLen, $keyLen, $keyLen, 2 * $keyLen + $ivLen, $ivLen, 2 * $keyLen, $ivLen, $kbLen],
            'swp_both' => [$keyLen, $keyLen, 0, $keyLen, 2 * $keyLen + $ivLen, $ivLen, 2 * $keyLen, $ivLen, $kbLen],
            'iv8_std' => [0, $keyLen, $keyLen, $keyLen, 2 * $keyLen, 8, 2 * $keyLen + 8, 8, $kbLenExtra],
            'iv8_swp' => [$keyLen, $keyLen, 0, $keyLen, 2 * $keyLen + 8, 8, 2 * $keyLen, 8, $kbLenExtra],
            'k32_std' => [0, $keyLen, $keyLen, $keyLen, 2 * $keyLen, $ivLen, 2 * $keyLen + $ivLen, $ivLen, $kbLen], // alias
        ];

        $labels = ["key expansion"];

        $encryptionByVariant = [];
        foreach ($msCandidates as $msName => $ms) {
            if (strlen($ms) !== 48) continue;
            foreach ($seedVariants as $seedName => $seed) {
                foreach ($labels as $label) {
                    foreach ($splitPermutations as $spName => $sp) {
                        list($co, $cl, $so, $sl, $cio, $cil, $sio, $sil, $totalLen) = $sp;
                        if ($co + $cl > $totalLen) continue;
                        if ($so + $sl > $totalLen) continue;
                        if ($cio + $cil > $totalLen) continue;
                        if ($sio + $sil > $totalLen) continue;
                        $kb = $this->tls12PRF($ms, $label, $seed, $totalLen, $hashAlgo);
                        $cwk = substr($kb, $co, $cl);
                        $swk = substr($kb, $so, $sl);
                        $cwi = substr($kb, $cio, $cil);
                        $swi = substr($kb, $sio, $sil);
                        $variantName = $msName . '_' . $seedName . '_' . $spName;
                        $encryptionByVariant[$variantName] = [
                            'clientWriteKey' => $cwk,
                            'serverWriteKey' => $swk,
                            'clientWriteIV' => $cwi,
                            'serverWriteIV' => $swi,
                            'cipherAlgo' => $cipherAlgo,
                            'variant' => $variantName,
                            'masterSecret' => $ms,
                        ];
                    }
                }
            }
        }
        $this->clients[$clientId]['encryptionVariants'] = $encryptionByVariant;
        $first = reset($encryptionByVariant);
        $firstKey = key($encryptionByVariant);
        if (isset($encryptionByVariant['pms_ext_hhashCurDTLS12_sr_cr_std'])) {
            $this->clients[$clientId]['encryption'] = $encryptionByVariant['pms_ext_hhashCurDTLS12_sr_cr_std'];
        } elseif (isset($encryptionByVariant['pms_ext_hhashCurTLS4_sr_cr_std'])) {
            $this->clients[$clientId]['encryption'] = $encryptionByVariant['pms_ext_hhashCurTLS4_sr_cr_std'];
        } elseif (isset($encryptionByVariant['pms_ext_snapTLS4_sr_cr_std'])) {
            $this->clients[$clientId]['encryption'] = $encryptionByVariant['pms_ext_snapTLS4_sr_cr_std'];
        } elseif (isset($encryptionByVariant['ext_snapTLS4_sr_cr_std'])) {
            $this->clients[$clientId]['encryption'] = $encryptionByVariant['ext_snapTLS4_sr_cr_std'];
        } elseif ($first) {
            $this->clients[$clientId]['encryption'] = $first;
        }
        $this->clients[$clientId]['cachedServerFlight'] = [];
        $this->_log_std("Client {$clientId} Client CCS received, " . count($encryptionByVariant) . " key variants ready (default=$firstKey, defer server CCS/Finished until client Finished verified)\n");

        $testEpoch = 1;
        $testSeq = 0;
        $testContentType = 0x16;
        $testPlain = "\x14\x00\x00\x0c" . pack('n', 5) . "\x00\x00\x00\x00\x00\x0c" . random_bytes(12); // DTLS-style Finished (24B)
        $numValid = 0;
        $firstValidVariant = '';
        foreach ($encryptionByVariant as $variantName => $enc) {
            $cipherAlgo = $enc['cipherAlgo'];
            $skey = $enc['serverWriteKey'];
            $sivf = $enc['serverWriteIV'];
            $ne = pack('n', $testEpoch) . substr(pack('J', $testSeq), 2, 6);
            $nonce = $sivf . $ne;
            $extSeq = $ne;
            $aad = $extSeq . chr($testContentType) . "\xFE\xFD" . pack('n', strlen($testPlain));
            $tag = '';
            $ct = @openssl_encrypt($testPlain, $cipherAlgo, $skey, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
            if ($ct === false || $tag === false || strlen($tag) !== 16) {
                $numValid++;
                continue;
            }
            $frag = $ne . $ct . $tag;

            $cne = substr($frag, 0, 8);
            $crest = substr($frag, 8);
            $cct = substr($crest, 0, -16);
            $ctag = substr($crest, -16);
            $cnonce = $sivf . $cne;
            $caad = $cne . chr($testContentType) . "\xFE\xFD" . pack('n', strlen($testPlain));
            while (openssl_error_string() !== false) {
            }
            $dec = @openssl_decrypt($cct, $cipherAlgo, $skey, OPENSSL_RAW_DATA, $cnonce, $ctag, $caad);
            if (is_string($dec) && hash_equals($dec, $testPlain)) {
                if ($firstValidVariant === '') $firstValidVariant = $variantName;
            } else {

                $ckey = $enc['clientWriteKey'];
                $civf = $enc['clientWriteIV'];
                $ne2 = pack('n', $testEpoch) . substr(pack('J', $testSeq), 2, 6);
                $nonce2 = $civf . $ne2;
                $aad2 = $ne2 . chr($testContentType) . "\xFE\xFD" . pack('n', strlen($testPlain));
                $tag2 = '';
                $ct2 = @openssl_encrypt($testPlain, $cipherAlgo, $ckey, OPENSSL_RAW_DATA, $nonce2, $tag2, $aad2);
                if (is_string($ct2) && strlen($tag2) === 16) {
                    $frag2 = $ne2 . $ct2 . $tag2;
                    $neD = substr($frag2, 0, 8);
                    $rD = substr($frag2, 8);
                    $ctD = substr($rD, 0, -16);
                    $tgD = substr($rD, -16);
                    $nD = $civf . $neD;
                    $aD = $neD . chr($testContentType) . "\xFE\xFD" . pack('n', strlen($testPlain));
                    while (openssl_error_string() !== false) {
                    }
                    $ptD = @openssl_decrypt($ctD, $cipherAlgo, $ckey, OPENSSL_RAW_DATA, $nD, $tgD, $aD);
                    if (is_string($ptD) && hash_equals($ptD, $testPlain)) {
                        if ($firstValidVariant === '') $firstValidVariant = $variantName;
                        $numValid++;
                        continue;
                    }
                }
                continue;
            }
            $numValid++;
        }
        $this->_log_std("Client {$clientId} KEY SELF-TEST: $numValid/" . count($encryptionByVariant) . " variants pass roundtrip.\n");
        if ($firstValidVariant !== '') $this->_log_std("Client {$clientId} First valid variant: $firstValidVariant\n");
        if ($numValid === 0) {
            $this->_log_std("Client {$clientId} *** ALL KEY VARIANTS FAIL SELF-TEST! This indicates broken PRF/key-split/openssl-params ***\n");
            $dbgPMS = bin2hex($this->clients[$clientId]['preMasterSecret'] ?? '');
            $dbgMSL = bin2hex($this->clients[$clientId]['masterSecretLegacy'] ?? '');
            $dbgMSE = bin2hex($this->clients[$clientId]['masterSecretExtended'] ?? '');
            $this->_log_std("Client {$clientId} DEBUG: PMS=$dbgPMS\n  MS_Legacy=$dbgMSL\n  MS_Extended=$dbgMSE\n");
        }
    }


    /**
     * dtls加密
     * @param $clientId
     * @param $data
     * @param $epoch
     * @param $seq
     * @param $contentType
     * @return string
     */
    private function encryptDTLSRecord($clientId, $data, $epoch, $seq, $contentType = 0x16)
    {
        $enc = $this->clients[$clientId]['encryption'];
        $key = $enc['serverWriteKey'];
        $ivFixed = $enc['serverWriteIV'];

        $epochBE = pack('n', $epoch);
        $seq48BE = substr(pack('J', $seq), 2, 6);
        $nonceExplicit = $epochBE . $seq48BE;
        $nonce = $ivFixed . $nonceExplicit;

        $extendedSeq = $nonceExplicit;
        $ad = $extendedSeq . chr($contentType) . "\xFE\xFD" . pack('n', strlen($data));

        $tag = '';
        $ciphertext = openssl_encrypt($data, $enc['cipherAlgo'], $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
        return $nonceExplicit . $ciphertext . $tag;
    }


    /**
     * DTLS解密
     * @param $clientId
     * @param $data
     * @param $epoch
     * @param $seq
     * @param $contentType
     * @param $version
     * @return false|string
     */
    private function decryptDTLSRecord($clientId, $data, $epoch, $seq, $contentType = 0x17, $version = "\xFE\xFD")
    {
        $variants = $this->clients[$clientId]['encryptionVariants'] ?? null;
        $pinnedEnc = $this->clients[$clientId]['encryption'] ?? null;
        if (is_array($pinnedEnc) && !empty($pinnedEnc['clientWriteKey']) && !empty($pinnedEnc['serverWriteKey'])) {
            $pinPrefix = ['__pinned' => $pinnedEnc];
            if (is_array($variants)) {
                $variants = $pinPrefix + $variants;
            } else {
                $variants = $pinPrefix;
            }
        }
        if (empty($variants)) {
            $variants = ['default' => $pinnedEnc];
        }

        $explicitLen = 8;
        $tagLen = 16;
        if (strlen($data) <= $explicitLen + $tagLen) return false;

        $nonceExplicit = substr($data, 0, $explicitLen);
        $rest = substr($data, $explicitLen);

        $ciphertext = substr($rest, 0, -$tagLen);
        $tag = substr($rest, -$tagLen);

        $extendedSeq = $nonceExplicit;
        $plaintextLen = strlen($ciphertext);

        $versionCandidates = [$version, "\xFE\xFD", "\xFD\xFD"];
        $lengthCandidates = [$plaintextLen];
        $tlsFragLen = strlen($data);
        $lengthCandidates[] = $tlsFragLen - $explicitLen - $tagLen;

        $loggedVariantErrors = 0;
        $loggedVariants = [];
        foreach ($variants as $variantName => $enc) {
            if (!$enc) continue;
            $key = $enc['clientWriteKey'];
            $ivFixed = $enc['clientWriteIV'];

            $nonceCandidates = [
                $ivFixed . $nonceExplicit,
                $nonceExplicit . $ivFixed,
                substr($ivFixed, 0, 2) . $nonceExplicit . substr($ivFixed, 2, 2),
                $ivFixed . substr($nonceExplicit, 2, 8),
            ];

            $ivLen = strlen($ivFixed);
            if ($ivLen === 8) {
                $nonceCandidates[] = $ivFixed ^ $nonceExplicit;
            }
            $variantLoggedThis = false;
            foreach ($nonceCandidates as $ncIdx => $nonce) {
                if (strlen($nonce) !== 12) continue;
                foreach ($versionCandidates as $vcIdx => $vVer) {
                    foreach ($lengthCandidates as $lcIdx => $vLen) {

                        while (openssl_error_string() !== false) {
                        }
                        $ad = $extendedSeq . chr($contentType) . $vVer . pack('n', $vLen);
                        $plaintext = openssl_decrypt($ciphertext, $enc['cipherAlgo'], $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
                        if ($plaintext !== false) {

                            $nonceModeByNcIdx = [
                                0 => 'fix_exp',
                                1 => 'exp_fix',
                                2 => 'split_iv_2_2',
                                3 => 'fix_exp_noepoch',
                                4 => 'xor8pad',
                            ];
                            $nm = isset($nonceModeByNcIdx[$ncIdx]) ? $nonceModeByNcIdx[$ncIdx] : 'fix_exp';

                            if (!is_array($this->clients[$clientId]['encryption']) ||
                                ($this->clients[$clientId]['encryption']['variant'] ?? null) !== $variantName ||
                                ($this->clients[$clientId]['encryption']['nonceMode'] ?? null) !== $nm ||
                                ($this->clients[$clientId]['encryption']['aadVersion'] ?? null) !== $vVer ||
                                ($this->clients[$clientId]['encryption']['aadLength'] ?? null) !== $vLen) {
                                $this->clients[$clientId]['encryption'] = array_replace(
                                    is_array($this->clients[$clientId]['encryption']) ? $this->clients[$clientId]['encryption'] : [],
                                    $enc,
                                    [
                                        'nonceMode' => $nm,
                                        'aadVersion' => $vVer,
                                        'aadLength' => $vLen,
                                        'variant' => $enc['variant'] ?? ($variantName === '__pinned' ? 'pinned_quick' : $variantName),
                                    ]
                                );
                                $this->_log_std("Client {$clientId} encryption pinned: variant={$variantName} nonceMode=$nm aadVer=" . bin2hex($vVer) . " aadLen=$vLen\n");
                            }
                            $this->_log_std("Client {$clientId} decryptDTLSRecord SUCCESS variant={$variantName}, ncIdx={$ncIdx}[$nm], vcIdx={$vcIdx}(" . bin2hex($vVer) . "), lcIdx={$lcIdx}({$vLen})\n");
                            $this->_log_std("  plaintext len=" . strlen($plaintext) . " hex=" . bin2hex($plaintext) . "\n");
                            return $plaintext;
                        }
                        if ($loggedVariantErrors < 8 && !$variantLoggedThis) {
                            $err = '';
                            while (($e = openssl_error_string()) !== false) {
                                $err .= $e . "\n";
                            }
                            if ($err === '') $err = "openssl_decrypt returned false (no message queue, likely wrong key/nonce/tag/aad)\n";
                            $this->_log_std("Client {$clientId} decryptDTLSRecord #$loggedVariantErrors variant[{$variantName}] ncIdx={$ncIdx},v=" . bin2hex($vVer) . " len={$vLen} FAILED\n");
                            $this->_log_std("  key (len=" . strlen($key) . ")=" . bin2hex($key) . "\n");
                            $this->_log_std("  ivFixed (len=" . strlen($ivFixed) . ")=" . bin2hex($ivFixed) . "\n");
                            $this->_log_std("  nonce=" . bin2hex($nonce) . "  nonce_explicit=" . bin2hex($nonceExplicit) . "\n");
                            $this->_log_std("  ad=" . bin2hex($ad) . "  ct=" . bin2hex($ciphertext) . "  tag=" . bin2hex($tag) . "\n");
                            $loggedVariantErrors++;
                            $variantLoggedThis = true;
                        } else {
                            while (openssl_error_string() !== false) {
                            }
                        }
                    }
                }
            }
        }
        $this->_log_std("Client {$clientId} decryptDTLSRecord: $loggedVariantErrors variant samples logged, all " . count($variants) . " failed.\n");

        if (!defined('DECRYPT_FALLBACK_DONE') && $epoch > 0) {
            $this->_log_std("Client {$clientId} decryptDTLSRecord FALLBACK: launching exhaustive search...\n");
            $fallbackResult = $this->_decryptFallbackSearch($clientId, $data, $epoch, $seq, $contentType, $version);
            if (is_string($fallbackResult) && $fallbackResult !== '') {
                define('DECRYPT_FALLBACK_DONE', true);
                return $fallbackResult;
            }
        }

        return false;
    }

    /**
     * DTLS穷举法解密浏览器发来的数据
     * @param $clientId
     * @param $data
     * @param $epoch
     * @param $seq
     * @param $contentType
     * @param $version
     * @return false|string
     * @note 当标准的密钥派生（Key Derivation）逻辑无法解密浏览器发来的加密包时，立即启动“穷举匹配模式”，通过遍历所有可能的算法组合（主密钥变体、密钥拆分顺序、Nonce 拼接规则、AAD 版本等），暴力尝试解密，一旦成功，就“记住”这套参数供后续所有数据包使用
     */
    private function _decryptFallbackSearch($clientId, $data, $epoch, $seq, $contentType, $version)
    {
        $hashAlgo = $this->clients[$clientId]['masterHashAlgo'] ?? 'sha256';
        $cipherAlgo = 'aes-128-gcm';
        $cr = $this->clients[$clientId]['clientRandom'] ?? '';
        $sr = $this->clients[$clientId]['serverRandom'] ?? '';

        $pmsList = [];
        if (isset($this->clients[$clientId]['preMasterSecret']) && is_string($this->clients[$clientId]['preMasterSecret']))
            $pmsList[] = $this->clients[$clientId]['preMasterSecret'];
        if (isset($this->clients[$clientId]['preMasterSecretAlt']) && is_string($this->clients[$clientId]['preMasterSecretAlt']))
            $pmsList[] = $this->clients[$clientId]['preMasterSecretAlt'];
        if (empty($pmsList)) return false;

        $snapTLS4 = $this->clients[$clientId]['sessionHashSnapshotTLS4'] ?? '';
        $snapDTLS12 = $this->clients[$clientId]['sessionHashSnapshotDTLS12'] ?? '';
        $snapLegacy = $this->clients[$clientId]['sessionHashSnapshot'] ?? $snapTLS4;
        $hhashCur = $this->clients[$clientId]['handshakeHash'] ?? '';
        $hhashCurD = $this->clients[$clientId]['handshakeHashDTLS12'] ?? '';

        $allSnaps = [
            'snapTLS4' => $snapTLS4,
            'snapDTLS12' => $snapDTLS12,
            'snapLegacy' => $snapLegacy,
        ];
        if ($hhashCur !== '' && $hhashCur !== $snapTLS4) $allSnaps['hhashCurTLS4'] = $hhashCur;
        if ($hhashCurD !== '' && $hhashCurD !== $snapDTLS12) $allSnaps['hhashCurDTLS12'] = $hhashCurD;

        $msList = [];
        foreach ($pmsList as $pIdx => $pms) {

            foreach ($allSnaps as $snName => $snap) {
                if ($snap === '') continue;
                $snapHash = hash($hashAlgo, $snap, true);
                $msList['p' . $pIdx . '_ems_' . $snName . '_hash'] = $this->tls12PRF($pms, "extended master secret", $snapHash, 48, $hashAlgo);
            }

            $msList['p' . $pIdx . '_ems_CR_SR'] = $this->tls12PRF($pms, "extended master secret", $cr . $sr, 48, $hashAlgo);
            $msList['p' . $pIdx . '_ems_SR_CR'] = $this->tls12PRF($pms, "extended master secret", $sr . $cr, 48, $hashAlgo);

            $msList['p' . $pIdx . '_legacy_CR_SR'] = $this->tls12PRF($pms, "master secret", $cr . $sr, 48, $hashAlgo);
            $msList['p' . $pIdx . '_legacy_SR_CR'] = $this->tls12PRF($pms, "master secret", $sr . $cr, 48, $hashAlgo);

            foreach ($allSnaps as $snName => $snap) {
                if ($snap === '') continue;
                $snapHash = hash($hashAlgo, $snap, true);
                $msList['p' . $pIdx . '_ems0_' . $snName] = $this->tls12PRF($pms, "extended master secret\x00", $snapHash, 48, $hashAlgo);
            }
            $msList['p' . $pIdx . '_legacy0_CR_SR'] = $this->tls12PRF($pms, "master secret\x00", $cr . $sr, 48, $hashAlgo);
        }

        $i = 0;
        foreach ($msList as $mn => $mv) {
            if ($i++ >= 4) break;
            $this->_log_std("  candidate[$mn] MS sha256=" . bin2hex(hash('sha256', $mv, true)) . " (len=" . strlen($mv) . ")\n");
        }

        $explicitLen = 8;
        $tagLen = 16;
        $nonceExplicit = substr($data, 0, $explicitLen);
        $rest = substr($data, $explicitLen);
        $ciphertext = substr($rest, 0, -$tagLen);
        $tag = substr($rest, -$tagLen);
        $extendedSeq = pack('n', $epoch) . substr(pack('J', $seq), 2, 6);

        $versionCands = ["\xFE\xFD", "\xFD\xFD", $version];
        $lengthCands = [strlen($ciphertext), 24, 16, 12, 20, 28, 32];
        $keyExpLabels = ["key expansion", "key expansion\x00"];
        $seedCands = ['SR_CR' => $sr . $cr, 'CR_SR' => $cr . $sr];

        $kbSizes = [40 => 4, 48 => 8, 56 => 12];

        $tries = 0;
        $totalExpected = count($msList) * count($keyExpLabels) * count($seedCands) * 3 * 6 * 6 * count($versionCands) * count($lengthCands);
        $this->_log_std("Client {$clientId} fallback: ~$totalExpected combinations\n");

        foreach ($msList as $msName => $ms) {
            foreach ($keyExpLabels as $lbl) {
                foreach ($seedCands as $seedName => $seed) {
                    foreach ($kbSizes as $kbLen => $ivLen) {
                        $kb = $this->tls12PRF($ms, $lbl, $seed, $kbLen, $hashAlgo);

                        $splits = [
                            ['cwk' => substr($kb, 0, 16), 'swk' => substr($kb, 16, 16), 'cwi' => substr($kb, 32, $ivLen), 'swi' => substr($kb, 32 + $ivLen, $ivLen)],
                            ['swk' => substr($kb, 0, 16), 'cwk' => substr($kb, 16, 16), 'cwi' => substr($kb, 32, $ivLen), 'swi' => substr($kb, 32 + $ivLen, $ivLen)],
                            ['cwk' => substr($kb, 0, 16), 'swk' => substr($kb, 16, 16), 'swi' => substr($kb, 32, $ivLen), 'cwi' => substr($kb, 32 + $ivLen, $ivLen)],
                            ['swk' => substr($kb, 0, 16), 'cwk' => substr($kb, 16, 16), 'swi' => substr($kb, 32, $ivLen), 'cwi' => substr($kb, 32 + $ivLen, $ivLen)],

                            ['cwi' => substr($kb, 0, $ivLen), 'swi' => substr($kb, $ivLen, $ivLen), 'cwk' => substr($kb, 2 * $ivLen, 16), 'swk' => substr($kb, 2 * $ivLen + 16, 16)],
                            ['swi' => substr($kb, 0, $ivLen), 'cwi' => substr($kb, $ivLen, $ivLen), 'cwk' => substr($kb, 2 * $ivLen, 16), 'swk' => substr($kb, 2 * $ivLen + 16, 16)],
                            ['cwi' => substr($kb, 0, $ivLen), 'swi' => substr($kb, $ivLen, $ivLen), 'swk' => substr($kb, 2 * $ivLen, 16), 'cwk' => substr($kb, 2 * $ivLen + 16, 16)],
                        ];
                        foreach ($splits as $spIdx => $sp) {
                            if (!isset($sp['cwk']) || !isset($sp['cwi'])) continue;
                            foreach (['client' => ['k' => $sp['cwk'], 'iv' => $sp['cwi']], 'server' => ['k' => $sp['swk'], 'iv' => $sp['swi']]] as $who => $mat) {
                                $k = $mat['k'];
                                $ivf = $mat['iv'];
                                if (strlen($k) !== 16) continue;
                                $ivfLen = strlen($ivf);

                                $nonces = [];
                                $nonces['fix_exp'] = str_pad(substr($ivf . $nonceExplicit, 0, 12), 12, "\0");
                                $nonces['exp_fix'] = str_pad(substr($nonceExplicit . $ivf, 0, 12), 12, "\0");
                                if ($ivfLen === 4) {
                                    $nonces['fix_xor_exp_plus_fix'] = $ivf . ($nonceExplicit ^ str_repeat($ivf, 2));
                                }
                                if ($ivfLen === 8) {
                                    $nonces['xor8pad'] = str_pad($ivf ^ $nonceExplicit, 12, "\0", STR_PAD_RIGHT);
                                    $nonces['xor8padL'] = str_pad($ivf ^ $nonceExplicit, 12, "\0", STR_PAD_LEFT);
                                }

                                $exact12 = [];
                                foreach ($nonces as $nn => $nv) {
                                    if (strlen($nv) === 12) $exact12[$nn] = $nv;
                                }

                                foreach ($exact12 as $nName => $nonce) {
                                    foreach ($versionCands as $vVer) {
                                        foreach ($lengthCands as $vLen) {
                                            while (openssl_error_string() !== false) {
                                            }
                                            $ad = $extendedSeq . chr($contentType) . $vVer . pack('n', $vLen);
                                            $pt = openssl_decrypt($ciphertext, $cipherAlgo, $k, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
                                            $tries++;
                                            if ($pt !== false) {
                                                $this->_log_std("Client {$clientId} ##### FALLBACK DECRYPT SUCCESS! tries=$tries #####\n");
                                                $this->_log_std("  msName=$msName, lbl=" . bin2hex($lbl) . ", seed=$seedName, kbLen=$kbLen\n");
                                                $this->_log_std("  splitIdx=$spIdx, who=$who, nonceName=$nName\n");
                                                $this->_log_std("  ver=" . bin2hex($vVer) . " len=$vLen contentType=$contentType\n");
                                                $this->_log_std("  key=" . bin2hex($k) . " fixedIv=" . bin2hex($ivf) . " nonce=" . bin2hex($nonce) . "\n");
                                                $this->_log_std("  pt len=" . strlen($pt) . " hex=" . bin2hex($pt) . "\n");

                                                $this->clients[$clientId]['encryption'] = [
                                                    'cipherAlgo' => $cipherAlgo,
                                                    'clientWriteKey' => $sp['cwk'],
                                                    'clientWriteIV' => $sp['cwi'],
                                                    'serverWriteKey' => $sp['swk'],
                                                    'serverWriteIV' => $sp['swi'],
                                                    'nonceMode' => $nName,
                                                    'aadVersion' => $vVer,
                                                    'aadLength' => $vLen,
                                                    'variant' => 'fb_' . $msName,
                                                    'masterSecret' => $ms,
                                                    'msName' => $msName,
                                                    'kbLen' => $kbLen,
                                                    'splitIdx' => $spIdx,
                                                    'seedName' => $seedName,
                                                    'keyExpLabel' => $lbl,
                                                ];

                                                $this->clients[$clientId]['masterSecret'] = $ms;
                                                $this->clients[$clientId]['fbMsName'] = $msName;
                                                if (strlen($pt) >= 4 && ord($pt[0]) === 20) {
                                                    $vlen = (ord($pt[1]) << 16) | (ord($pt[2]) << 8) | ord($pt[3]);

                                                    $isDTLSHeader = false;
                                                    if (strlen($pt) >= 12) {
                                                        $fragLenFromDTLSHeader = (ord($pt[9]) << 16) | (ord($pt[10]) << 8) | ord($pt[11]);
                                                        if ($fragLenFromDTLSHeader === $vlen && 12 + $vlen === strlen($pt)) {
                                                            $isDTLSHeader = true;
                                                        }
                                                    }
                                                    if ($isDTLSHeader) {
                                                        $actualVD = substr($pt, 12, $vlen);
                                                        $vdLogFmt = 'DTLS12hdr@12';
                                                    } else {
                                                        $actualVD = substr($pt, 4, $vlen);
                                                        $vdLogFmt = 'TLS4hdr@4';
                                                    }

                                                    $hhTls4 = $this->clients[$clientId]['handshakeHash'] ?? '';
                                                    $hhDtls = $this->clients[$clientId]['handshakeHashDTLS12'] ?? $hhTls4;
                                                    $hhCands = [
                                                        'hhTLS4' => $hhTls4,
                                                        'hhDTLS12' => $hhDtls,
                                                    ];
                                                    $foundVDMatch = false;
                                                    $chosenHH = '';
                                                    $expectedVD = '';
                                                    foreach ($hhCands as $hhCN => $hhCVal) {
                                                        if ($hhCVal === '') continue;
                                                        $hshVD = hash($hashAlgo, $hhCVal, true);
                                                        $expVD = $this->tls12PRF($ms, "client finished", $hshVD, 12, $hashAlgo);
                                                        if (hash_equals($expVD, $actualVD)) {
                                                            $foundVDMatch = true;
                                                            $chosenHH = $hhCN;
                                                            $expectedVD = $expVD;
                                                            $this->clients[$clientId]['matchedHhashName'] = $hhCN;
                                                            $this->clients[$clientId]['encryption']['matchedHhashName'] = $hhCN;
                                                            break;
                                                        }
                                                        if ($expectedVD === '') $expectedVD = $expVD;
                                                    }
                                                    $this->clients[$clientId]['fbClientVerifyData'] = $actualVD;
                                                    $this->_log_std("  verify_data (vlen=$vlen, fmt=$vdLogFmt) " . ($foundVDMatch ? "MATCH hhash=$chosenHH" : "NO MATCH") . "\n");
                                                    $this->_log_std("    expected(first)=" . bin2hex($expectedVD) . " actual=" . bin2hex($actualVD) . "\n");
                                                }
                                                return $pt;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        $this->_log_std("Client {$clientId} fallback decrypt exhausted ($tries tries, no match)\n");
        return false;
    }


    /**
     * DTLS握手
     * @param $clientId
     * @param $data
     * @return void
     */
    private function handleDTLSHandshake($clientId, $data)
    {
        if (strlen($data) < 12) return;

        $msgType = ord($data[0]);
        $length = unpack('N', "\x00" . substr($data, 1, 3))[1];
        $messageSeq = unpack('n', substr($data, 4, 2))[1];
        $fragOffset = unpack('N', "\x00" . substr($data, 6, 3))[1];
        $fragLength = unpack('N', "\x00" . substr($data, 9, 3))[1];

        $this->_log_std("Client {$clientId} DTLS Handshake: type={$msgType}, len={$length}, seq={$messageSeq}, fragOff={$fragOffset}, fragLen={$fragLength}\n");

        $validTypes = [0, 1, 2, 3, 4, 6, 8, 10, 11, 12, 13, 14, 15, 16, 20];
        if (!in_array($msgType, $validTypes) || $length > 65535 || $length < 0 || $fragLength > $length || $fragOffset > $length) {
            $this->_log_std("Client {$clientId} Invalid handshake header (msgType={$msgType}, len={$length}, fragLen={$fragLength}), skipping (probably encrypted)\n");
            return;
        }
        if (strlen($data) < 12 + $fragLength) {
            $this->_log_std("Client {$clientId} Fragment longer than buffer, skipping\n");
            return;
        }

        $fragData = substr($data, 12, $fragLength);

        if ($fragOffset == 0 && $fragLength == $length) {
            $this->processHandshakeMessage($clientId, $msgType, $fragData, $length, $messageSeq);
            return;
        }

        if (!isset($this->clients[$clientId]['handshakeFrags'])) {
            $this->clients[$clientId]['handshakeFrags'] = [];
        }
        $key = $messageSeq;
        if (!isset($this->clients[$clientId]['handshakeFrags'][$key])) {
            if ($length <= 0 || $length > 65535) {
                $this->_log_std("Client {$clientId} Invalid fragment total length, skipping\n");
                return;
            }
            $this->clients[$clientId]['handshakeFrags'][$key] = [
                'msgType' => $msgType,
                'length' => $length,
                'msgSeq' => $messageSeq,
                'received' => 0,
                'data' => str_repeat("\x00", $length)
            ];
        }
        $frag = &$this->clients[$clientId]['handshakeFrags'][$key];
        if ($fragOffset + $fragLength > $frag['length']) {
            $this->_log_std("Client {$clientId} Fragment overflow, skipping\n");
            return;
        }
        for ($i = 0; $i < $fragLength; $i++) {
            $frag['data'][$fragOffset + $i] = $fragData[$i];
        }
        $frag['received'] += $fragLength;

        $this->_log_std("Client {$clientId} Fragment reassembled: received={$frag['received']}/{$frag['length']}\n");

        if ($frag['received'] >= $frag['length']) {
            $completeData = $frag['data'];
            $completeMsgType = $frag['msgType'];
            $completeLength = $frag['length'];
            $completeMsgSeq = $frag['msgSeq'];
            unset($this->clients[$clientId]['handshakeFrags'][$key]);
            $this->processHandshakeMessage($clientId, $completeMsgType, $completeData, $completeLength, $completeMsgSeq);
        }
    }

    /**
     * DTLS 握手哈希的“双轨记录器”
     * @param $clientId
     * @param $msgType
     * @param $totalLength
     * @param $messageSeq
     * @param $body
     * @param $typeNameForLog
     * @return void
     * @note 在 DTLS 握手过程中，每收到或发送一个握手消息（Handshake Message），就将该消息同时追加到两条独立的哈希链中——一条按 TLS 4 字节头格式记录，另一条按 DTLS 12 字节头格式记录。这两条哈希链将分别用于后续 Finished 消息中 verify_data 的校验，以兼容不同浏览器（Chrome vs Firefox）对握手哈希计算方式的差异。
     */
    private function _appendToBothHandshakeHashes($clientId, $msgType, $totalLength, $messageSeq, $body, $typeNameForLog = null)
    {
        if ($totalLength === null) $totalLength = strlen($body);
        $len3 = function ($v) {
            return substr(pack('N', $v), 1, 3);
        };

        $tls4Header = chr($msgType) . $len3($totalLength);
        $appendTls4 = $tls4Header . $body;
        $this->clients[$clientId]['handshakeHash'] = ($this->clients[$clientId]['handshakeHash'] ?? '') . $appendTls4;

        if ($messageSeq === null) {
            if (!isset($this->clients[$clientId]['fallbackHsSeqDTLS'])) {
                $this->clients[$clientId]['fallbackHsSeqDTLS'] = 0;
            }
            $messageSeq = $this->clients[$clientId]['fallbackHsSeqDTLS']++;
        }
        $dtlsHeader = chr($msgType)
            . $len3($totalLength)
            . pack('n', $messageSeq)
            . "\x00\x00\x00"
            . $len3($totalLength);
        $appendDtls = $dtlsHeader . $body;
        $this->clients[$clientId]['handshakeHashDTLS12'] = ($this->clients[$clientId]['handshakeHashDTLS12'] ?? '') . $appendDtls;

        if ($typeNameForLog) {
            $hhTls4 = $this->clients[$clientId]['handshakeHash'];
            $hhDtls = $this->clients[$clientId]['handshakeHashDTLS12'];
            $this->_log_std("Client {$clientId} handshakeHash[{$typeNameForLog}] TLS4: append " . strlen($appendTls4) . "B, total " . strlen($hhTls4) . "B, sha256=" . bin2hex(hash('sha256', $hhTls4, true)) . "\n");
            $this->_log_std("Client {$clientId} handshakeHash[{$typeNameForLog}] DTLS12: append " . strlen($appendDtls) . "B, total " . strlen($hhDtls) . "B, sha256=" . bin2hex(hash('sha256', $hhDtls, true)) . "\n");
        }
    }

    /**
     * 处理DTLS握手消息
     * @param $clientId
     * @param $msgType
     * @param $data
     * @param $totalLength
     * @param $messageSeq
     * @return void
     */
    private function processHandshakeMessage($clientId, $msgType, $data, $totalLength = null, $messageSeq = null)
    {

        $fingerprint = $msgType . ":" . strlen($data) . ":" . bin2hex(substr($data, 0, 8));
        if (!isset($this->clients[$clientId]['hsProcessed'])) {
            $this->clients[$clientId]['hsProcessed'] = [];
        }
        if (isset($this->clients[$clientId]['hsProcessed'][$fingerprint])) {
            $this->_log_std("Client {$clientId} Handshake msg (type={$msgType},fp={$fingerprint}) already processed, skip re-append to hash\n");

            if ($msgType === 20) {
                $cachedFlight = $this->clients[$clientId]['cachedServerFlight'] ?? [];
                if (!empty($cachedFlight)) {
                    foreach ($cachedFlight as $r) {
                        $this->sendUDP($clientId, $r);
                    }
                    $this->_log_std("Client {$clientId} Re-sent cached server CCS+Finished on duplicate Client Finished (" . count($cachedFlight) . " records)\n");
                }
            }
            return;
        }
        $this->clients[$clientId]['hsProcessed'][$fingerprint] = true;

        $this->_log_std("Client {$clientId} Processing handshake: type={$msgType}, dataLen=" . strlen($data) . ", totalLen=" . ($totalLength === null ? 'null' : $totalLength) . ", msgSeq=" . ($messageSeq === null ? 'null' : $messageSeq) . "\n");

        if ($msgType !== 20) {
            $typeName = [1 => 'ClientHello', 16 => 'ClientKeyExchange'];
            $tn = $typeName[$msgType] ?? "msg$msgType";
            $this->_appendToBothHandshakeHashes($clientId, $msgType, $totalLength, $messageSeq, $data, $tn);
            if ($msgType === 1) {
                $hhTls4 = $this->clients[$clientId]['handshakeHash'];
                $this->_log_std("Client {$clientId} ClientHello TLS4 hdr+body (first 64 hex)=" . bin2hex(substr($hhTls4, 0, 64)) . "\n");
            } elseif ($msgType === 16) {
                $hhTls4 = $this->clients[$clientId]['handshakeHash'];
                $this->_log_std("Client {$clientId} ClientKeyExchange TLS4 hdr+body (full hex)=" . bin2hex(substr($hhTls4, -70)) . "\n");
            }
        }

        switch ($msgType) {
            case 1:
                $this->handleClientHello($clientId, $data);
                break;
            case 16:
                $this->_log_std("Client {$clientId} ClientKeyExchange received\n");
                $this->handleClientKeyExchange($clientId, $data);
                break;
            case 20:
                $this->_log_std("Client {$clientId} Finished received\n");

                $len3T = function ($v) {
                    return substr(pack('N', $v), 1, 3);
                };
                if ($totalLength === null) $totalLength = strlen($data);
                $clientFinDTLS = chr(20)
                    . $len3T($totalLength)
                    . pack('n', $messageSeq ?? 0)
                    . "\x00\x00\x00"
                    . $len3T($totalLength)
                    . $data;
                $this->handleFinished($clientId, $data, $clientFinDTLS);
                break;
        }
    }

    /**
     * dtls客户端握手-hello阶段
     * @param $clientId
     * @param $data
     * @return void
     */
    private function handleClientHello($clientId, $data)
    {
        $this->_log_std("Client {$clientId} ClientHello received (len=" . strlen($data) . ")\n");

        if (!isset($this->clients[$clientId]['hsSeq'])) {
            $this->clients[$clientId]['hsSeq'] = 0;
        }

        if (strlen($data) >= 2) {
            $this->clients[$clientId]['clientVersion'] = substr($data, 0, 2);
            $this->_log_std("Client {$clientId} ClientHello version: " . bin2hex($this->clients[$clientId]['clientVersion']) . "\n");
        }

        if (strlen($data) >= 34) {
            $this->clients[$clientId]['clientRandom'] = substr($data, 2, 32);
            $chRandHex = bin2hex($this->clients[$clientId]['clientRandom']);
            $this->_log_std("Client {$clientId} clientRandom extracted from offset 2, first 8 bytes: " . bin2hex(substr($this->clients[$clientId]['clientRandom'], 0, 8)) . "\n");

            if (isset($this->clients[$clientId]['hsCache'][$chRandHex])) {
                $cachedFlight = $this->clients[$clientId]['serverFlight'] ?? null;
                if ($cachedFlight) {
                    $this->sendUDP($clientId, $cachedFlight);
                    $this->_log_std("Client {$clientId} Retransmitting cached ServerFlight (len=" . strlen($cachedFlight) . ")\n");
                }

                return;
            }
            $this->clients[$clientId]['hsCache'][$chRandHex] = true;
        }

        $sessionId = '';
        if (strlen($data) >= 35) {
            $sessionIdLen = ord($data[34]);
            if ($sessionIdLen > 0 && strlen($data) >= 35 + $sessionIdLen) {
                $sessionId = substr($data, 35, $sessionIdLen);
            }
        }
        $this->clients[$clientId]['sessionId'] = $sessionId;
        $this->_log_std("Client {$clientId} Extracted session_id: " . bin2hex($sessionId) . " (len=" . strlen($sessionId) . ")\n");

        $cipherSuite = $this->parseCipherSuites($clientId, $data);
        $this->clients[$clientId]['cipherSuite'] = $cipherSuite;

        $this->_log_std("Client {$clientId} Selected cipher suite: 0x" . bin2hex($cipherSuite) . "\n");

        $this->clients[$clientId]['pendingRecords'] = [];

        $cs = bin2hex($cipherSuite);
        $this->clients[$clientId]['needsServerKeyExchange'] = in_array($cs, ['c02f', 'c02b', 'c030', 'c02c', 'cca8', 'cca9', 'c013', 'c014', 'c023', 'c027']);

        if ($this->clients[$clientId]['needsServerKeyExchange']) {
            $this->generateECDHEKey($clientId);
        }

        /** 服务端返回hello */
        $this->sendServerHello($clientId, $cipherSuite);
        /** 发送证书 */
        $this->sendCertificate($clientId);

        if ($this->clients[$clientId]['needsServerKeyExchange']) {
            /** 交换密钥 */
            $this->sendServerKeyExchange($clientId);
        }

        /** 回复hello完成 */
        $this->sendServerHelloDone($clientId);

        $records = $this->clients[$clientId]['pendingRecords'];
        $combined = implode('', $records);
        unset($this->clients[$clientId]['pendingRecords']);

        $this->clients[$clientId]['serverFlight'] = $combined;

        foreach ($records as $i => $record) {
            $this->sendUDP($clientId, $record);
            $this->_log_std("Client {$clientId} Record {$i} sent (len=" . strlen($record) . ")\n");
            usleep(10000);
        }

        $this->_log_std("Client {$clientId} ServerFlight sent (combined len=" . strlen($combined) . ")\n");

        $this->clients[$clientId]['dtlsState'] = 'handshaking';
    }

    /**
     * DTLS筛选最适合的加密方法
     * @param $clientId
     * @param $data
     * @return false|mixed|string
     * @note 它从客户端发来的密码套件（Cipher Suite）列表中，按照服务端预定义的优先级顺序，选择第一个双方都支持的套件，作为后续 DTLS 握手和数据加密的最终算法。
     */
    private function parseCipherSuites($clientId, $data)
    {

        $serverPreference = [
            "\xc0\x2f",  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (首选，兼容性+SHA256签名)
            "\xc0\x2b",  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            "\xc0\x30",  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            "\xc0\x13",  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            "\xc0\x14",  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            "\x00\x2f",  // TLS_RSA_WITH_AES_128_CBC_SHA
            "\x00\x35",  // TLS_RSA_WITH_AES_256_CBC_SHA
        ];
        $serverSupported = [
            "\xc0\x2f" => 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            "\xc0\x2b" => 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            "\xc0\x30" => 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            "\xc0\x13" => 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            "\xc0\x14" => 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            "\x00\x2f" => 'TLS_RSA_WITH_AES_128_CBC_SHA',
            "\x00\x35" => 'TLS_RSA_WITH_AES_256_CBC_SHA',
        ];

        if (strlen($data) < 34) {
            $this->_log_std("Client {$clientId} ClientHello too short\n");
            return "\x00\x2f";
        }

        $this->_log_std("Client {$clientId} ClientHello data first 40 bytes: " . bin2hex(substr($data, 0, 40)) . "\n");

        $pos = 34;
        $sessionIdLen = ord($data[$pos]);
        $this->_log_std("Client {$clientId} Session ID length at pos {$pos}: {$sessionIdLen}\n");
        $pos += 1 + $sessionIdLen;

        $this->_log_std("Client {$clientId} Position after session ID: {$pos}\n");

        $cookieLen = ord($data[$pos]);
        $this->_log_std("Client {$clientId} Cookie length at pos {$pos}: {$cookieLen}\n");
        $pos += 1 + $cookieLen;

        $this->_log_std("Client {$clientId} Position after cookie: {$pos}\n");

        if ($pos + 2 > strlen($data)) {
            $this->_log_std("Client {$clientId} No cipher suites found, pos={$pos}, len=" . strlen($data) . "\n");
            return "\x00\x2f";
        }

        $cipherSuitesLenBytes = substr($data, $pos, 2);
        $cipherSuitesLen = unpack('n', $cipherSuitesLenBytes)[1];
        $this->_log_std("Client {$clientId} Cipher suites len bytes: " . bin2hex($cipherSuitesLenBytes) . " -> {$cipherSuitesLen}\n");
        $pos += 2;

        $this->_log_std("Client {$clientId} Cipher suites list len: {$cipherSuitesLen}\n");

        if ($cipherSuitesLen == 0) {
            $this->_log_std("Client {$clientId} Empty cipher suites list\n");
            return "\x00\x2f";
        }

        $clientSuites = [];
        for ($i = 0; $i < $cipherSuitesLen; $i += 2) {
            if ($pos + $i + 2 > strlen($data)) break;
            $clientSuites[] = substr($data, $pos + $i, 2);
        }

        $pos += $cipherSuitesLen;

        $this->_log_std("Client {$clientId} After cipher_suites: pos={$pos}, remaining=" . (strlen($data) - $pos) . " bytes, hex(32B)=" . bin2hex(substr($data, $pos, min(32, strlen($data) - $pos))) . "\n");

        if ($pos + 1 > strlen($data)) {
            $this->_log_std("Client {$clientId} No compression methods found\n");
            return "\x00\x2f";
        }
        $compressionLen = ord($data[$pos]);
        $this->_log_std("Client {$clientId} Compression methods count={$compressionLen} @ pos {$pos}\n");
        $pos += 1 + $compressionLen;
        $this->_log_std("Client {$clientId} After compression: pos={$pos}, remaining=" . (strlen($data) - $pos) . " bytes, hex(32B)=" . bin2hex(substr($data, $pos, min(32, strlen($data) - $pos))) . "\n");

        if ($pos + 2 > strlen($data)) {

            $this->_log_std("Client {$clientId} No extensions (pos={$pos}, totalLen=" . strlen($data) . ")\n");
            return reset($clientSuites) ?? "\x00\x2f";
        }
        $extensionsLenBytes = substr($data, $pos, 2);
        $extensionsLen = unpack('n', $extensionsLenBytes)[1];
        $pos += 2;
        $extEnd = $pos + $extensionsLen;
        $this->_log_std("Client {$clientId} Extensions total len={$extensionsLen} (pos {$pos}..{$extEnd})\n");
        $clientExtNames = [
            0x0000 => 'server_name',
            0x0001 => 'max_fragment_length',
            0x0005 => 'status_request',
            0x000a => 'elliptic_curves',
            0x000b => 'ec_point_formats',
            0x000d => 'signature_algorithms',
            0x000e => 'use_srtp',
            0x000f => 'heartbeat',
            0x0010 => 'alpn',
            0x0012 => 'signed_certificate_timestamp',
            0x0013 => 'client_certificate_type',
            0x0014 => 'server_certificate_type',
            0x0015 => 'padding',
            0x0017 => 'extended_master_secret',
            0x001b => 'client_supported_versions',
            0x0022 => 'encrypt_then_mac',
            0x0023 => 'extended_master_secret?',
            0x0029 => 'client_early_data?',
            0x002b => 'supported_versions',
            0x002d => 'psk_key_exchange_modes',
            0x0033 => 'certificate_authorities',
            0x003a => 'signature_algorithms_cert',
            0x003b => 'supported_signature_algorithms?',
            0x4469 => 'DtlsSrtp?',
            0xff01 => 'renegotiation_info',
        ];
        $foundExtIds = [];
        $clientHasUseSrtp = false;
        $clientSrtpProfiles = [];
        while ($pos + 4 <= $extEnd && $pos + 4 <= strlen($data)) {
            $extType = unpack('n', substr($data, $pos, 2))[1];
            $extDataLen = unpack('n', substr($data, $pos + 2, 2))[1];
            $pos += 4;
            if ($pos + $extDataLen > strlen($data)) break;
            $extData = substr($data, $pos, $extDataLen);
            $name = $clientExtNames[$extType] ?? "UNKNOWN($extType)";
            $dataPreview = $extDataLen <= 16 ? bin2hex($extData) : (bin2hex(substr($extData, 0, 16)) . "... len=$extDataLen");
            $this->_log_std("  ext[0x" . sprintf('%04X', $extType) . " $name] len=$extDataLen data=$dataPreview\n");
            $foundExtIds[] = $extType;

            if ($extType === 0x000e && strlen($extData) >= 3) {
                $clientHasUseSrtp = true;
                $p = 0;
                $protoCount = unpack('n', substr($extData, $p, 2))[1]; $p += 2;
                for ($i = 0; $i < $protoCount && $p + 2 <= strlen($extData); $i++) {
                    $profile = unpack('n', substr($extData, $p, 2))[1]; $p += 2;
                    $clientSrtpProfiles[] = $profile;
                }
                $this->clients[$clientId]['clientSrtpProfiles'] = $clientSrtpProfiles;
                $this->_log_std("  use_srtp profiles: " . implode(', ', array_map(function($x){ return '0x'.sprintf('%04X',$x); }, $clientSrtpProfiles)) . "\n");
            }
            $pos += $extDataLen;
        }

        $this->clients[$clientId]['clientExtIds'] = $foundExtIds;
        $this->clients[$clientId]['clientHasEms'] = in_array(0x0017, $foundExtIds);
        $this->clients[$clientId]['clientHasRenego'] = in_array(0xff01, $foundExtIds);
        $this->clients[$clientId]['clientHasSupportedVersions'] = in_array(0x002b, $foundExtIds);
        $this->clients[$clientId]['clientHasUseSrtp'] = $clientHasUseSrtp;

        foreach ($serverPreference as $pref) {
            foreach ($clientSuites as $cs) {
                if ($cs === $pref) {
                    $this->_log_std("Client {$clientId} Selected cipher suite: 0x" . bin2hex($cs) . " (" . ($serverSupported[$cs] ?? '?') . ")\n");
                    return $cs;
                }
            }
        }

        $this->_log_std("Client {$clientId} No preferred cipher suite matched, fallback AES128-CBC\n");
        return "\x00\x2f";
    }

    /**
     * DTLS 临时椭圆曲线 Diffie-Hellman (ECDHE) 密钥对
     * @param $clientId
     * @return void
     * 生成临时密钥对，确保即使服务端长期证书私钥在未来泄露，攻击者也无法解密本次通话的历史记录
     */
    private function generateECDHEKey($clientId)
    {
        $configPath = __DIR__ . '/certs/openssl.cnf';
        $ecKey = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config' => $configPath
        ]);

        if (!$ecKey) {
            $this->_log_std("Client {$clientId} ECDHE key gen failed: " . openssl_error_string() . "\n");
            return;
        }

        $privPem = '';
        $exported = @openssl_pkey_export($ecKey, $privPem, null, ['config' => $configPath]);
        if ($exported && is_string($privPem) && $privPem !== '') {
            $reimported = @openssl_pkey_get_private($privPem);
            if (is_resource($reimported) || is_object($reimported)) {
                $reDetails = openssl_pkey_get_details($reimported);
                if (isset($reDetails['ec']['x']) && isset($reDetails['ec']['d'])) {
                    $ecKey = $reimported;
                }
            }
        }
        $details = openssl_pkey_get_details($ecKey);
        $hasPriv = isset($details['ec']['d']) && $details['ec']['d'] !== '';
        $this->clients[$clientId]['ecdhKey'] = $ecKey;
        $this->clients[$clientId]['ecdhPublicKey'] = $details['ec']['x'] . $details['ec']['y'];

        $this->_log_std("Client {$clientId} ECDHE key generated, public key len: " . strlen($this->clients[$clientId]['ecdhPublicKey']) . " private_d_set=" . ($hasPriv ? 'YES' : 'NO') . "\n");
    }

    /**
     * DTLS 和客户端交换密钥
     * @param $clientId
     * @param $data
     * @return void
     */
    private function handleClientKeyExchange($clientId, $data)
    {
        $this->_log_std("Client {$clientId} ClientKeyExchange received (len=" . strlen($data) . ")\n");

        $cipherSuite = $this->clients[$clientId]['cipherSuite'] ?? "\x00\x35";
        $cs = bin2hex($cipherSuite);

        $isECDHE = in_array($cs, ['c02f', 'c02b', 'c030', 'c02c', 'cca8', 'cca9', 'c013', 'c014', 'c023', 'c027']);

        if ($isECDHE) {
            if (strlen($data) < 1) {
                $this->_log_std("Client {$clientId} ECDHE ClientKeyExchange too short\n");
                return;
            }

            $pubKeyLen = ord($data[0]);
            $clientPubKey = substr($data, 1, $pubKeyLen);

            $this->_log_std("Client {$clientId} ECDHE public key len={$pubKeyLen}\n");

            $ecdhKey = $this->clients[$clientId]['ecdhKey'] ?? null;
            if (!$ecdhKey) {
                $this->_log_std("Client {$clientId} ECDHE private key not available\n");
                return;
            }

            $x = substr($clientPubKey, 1, 32);
            $y = substr($clientPubKey, 33, 32);

            $this->clients[$clientId]['clientEcPubPoint'] = $clientPubKey;
            $this->clients[$clientId]['clientEcPubX'] = $x;
            $this->clients[$clientId]['clientEcPubY'] = $y;

            $spkiPrefix = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
                . "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04";
            $spkiDer = $spkiPrefix . $x . $y;
            if (strlen($spkiDer) !== 91) {
                $this->_log_std("Client {$clientId} SPKI DER length error: got " . strlen($spkiDer) . " bytes\n");
                return;
            }
            $pemBody = base64_encode($spkiDer);
            $pem = "-----BEGIN PUBLIC KEY-----\n"
                . chunk_split($pemBody, 64, "\n")
                . "-----END PUBLIC KEY-----\n";
            $clientEcKey = openssl_pkey_get_public($pem);
            if (!$clientEcKey) {
                $this->_log_std("Client {$clientId} Failed to load client EC pubkey via PEM: " . openssl_error_string() . "\n");
                return;
            }
            $importedDetails = openssl_pkey_get_details($clientEcKey);
            $ix = $importedDetails['ec']['x'] ?? '';
            $iy = $importedDetails['ec']['y'] ?? '';
            $xMatch = hash_equals($x, $ix);
            $yMatch = hash_equals($y, $iy);
            $this->_log_std("Client {$clientId} PUBKEY IMPORT VERIFY: X_match=" . ($xMatch ? 'YES' : 'NO') . " Y_match=" . ($yMatch ? 'YES' : 'NO') . "\n");
            if (!$xMatch || !$yMatch) {
                $this->_log_std("  * Original X = " . bin2hex($x) . "\n");
                $this->_log_std("  * Imported X = " . bin2hex($ix) . "\n");
                $this->_log_std("  * Original Y = " . bin2hex($y) . "\n");
                $this->_log_std("  * Imported Y = " . bin2hex($iy) . "\n");
                $this->_log_std("  FATAL: EC pubkey mismatch! ECDHE will definitely fail.\n");
            }

            $sharedSecret1 = @openssl_pkey_derive($ecdhKey, $clientEcKey, 32);
            $sharedSecret2 = @openssl_pkey_derive($clientEcKey, $ecdhKey, 32);
            $sharedSecret = false;
            $whichPmsOrder = '';
            if (
                $sharedSecret1 !== false && is_string($sharedSecret1) && strlen($sharedSecret1) === 32
            ) {
                $sharedSecret = $sharedSecret1;
                $whichPmsOrder = 'order=priv_pub (文档顺序';
            } elseif (
                $sharedSecret2 !== false && is_string($sharedSecret2) && strlen($sharedSecret2) === 32
            ) {
                $sharedSecret = $sharedSecret2;
                $whichPmsOrder = 'order=pub_priv (实测顺序)';
            }

            if ($sharedSecret === false) {
                $this->_log_std("Client {$clientId} Failed to derive shared secret (both orders failed)\n");
                return;
            }

            $this->_log_std("Client {$clientId} ECDHE shared secret derived (len=" . strlen($sharedSecret) . ", {$whichPmsOrder})\n");
            $this->_log_std("  ss1 (priv,pub) valid=" . (is_string($sharedSecret1) && strlen($sharedSecret1) === 32 ? 'yes len=' . bin2hex($sharedSecret1) : 'no') . "\n");
            $this->_log_std("  ss2 (pub,priv) valid=" . (is_string($sharedSecret2) && strlen($sharedSecret2) === 32 ? 'yes len=' . strlen($sharedSecret2) : 'no') . "\n");
            if (is_string($sharedSecret1) && is_string($sharedSecret2) && $sharedSecret1 === $sharedSecret2) {
                $this->_log_std("  ss1 === ss2 (两种顺序结果相同，说明两个方向对称)\n");
            } elseif (is_string($sharedSecret1) && is_string($sharedSecret2)) {
                $this->_log_std("  ss1 !== ss2 (两种顺序结果不同!)\n");
                $this->clients[$clientId]['preMasterSecretAlt'] = $sharedSecret2;
            }


            $preMasterSecret = $sharedSecret;
        } else {
            if (strlen($data) < 3) {
                $this->_log_std("Client {$clientId} RSA ClientKeyExchange too short\n");
                return;
            }

            $encryptedLen = unpack('N', "\x00" . substr($data, 0, 3))[1];
            $encryptedPreMasterSecret = substr($data, 3, $encryptedLen);

            $this->_log_std("Client {$clientId} RSA ClientKeyExchange: encryptedLen={$encryptedLen}\n");

            $keyContent = file_get_contents($this->keyPath);
            $privateKey = openssl_pkey_get_private($keyContent);

            if (!$privateKey) {
                $this->_log_std("Client {$clientId} Failed to load private key\n");
                return;
            }

            $preMasterSecret = '';
            $result = openssl_private_decrypt($encryptedPreMasterSecret, $preMasterSecret, $privateKey);

            if (!$result) {
                $this->_log_std("Client {$clientId} Failed to decrypt preMasterSecret\n");
                return;
            }

            $this->_log_std("Client {$clientId} PreMasterSecret decrypted (len=" . strlen($preMasterSecret) . ")\n");
        }

        $clientRandom = $this->clients[$clientId]['clientRandom'] ?? '';
        $serverRandom = $this->clients[$clientId]['serverRandom'] ?? '';

        $this->clients[$clientId]['preMasterSecret'] = $preMasterSecret;

        $cipherSuite = $this->clients[$clientId]['cipherSuite'];
        $cs = bin2hex($cipherSuite);
        $masterHashAlgo = ($cs === 'c02b') ? 'sha384' : 'sha256';

        $msLegacy = $this->tls12PRF($preMasterSecret, "master secret", $clientRandom . $serverRandom, 48, $masterHashAlgo);
        $this->_log_std("Client {$clientId} MS_legacy=" . bin2hex($msLegacy) . "\n");

        $snapTls4 = $this->clients[$clientId]['sessionHashSnapshotTLS4'] ?? ($this->clients[$clientId]['handshakeHash'] ?? '');
        $snapDtls12 = $this->clients[$clientId]['sessionHashSnapshotDTLS12'] ?? ($this->clients[$clientId]['handshakeHashDTLS12'] ?? ($this->clients[$clientId]['handshakeHash'] ?? ''));
        $sessHashTls4 = hash($masterHashAlgo, $snapTls4, true);
        $sessHashDtls12 = hash($masterHashAlgo, $snapDtls12, true);
        $msExtTls4 = $this->tls12PRF($preMasterSecret, "extended master secret", $sessHashTls4, 48, $masterHashAlgo);
        $msExtDtls12 = $this->tls12PRF($preMasterSecret, "extended master secret", $sessHashDtls12, 48, $masterHashAlgo);
        $this->_log_std("Client {$clientId} MS_extTLS4  (snap=" . strlen($snapTls4) . "B h=" . bin2hex($sessHashTls4) . ")=" . bin2hex($msExtTls4) . "\n");
        $this->_log_std("Client {$clientId} MS_extDTLS12(snap=" . strlen($snapDtls12) . "B h=" . bin2hex($sessHashDtls12) . ")=" . bin2hex($msExtDtls12) . "\n");

        $this->clients[$clientId]['masterSecret'] = $msLegacy;
        $this->clients[$clientId]['masterSecretLegacy'] = $msLegacy;
        $this->clients[$clientId]['masterSecretExtendedTLS4'] = $msExtTls4;
        $this->clients[$clientId]['masterSecretExtendedDTLS12'] = $msExtDtls12;
        $this->clients[$clientId]['masterSecretExtended'] = $msExtDtls12;
        $this->clients[$clientId]['masterHashAlgo'] = $masterHashAlgo;

        $this->_log_std("Client {$clientId} MasterSecret computed (legacy + extTLS4 + extDTLS12), waiting for client CCS\n");
    }

    /**
     * DTLS握手完成
     * @param $clientId
     * @param $data
     * @param $clientFinDTLSFull
     * @return void
     */
    private function handleFinished($clientId, $data, $clientFinDTLSFull = null)
    {
        $this->_log_std("Client {$clientId} Finished received (len=" . strlen($data) . ")\n");
        $this->_log_std("Client {$clientId} Finished data hex=" . bin2hex($data) . "\n");

        $clientVerifyData = $data;

        $this->_log_std("Client {$clientId} Client verify data len=" . strlen($clientVerifyData) . "\n");

        $cs = bin2hex($this->clients[$clientId]['cipherSuite']);
        $hashAlgo = ($cs === 'c02b') ? 'sha384' : 'sha256';

        $hhTls4 = $this->clients[$clientId]['handshakeHash'] ?? '';
        $hhDtls12 = $this->clients[$clientId]['handshakeHashDTLS12'] ?? $hhTls4;
        $hashTls4 = hash($hashAlgo, $hhTls4, true);
        $hashDtls12 = hash($hashAlgo, $hhDtls12, true);
        $hashCandidates = [
            'hhTLS4' => $hashTls4,
            'hhDTLS12' => $hashDtls12,
        ];

        $pinnedEnc = $this->clients[$clientId]['encryption'] ?? null;
        $pinnedVariant = $pinnedEnc['variant'] ?? 'unknown';
        $pinnedMs = $pinnedEnc['masterSecret'] ?? null;
        $candidateMsList = [];
        if ($pinnedMs && strlen($pinnedMs) === 48) {
            $candidateMsList['pinned(' . $pinnedVariant . ')'] = $pinnedMs;
        }
        $variants = $this->clients[$clientId]['encryptionVariants'] ?? [];
        foreach ($variants as $vn => $v) {
            if (empty($v['masterSecret']) || strlen($v['masterSecret']) !== 48) continue;
            if (isset($candidateMsList[$vn])) continue;
            $candidateMsList[$vn] = $v['masterSecret'];
        }

        $this->_log_std("Client {$clientId} verify_data: " . count($candidateMsList) . " MS × " . count($hashCandidates) . " hhash = " . (count($candidateMsList) * count($hashCandidates)) . " combos, pinned_variant={$pinnedVariant}\n");
        $this->_log_std("Client {$clientId} hhTLS4 len=" . strlen($hhTls4) . " sha256=" . bin2hex(hash('sha256', $hhTls4, true)) . "\n");
        $this->_log_std("Client {$clientId} hhDTLS12 len=" . strlen($hhDtls12) . " sha256=" . bin2hex(hash('sha256', $hhDtls12, true)) . "\n");

        $matchMs = null;
        $matchName = '';
        $matchedHhashName = '';
        foreach ($candidateMsList as $name => $ms) {
            $found = false;
            foreach ($hashCandidates as $hhName => $hash) {
                $expected = $this->tls12PRF($ms, "client finished", $hash, 12, $hashAlgo);
                if (hash_equals($expected, $clientVerifyData)) {
                    $this->_log_std("Client {$clientId} verify_data MATCH! variant={$name}, hhash={$hhName}\n");
                    $matchMs = $ms;
                    $matchName = $name;
                    $matchedHhashName = $hhName;
                    $found = true;
                    break;
                }
            }
            if ($found) break;
            if ($matchMs === null) {
                $expQuick = $this->tls12PRF($ms, "client finished", $hashTls4, 12, $hashAlgo);
                $this->_log_std("Client {$clientId} variant[{$name}] TLS4_exp=" . bin2hex(substr($expQuick, 0, 6)) . " actual=" . bin2hex(substr($clientVerifyData, 0, 6)) . " (no match)\n");
            }
        }

        if ($matchMs !== null) {
            $this->clients[$clientId]['masterSecret'] = $matchMs;
            $this->clients[$clientId]['matchedHhashName'] = $matchedHhashName;
            if (isset($variants[$matchName])) {
                $this->clients[$clientId]['encryption'] = $variants[$matchName];
            }
            $this->_log_std("Client {$clientId} Master secret finalized via variant={$matchName} / hhash={$matchedHhashName}\n");

            $cr = $this->clients[$clientId]['clientRandom'] ?? '';
            $sr = $this->clients[$clientId]['serverRandom'] ?? '';
            $this->deriveSrtpKeys($clientId, $matchMs, $cr, $sr, $hashAlgo);
        } else {
            $this->_log_std("Client {$clientId} WARNING: verify_data did NOT match any MS×hhash combo, continue with pinned variant={$pinnedVariant}\n");
        }

        $bodyLen = strlen($clientVerifyData);
        if (!isset($len3) || !is_callable($len3)) {
            $len3 = function ($v) {
                return substr(pack('N', $v), 1, 3);
            };
        }
        $tls4Append = "\x14" . $len3($bodyLen) . $clientVerifyData;
        $this->clients[$clientId]['handshakeHash'] = ($this->clients[$clientId]['handshakeHash'] ?? '') . $tls4Append;

        if ($clientFinDTLSFull !== null && strlen($clientFinDTLSFull) > 0) {
            $dtlsAppend = $clientFinDTLSFull;
        } else {
            $fallbackSeq = isset($this->clients[$clientId]['hsSeq']) ? $this->clients[$clientId]['hsSeq'] : 5;
            $dtlsAppend = "\x14" . $len3($bodyLen) . pack('n', $fallbackSeq) . "\x00\x00\x00" . $len3($bodyLen) . $clientVerifyData;
        }
        $this->clients[$clientId]['handshakeHashDTLS12'] = ($this->clients[$clientId]['handshakeHashDTLS12'] ?? '') . $dtlsAppend;
        $this->_log_std("Client {$clientId} Client Finished appended: TLS4 chain +" . strlen($tls4Append) . "B (total " . strlen($this->clients[$clientId]['handshakeHash']) . "B), DTLS12 chain +" . strlen($dtlsAppend) . "B (total " . strlen($this->clients[$clientId]['handshakeHashDTLS12']) . "B)\n");

        $cachedFlight = $this->clients[$clientId]['cachedServerFlight'] ?? [];
        if (empty($cachedFlight)) {
            $this->_log_std("Client {$clientId} Sending server CCS+Finished (flight 4, first time)\n");
            $ccsRecord = $this->buildServerCCSRecord($clientId);
            $this->clients[$clientId]['cachedServerFlight'][] = $ccsRecord;
            $finRecord = $this->buildServerFinishedRecord($clientId);
            $this->clients[$clientId]['cachedServerFlight'][] = $finRecord;
            foreach ($this->clients[$clientId]['cachedServerFlight'] as $r) {
                $this->sendUDP($clientId, $r);
            }
            $this->_log_std("Client {$clientId} Server CCS+Finished sent (total len=" . (strlen($ccsRecord) + strlen($finRecord)) . ")\n");
        } else {
            foreach ($cachedFlight as $r) {
                $this->sendUDP($clientId, $r);
            }
            $this->_log_std("Client {$clientId} Re-sent cached server CCS+Finished (retransmit, unchanged bytes)\n");
        }

        $this->clients[$clientId]['dtlsState'] = 'connected';
        $this->clients[$clientId]['state'] = 'connected';
        $_readyClient = $this->clients[$clientId] ?? [];
        $_readyMeta = is_array($_readyClient['meta'] ?? null) ? $_readyClient['meta'] : [];
        if (($_readyMeta['role'] ?? '') === 'play'
            && !empty($_readyClient['srtpTx'])
            && !empty($_readyClient['remoteCandidate'])
            && method_exists($this, 'kickFaststartForSubscriber')) {
            $this->kickFaststartForSubscriber((int)$clientId);
        }
        $this->_log_std("Client {$clientId} DTLS handshake completed!\n");
        $this->_log_std("Client {$clientId} WebRTC连接建立成功！\n");
    }

    /**
     * DTLS 通知客户端即将切换加密模式
     * @param $clientId
     * @return string
     */
    private function buildServerCCSRecord($clientId)
    {
        $this->clients[$clientId]['dtlsEpoch'] = 0;
        $ccsBody = "\x01";
        $record = $this->createDTLSRecord($clientId, 20, $ccsBody);
        $this->clients[$clientId]['dtlsEpoch'] = 1;
        $this->clients[$clientId]['dtlsSeq'] = 0;
        $this->_log_std("Client {$clientId} Server CCS built (epoch=0), switching to epoch=1/seq=0 for Finished\n");
        return $record;
    }

    /**
     * DTLS 服务端切换加密模式
     * @param $clientId
     * @return string
     */
    private function buildServerFinishedRecord($clientId)
    {
        $masterSecret = $this->clients[$clientId]['masterSecret'] ?? '';
        $hhName = $this->clients[$clientId]['matchedHhashName'] ?? 'hhDTLS12';
        if ($hhName === 'hhTLS4') {
            $handshakeHash = $this->clients[$clientId]['handshakeHash'] ?? '';
        } else {
            $handshakeHash = $this->clients[$clientId]['handshakeHashDTLS12'] ?? ($this->clients[$clientId]['handshakeHash'] ?? '');
        }
        $cs = bin2hex($this->clients[$clientId]['cipherSuite']);
        $hashAlgo = ($cs === 'c02b') ? 'sha384' : 'sha256';

        $hash = hash($hashAlgo, $handshakeHash, true);
        $verifyData = $this->tls12PRF($masterSecret, "server finished", $hash, 12, $hashAlgo);
        $this->clients[$clientId]['serverVerifyData'] = $verifyData;

        $this->_log_std("Client {$clientId} buildServerFinishedRecord: using hhash={$hhName}, server verify_data=" . bin2hex($verifyData) . "\n");
        $this->_log_std("Client {$clientId} buildServerFinishedRecord: handshakeHash({$hhName}) len=" . strlen($handshakeHash) . " sha256=" . bin2hex(hash('sha256', $handshakeHash, true)) . "\n");

        $bodyLen = strlen($verifyData);
        $hsSeq = $this->getNextHandshakeSeq($clientId);

        $finishedMsg = "\x14";
        $finishedMsg .= chr(($bodyLen >> 16) & 0xFF);
        $finishedMsg .= chr(($bodyLen >> 8) & 0xFF);
        $finishedMsg .= chr($bodyLen & 0xFF);
        $finishedMsg .= pack('n', $hsSeq);
        $finishedMsg .= "\x00\x00\x00";
        $finishedMsg .= chr(($bodyLen >> 16) & 0xFF);
        $finishedMsg .= chr(($bodyLen >> 8) & 0xFF);
        $finishedMsg .= chr($bodyLen & 0xFF);
        $finishedMsg .= $verifyData;

        $epoch = $this->clients[$clientId]['dtlsEpoch'] ?? 1;
        $seq = $this->clients[$clientId]['dtlsSeq'] ?? 0;

        $encrypted = $this->encryptDTLSRecord($clientId, $finishedMsg, $epoch, $seq, 0x16);
        $record = $this->createDTLSRecord($clientId, 22, $encrypted);
        $this->_log_std("Client {$clientId} ServerFinished built (epoch={$epoch},seq={$seq},len=" . strlen($record) . ")\n");
        return $record;
    }

    /**
     * 计算主密码
     * @param $clientId
     * @param $preMasterSecret
     * @param $clientRandom
     * @param $serverRandom
     * @param $hashAlgo
     * @return false|string
     */
    private function computeMasterSecret($clientId, $preMasterSecret, $clientRandom, $serverRandom, $hashAlgo = 'sha256')
    {
        $label = "extended master secret";
        $snapshot = $this->clients[$clientId]['sessionHashSnapshot'] ?? ($this->clients[$clientId]['handshakeHash'] ?? '');
        $sessionHash = hash($hashAlgo, $snapshot, true);
        $this->_log_std("Client {$clientId} computeMasterSecret (extended): hashAlgo={$hashAlgo}, snapshotLen=" . strlen($snapshot) . " session_hash=" . bin2hex($sessionHash) . "\n");
        return $this->tls12PRF($preMasterSecret, $label, $sessionHash, 48, $hashAlgo);
    }

    /**
     * DTLS的加密key,iv生成函数，遵循tls规范
     * @param $secret
     * @param $label
     * @param $seed
     * @param $length
     * @param $hashAlgo
     * @return false|string
     */
    private function tls12PRF($secret, $label, $seed, $length, $hashAlgo = 'sha256')
    {
        $labelSeed = $label . $seed;
        $pHash = '';
        $a = $labelSeed;

        while (strlen($pHash) < $length) {
            $a = hash_hmac($hashAlgo, $a, $secret, true);
            $pHash .= hash_hmac($hashAlgo, $a . $labelSeed, $secret, true);
        }

        return substr($pHash, 0, $length);
    }

    /**
     * 获取客户端下次握手序列号
     * @param $clientId
     * @return mixed
     */
    private function getNextHandshakeSeq($clientId)
    {
        if (!isset($this->clients[$clientId]['hsSeq'])) {
            $this->clients[$clientId]['hsSeq'] = 0;
        }
        return $this->clients[$clientId]['hsSeq']++;
    }

    private function computeKeyBlock($masterSecret, $clientRandom, $serverRandom)
    {
        $label = "key expansion";
        $seed = $serverRandom . $clientRandom;
        return $this->tls12PRF($masterSecret, $label, $seed, 136);
    }

    /**
     * RFC 5764 §5.2: 从 DTLS master_secret 派生 SRTP Master Key / Salt。
     *   keying_material = PRF(
     *       master_secret,
     *       "EXTRACTOR-dtls_srtp",
     *       client_random || server_random,
     *       60
     *   );
     *   layout (client = browser; server = 本 PHP)：
     *     client_write_SRTP_master_key  (16B) [0..15]   -> 本端 RX（接收浏览器的 SRTP）
     *     server_write_SRTP_master_key  (16B) [16..31]  -> 本端 TX（发回给浏览器）
     *     client_write_SRTP_master_salt (14B) [32..45]  -> RX salt
     *     server_write_SRTP_master_salt (14B) [46..59]  -> TX salt
     *
     * 本方法只在 (client sent use_srtp) && (握手 master_secret 已确定) && (未 keyed)
     * 的情况下执行；结果存入 clients[clientId] 的 srtpRx / srtpTx / srtpKeyed。
     *
     * @param int    $clientId
     * @param string $masterSecret 48 bytes (TLS master_secret from computeMasterSecret)
     * @param string $clientRandom 32 bytes
     * @param string $serverRandom 32 bytes
     * @param string $hashAlgo     本握手使用的 PRF 哈希（TLS 1.2 = sha256/sha384 匹配 cipher suite PRF）
     * @return bool true = 成功派生并保存；false = 无需派生（客户端未声明 use_srtp 或已 keyed）
     */
    private function deriveSrtpKeys($clientId, $masterSecret, $clientRandom, $serverRandom, $hashAlgo = 'sha256')
    {
        if (empty($this->clients[$clientId]['clientHasUseSrtp'])) {
            return false;
        }
        if (!empty($this->clients[$clientId]['srtpKeyed'])) {
            return false;
        }
        if (!is_string($masterSecret) || strlen($masterSecret) !== 48) {
            $this->_log_std("Client {$clientId} deriveSrtpKeys: SKIP bad master_secret len=" . (is_string($masterSecret) ? strlen($masterSecret) : '?') . "\n");
            return false;
        }
        if (!is_string($clientRandom) || strlen($clientRandom) !== 32 || !is_string($serverRandom) || strlen($serverRandom) !== 32) {
            $this->_log_std("Client {$clientId} deriveSrtpKeys: SKIP bad CR/SR length\n");
            return false;
        }

        $seed = $clientRandom . $serverRandom;
        try {
            $mat = $this->tls12PRF($masterSecret, "EXTRACTOR-dtls_srtp", $seed, 60, $hashAlgo);
        } catch (\Throwable $e) {
            $this->_log_std("Client {$clientId} deriveSrtpKeys: PRF EXCEPTION " . $e->getMessage() . "\n");
            return false;
        }
        if (!is_string($mat) || strlen($mat) !== 60) {
            $this->_log_std("Client {$clientId} deriveSrtpKeys: PRF returned bad mat_len=" . (is_string($mat)?strlen($mat):'null') . "\n");
            return false;
        }
        $clientMK = substr($mat,  0, 16);
        $serverMK = substr($mat, 16, 16);
        $clientMS = substr($mat, 32, 14);
        $serverMS = substr($mat, 46, 14);
        try {

            $rx = new \Xiaosongshu\Webrtc\Core\Srtp($clientMK, $clientMS);
            $tx = new \Xiaosongshu\Webrtc\Core\Srtp($serverMK, $serverMS);
        } catch (\Throwable $e) {
            $this->_log_std("Client {$clientId} SRTP ctx init failed: " . $e->getMessage() . "\n");
            return false;
        }

        $clientIdLocal = $clientId;
        $rx->logger = function (string $msg) use ($clientIdLocal) {
            $this->_log_std("Client {$clientIdLocal} SRTP " . $msg);
        };
        $tx->logger = function (string $msg) use ($clientIdLocal) {
            $this->_log_std("Client {$clientIdLocal} SRTP " . $msg);
        };
        $this->clients[$clientId]['srtpRx']      = $rx;
        $this->clients[$clientId]['srtpTx']      = $tx;
        $this->clients[$clientId]['srtpKeyed']   = true;
        $this->clients[$clientId]['srtpHashAlgo']= $hashAlgo;
        $this->_log_std("Client {$clientId} SRTP keys derived via RFC 5764 EXTRACTOR (60B OK) algo={$hashAlgo}\n");
        $this->_log_std("Client {$clientId} SRTP rx_key=" . bin2hex($clientMK) . " rx_salt=" . bin2hex($clientMS) . "\n");
        $this->_log_std("Client {$clientId} SRTP tx_key=" . bin2hex($serverMK) . " tx_salt=" . bin2hex($serverMS) . "\n");
        return true;
    }

    /**
     * 无参 wrapper（与 server.php deriveSrtpKeysRfc5764 接口对齐）：
     *   从 clients[$clientId] 读取 encryption.masterSecret / clientRandom / serverRandom / cipherSuite → PRF hashAlgo，
     *   调用 deriveSrtpKeys 派生。UDP SRTP 收到包但 key 未就绪时可按需调用，避免丢首批媒体包。
     *
     * @param int $clientId
     * @return bool
     */
    private function deriveSrtpKeysRfc5764($clientId)
    {
        if (empty($this->clients[$clientId]['clientHasUseSrtp'])) return false;
        if (!empty($this->clients[$clientId]['srtpKeyed']))       return false;
        $enc = $this->clients[$clientId]['encryption'] ?? null;
        $ms  = null;
        if ($enc && !empty($enc['masterSecret']) && strlen($enc['masterSecret']) === 48) {
            $ms = $enc['masterSecret'];
        } elseif (!empty($this->clients[$clientId]['masterSecret']) && strlen($this->clients[$clientId]['masterSecret']) === 48) {
            $ms = $this->clients[$clientId]['masterSecret'];
        }
        if ($ms === null) return false;
        $cr = $this->clients[$clientId]['clientRandom'] ?? '';
        $sr = $this->clients[$clientId]['serverRandom'] ?? '';
        if (strlen($cr) !== 32 || strlen($sr) !== 32) return false;
        $cs = $this->clients[$clientId]['cipherSuite'] ?? "\x00\x2f";
        $csHex = is_string($cs) ? bin2hex($cs) : '';
        $hashAlgo = ($csHex === 'c02b') ? 'sha384' : 'sha256';
        return $this->deriveSrtpKeys($clientId, $ms, $cr, $sr, $hashAlgo);
    }

    /**
     * DTLS 服务端发送hello给客户端
     * @param $clientId
     * @param $cipherSuite
     * @return void
     * @throws \Random\RandomException
     */
    private function sendServerHello($clientId, $cipherSuite)
    {
        $random = random_bytes(32);
        $sessionId = $this->clients[$clientId]['sessionId'] ?? '';
        $sessionIdLen = strlen($sessionId);

        $this->clients[$clientId]['serverRandom'] = $random;

        $compression = "\x00";

        $clientHasEms = $this->clients[$clientId]['clientHasEms'] ?? false;
        $clientHasRenego = $this->clients[$clientId]['clientHasRenego'] ?? false;
        $clientHasUseSrtp = !empty($this->clients[$clientId]['clientHasUseSrtp']);

        $extensions = '';
        if ($clientHasEms) {
            $extensions .= "\x00\x17\x00\x00";
        }

        if ($clientHasUseSrtp) {

            $srtpPayload = "\x00\x02"
                         . "\x00\x01"
                         . "\x00";
            $extensions .= "\x00\x0e" . pack('n', strlen($srtpPayload)) . $srtpPayload;
        }

        $extensions .= "\xff\x01\x00\x01\x00";
        $extensionsLen = strlen($extensions);

        $this->_log_std("Client {$clientId} ServerHello extensions build: ems=" . ($clientHasEms ? 'yes' : 'no') . " use_srtp=" . ($clientHasUseSrtp ? 'yes(0x0001 AES128_CM_SHA1_80)' : 'no') . " renego=" . ($clientHasRenego ? 'yes' : 'yes(default)') . " sv=skip(DTLS 1.2)\n");
        $this->_log_std("Client {$clientId} Extensions hex: " . bin2hex($extensions) . ", len={$extensionsLen}\n");

        $clientVersion = $this->clients[$clientId]['clientVersion'] ?? "\x03\x03";
        $body = $clientVersion;
        $body .= $random;
        $body .= chr($sessionIdLen);
        $body .= $sessionId;
        $body .= $cipherSuite;
        $body .= $compression;
        $body .= chr($extensionsLen >> 8);
        $body .= chr($extensionsLen & 0xFF);
        $body .= $extensions;

        $bodyLen = strlen($body);
        $seq = $this->getNextHandshakeSeq($clientId);

        $dtlsMsg = "\x02";
        $dtlsMsg .= chr(($bodyLen >> 16) & 0xFF);
        $dtlsMsg .= chr(($bodyLen >> 8) & 0xFF);
        $dtlsMsg .= chr($bodyLen & 0xFF);
        $dtlsMsg .= pack('n', $seq);
        $dtlsMsg .= "\x00\x00\x00";
        $dtlsMsg .= chr(($bodyLen >> 16) & 0xFF);
        $dtlsMsg .= chr(($bodyLen >> 8) & 0xFF);
        $dtlsMsg .= chr($bodyLen & 0xFF);
        $dtlsMsg .= $body;

        $this->_appendToBothHandshakeHashes($clientId, 0x02, $bodyLen, $seq, $body, "ServerHello");

        $record = $this->createDTLSRecord($clientId, 22, $dtlsMsg);
        $this->clients[$clientId]['pendingRecords'][] = $record;
        $this->_log_std("Client {$clientId} ServerHello appended (len=" . strlen($dtlsMsg) . ", cipher=0x" . bin2hex($cipherSuite) . ")\n");
    }


    /**
     * 发送密钥
     * @param $clientId
     * @return void
     */
    private function sendCertificate($clientId)
    {
        if (!file_exists($this->certPath)) return;

        $certPem = file_get_contents($this->certPath);
        $certDer = '';
        $lines = explode("\n", $certPem);
        foreach ($lines as $line) {
            if ($line && !preg_match('/^-----/', $line)) {
                $certDer .= trim($line);
            }
        }
        $certDer = base64_decode($certDer);

        $fingerprint = strtoupper(chunk_split(bin2hex(hash('sha256', $certDer, true)), 2, ':'));
        $this->_log_std("Client {$clientId} Certificate fingerprint: " . rtrim($fingerprint, ':') . "\n");

        $certLen = strlen($certDer);
        $listLen = $certLen + 3;
        $bodyLen = $listLen + 3;

        $body = chr(($listLen >> 16) & 0xFF);
        $body .= chr(($listLen >> 8) & 0xFF);
        $body .= chr($listLen & 0xFF);
        $body .= chr(($certLen >> 16) & 0xFF);
        $body .= chr(($certLen >> 8) & 0xFF);
        $body .= chr($certLen & 0xFF);
        $body .= $certDer;

        $seq = $this->getNextHandshakeSeq($clientId);

        $dtlsMsg = "\x0B";
        $dtlsMsg .= chr(($bodyLen >> 16) & 0xFF);
        $dtlsMsg .= chr(($bodyLen >> 8) & 0xFF);
        $dtlsMsg .= chr($bodyLen & 0xFF);
        $dtlsMsg .= pack('n', $seq);
        $dtlsMsg .= "\x00\x00\x00";
        $dtlsMsg .= chr(($bodyLen >> 16) & 0xFF);
        $dtlsMsg .= chr(($bodyLen >> 8) & 0xFF);
        $dtlsMsg .= chr($bodyLen & 0xFF);
        $dtlsMsg .= $body;

        $this->_appendToBothHandshakeHashes($clientId, 0x0B, $bodyLen, $seq, $body, "Certificate");
        $_hhTls4 = $this->clients[$clientId]['handshakeHash'];
        $_hhDtls = $this->clients[$clientId]['handshakeHashDTLS12'];
        $this->_log_std("Client {$clientId} Certificate DTLS SHA256(whole append DTLS12)=" . bin2hex(hash('sha256', substr($_hhDtls, -strlen($dtlsMsg)), true)) . " (first 16 hex=" . bin2hex(substr($dtlsMsg, 0, 16)) . ")\n");

        $record = $this->createDTLSRecord($clientId, 22, $dtlsMsg);
        $this->clients[$clientId]['pendingRecords'][] = $record;
        $this->_log_std("Client {$clientId} Certificate appended (len=" . strlen($dtlsMsg) . ", hhTLS4=" . strlen($_hhTls4) . "B hhDTLS12=" . strlen($_hhDtls) . "B)\n");
    }

    /**
     * DTLS 服务端更换key
     * @param $clientId
     * @return void
     */
    private function sendServerKeyExchange($clientId)
    {
        $ecdhPublicKey = $this->clients[$clientId]['ecdhPublicKey'] ?? '';
        if (empty($ecdhPublicKey)) {
            $this->_log_std("Client {$clientId} ECDHE public key not available\n");
            return;
        }

        $curveType = "\x03";
        $namedCurve = "\x00\x17";
        $pubKeyLen = chr(strlen($ecdhPublicKey) + 1);
        $pubKeyData = "\x04" . $ecdhPublicKey;

        $ecParams = $curveType . $namedCurve . $pubKeyLen . $pubKeyData;

        $clientRandom = $this->clients[$clientId]['clientRandom'] ?? '';
        $serverRandom = $this->clients[$clientId]['serverRandom'] ?? '';
        $toSign = $clientRandom . $serverRandom . $ecParams;

        $keyContent = file_get_contents($this->keyPath);
        $privateKey = openssl_pkey_get_private($keyContent);

        if (!$privateKey) {
            $this->_log_std("Client {$clientId} Failed to load private key for signing\n");
            return;
        }

        $cipherSuite = $this->clients[$clientId]['cipherSuite'] ?? '';
        $csHex = bin2hex($cipherSuite);
        $hashAlgo = OPENSSL_ALGO_SHA256;
        if (in_array($csHex, ['c02b', 'c030'])) {
            $hashAlgo = OPENSSL_ALGO_SHA384;
        }
        $this->_log_std("Client {$clientId} Using hash algorithm for signature: " . ($hashAlgo == OPENSSL_ALGO_SHA256 ? 'SHA256' : 'SHA384') . "\n");

        $signature = '';
        openssl_sign($toSign, $signature, $privateKey, $hashAlgo);

        $sigLen = strlen($signature);
        $sigLenBytes = pack('n', $sigLen);

        if ($hashAlgo == OPENSSL_ALGO_SHA256) {
            $sigAlgo = "\x04\x01";
        } else {
            $sigAlgo = "\x05\x01";
        }

        $body = $ecParams . $sigAlgo . $sigLenBytes . $signature;
        $bodyLen = strlen($body);

        $seq = $this->getNextHandshakeSeq($clientId);

        $dtlsMsg = "\x0C";
        $dtlsMsg .= chr(($bodyLen >> 16) & 0xFF);
        $dtlsMsg .= chr(($bodyLen >> 8) & 0xFF);
        $dtlsMsg .= chr($bodyLen & 0xFF);
        $dtlsMsg .= pack('n', $seq);
        $dtlsMsg .= "\x00\x00\x00";
        $dtlsMsg .= chr(($bodyLen >> 16) & 0xFF);
        $dtlsMsg .= chr(($bodyLen >> 8) & 0xFF);
        $dtlsMsg .= chr($bodyLen & 0xFF);
        $dtlsMsg .= $body;

        $this->_appendToBothHandshakeHashes($clientId, 0x0C, $bodyLen, $seq, $body, "ServerKeyExchange");
        $_hhTls4 = $this->clients[$clientId]['handshakeHash'];
        $_hhDtls = $this->clients[$clientId]['handshakeHashDTLS12'];
        $this->_log_std("Client {$clientId} ServerKeyExchange DTLS SHA256(whole append DTLS12)=" . bin2hex(hash('sha256', substr($_hhDtls, -strlen($dtlsMsg)), true)) . " (first 16 hex=" . bin2hex(substr($dtlsMsg, 0, 16)) . ")\n");

        $record = $this->createDTLSRecord($clientId, 22, $dtlsMsg);
        $this->clients[$clientId]['pendingRecords'][] = $record;
        $this->_log_std("Client {$clientId} ServerKeyExchange appended (len=" . strlen($dtlsMsg) . ", sigLen={$sigLen}, hhTLS4=" . strlen($_hhTls4) . "B hhDTLS12=" . strlen($_hhDtls) . "B)\n");
    }

    /**
     * 服务端握手完成发送hello done
     * @param $clientId
     * @return void
     */
    private function sendServerHelloDone($clientId)
    {
        $bodyLen = 0;
        $body = '';
        $seq = $this->getNextHandshakeSeq($clientId);

        $dtlsMsg = "\x0E";
        $dtlsMsg .= "\x00\x00\x00";
        $dtlsMsg .= pack('n', $seq);
        $dtlsMsg .= "\x00\x00\x00";
        $dtlsMsg .= "\x00\x00\x00";
        $dtlsMsg .= $body;

        $this->_appendToBothHandshakeHashes($clientId, 0x0E, $bodyLen, $seq, $body, "ServerHelloDone");

        $this->clients[$clientId]['sessionHashSnapshotTLS4'] = $this->clients[$clientId]['handshakeHash'];
        $this->clients[$clientId]['sessionHashSnapshotDTLS12'] = $this->clients[$clientId]['handshakeHashDTLS12'];

        $this->clients[$clientId]['sessionHashSnapshot'] = $this->clients[$clientId]['handshakeHashDTLS12'];
        $_snapTls4 = $this->clients[$clientId]['sessionHashSnapshotTLS4'];
        $_snapDtls = $this->clients[$clientId]['sessionHashSnapshotDTLS12'];
        $this->_log_std("Client {$clientId} sessionHashSnapshotTLS4 saved @ServerHelloDone (len=" . strlen($_snapTls4) . " sha256=" . bin2hex(hash('sha256', $_snapTls4, true)) . ")\n");
        $this->_log_std("Client {$clientId} sessionHashSnapshotDTLS12 saved @ServerHelloDone (len=" . strlen($_snapDtls) . " sha256=" . bin2hex(hash('sha256', $_snapDtls, true)) . ")\n");

        $record = $this->createDTLSRecord($clientId, 22, $dtlsMsg);
        $this->clients[$clientId]['pendingRecords'][] = $record;
        $this->_log_std("Client {$clientId} ServerHelloDone appended\n");
    }


    private function sendChangeCipherSpec($clientId, $returnBytes = false)
    {

        if (!isset($this->clients[$clientId]['dtlsEpoch'])) {
            $this->clients[$clientId]['dtlsEpoch'] = 0;
        }
        $this->clients[$clientId]['dtlsEpoch'] = 0;

        $ccs = "\x01";
        $record = $this->createDTLSRecord($clientId, 20, $ccs);
        if ($returnBytes) {
            $this->sendUDP($clientId, $record);
            $this->_log_std("Client {$clientId} ChangeCipherSpec sent (epoch=0)\n");
            $this->clients[$clientId]['dtlsEpoch'] = 1;
            $this->clients[$clientId]['dtlsSeq'] = 0;
            return $record;
        }
        $this->sendUDP($clientId, $record);
        $this->_log_std("Client {$clientId} ChangeCipherSpec sent (epoch=0)\n");
        $this->clients[$clientId]['dtlsEpoch'] = 1;
        $this->clients[$clientId]['dtlsSeq'] = 0;
    }

    private function sendFinished($clientId, $returnBytes = false)
    {
        $masterSecret = $this->clients[$clientId]['masterSecret'] ?? '';
        $hhName = $this->clients[$clientId]['matchedHhashName'] ?? 'hhDTLS12';
        if ($hhName === 'hhTLS4') {
            $handshakeHash = $this->clients[$clientId]['handshakeHash'] ?? '';
        } else {
            $handshakeHash = $this->clients[$clientId]['handshakeHashDTLS12'] ?? ($this->clients[$clientId]['handshakeHash'] ?? '');
        }

        if (empty($masterSecret) || empty($handshakeHash)) {
            $this->_log_std("Client {$clientId} Cannot send Finished: missing masterSecret or handshakeHash\n");
            return $returnBytes ? '' : null;
        }

        $cs = bin2hex($this->clients[$clientId]['cipherSuite']);
        $hashAlgo = ($cs === 'c02b') ? 'sha384' : 'sha256';
        $hash = hash($hashAlgo, $handshakeHash, true);
        $verifyData = $this->tls12PRF($masterSecret, "server finished", $hash, 12, $hashAlgo);
        $this->clients[$clientId]['serverVerifyData'] = $verifyData;
        $this->_log_std("Client {$clientId} sendFinished: using hhash={$hhName}, handshakeHash len=" . strlen($handshakeHash) . " sha256=" . bin2hex(hash('sha256', $handshakeHash, true)) . "\n");
        $this->_log_std("Client {$clientId} sendFinished: masterSecret len=" . strlen($masterSecret) . " sha256=" . bin2hex(hash('sha256', $masterSecret, true)) . "\n");
        $this->_log_std("Client {$clientId} sendFinished: hash(" . $hashAlgo . ") of hs=" . bin2hex($hash) . "\n");
        $this->_log_std("Client {$clientId} sendFinished: server verify_data=" . bin2hex($verifyData) . "\n");

        $finishedBody = $verifyData;

        $bodyLen = strlen($finishedBody);
        $hsSeq = $this->getNextHandshakeSeq($clientId);

        $finishedMsg = "\x14";
        $finishedMsg .= chr(($bodyLen >> 16) & 0xFF);
        $finishedMsg .= chr(($bodyLen >> 8) & 0xFF);
        $finishedMsg .= chr($bodyLen & 0xFF);
        $finishedMsg .= pack('n', $hsSeq);
        $finishedMsg .= "\x00\x00\x00";
        $finishedMsg .= chr(($bodyLen >> 16) & 0xFF);
        $finishedMsg .= chr(($bodyLen >> 8) & 0xFF);
        $finishedMsg .= chr($bodyLen & 0xFF);
        $finishedMsg .= $finishedBody;

        $epoch = $this->clients[$clientId]['dtlsEpoch'] ?? 1;
        $seq = $this->clients[$clientId]['dtlsSeq'] ?? 0;
        $encrypted = $this->encryptDTLSRecord($clientId, $finishedMsg, $epoch, $seq, 0x16);

        $enc = $this->clients[$clientId]['encryption'];
        $sfKey = $enc['serverWriteKey'];
        $sfIV = $enc['serverWriteIV'];
        $sfNE = substr($encrypted, 0, 8);
        $sfCip = substr($encrypted, 8, -16);
        $sfTag = substr($encrypted, -16);
        $sfNonce = $sfIV . $sfNE;
        $sfAD = $sfNE . chr(0x16) . "\xFE\xFD" . pack('n', strlen($finishedMsg));
        $sfDec = openssl_decrypt($sfCip, $enc['cipherAlgo'], $sfKey, OPENSSL_RAW_DATA, $sfNonce, $sfTag, $sfAD);
        $sfOk = ($sfDec === $finishedMsg) ? 'PASS' : 'FAIL (got ' . @strlen($sfDec) . ' vs ' . strlen($finishedMsg) . ')';
        $this->_log_std("Client {$clientId} ServerFinished SELF_DECRYPT: $sfOk\n");
        $this->_log_std("  plain_finished=" . bin2hex($finishedMsg) . "\n");
        $this->_log_std("  serverWriteKey=" . bin2hex($sfKey) . " serverWriteIV=" . bin2hex($sfIV) . "\n");

        $record = $this->createDTLSRecord($clientId, 22, $encrypted);
        $sfRecHeader = bin2hex(substr($record, 0, 13));
        $this->_log_std("  ServerFinished DTLS header(13B)=$sfRecHeader nonce_explicit=" . bin2hex($sfNE) . "\n");

        if ($returnBytes) {
            $this->sendUDP($clientId, $record);
            $this->_log_std("Client {$clientId} Finished sent (encrypted, len=" . strlen($record) . ")\n");

            $this->clients[$clientId]['dtlsState'] = 'connected';
            $this->clients[$clientId]['state'] = 'connected';
            $this->_log_std("Client {$clientId} WebRTC连接建立成功！\n");
            return $record;
        }
        $this->sendUDP($clientId, $record);
        $this->_log_std("Client {$clientId} Finished sent (encrypted, len=" . strlen($record) . ")\n");

        $this->clients[$clientId]['dtlsState'] = 'connected';
        $this->clients[$clientId]['state'] = 'connected';
        $this->_log_std("Client {$clientId} WebRTC连接建立成功！\n");
    }

    /**
     * 构建DTLS
     * @param $clientId
     * @param $contentType
     * @param $fragment
     * @return string
     */
    private function createDTLSRecord($clientId, $contentType, $fragment)
    {
        if (!isset($this->clients[$clientId]['dtlsEpoch'])) {
            $this->clients[$clientId]['dtlsEpoch'] = 0;
        }
        if (!isset($this->clients[$clientId]['dtlsSeq'])) {
            $this->clients[$clientId]['dtlsSeq'] = 0;
        }

        $epoch = $this->clients[$clientId]['dtlsEpoch'];
        $seq = $this->clients[$clientId]['dtlsSeq'];

        $seqBytes = '';
        for ($i = 5; $i >= 0; $i--) {
            $seqBytes .= chr(($seq >> ($i * 8)) & 0xFF);
        }

        $this->clients[$clientId]['dtlsSeq']++;

        $record = chr($contentType);
        $record .= "\xFE\xFD";
        $record .= pack('n', $epoch);
        $record .= $seqBytes;
        $record .= pack('n', strlen($fragment));
        $record .= $fragment;
        return $record;
    }
}