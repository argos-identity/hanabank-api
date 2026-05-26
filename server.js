/**
 * Hanabank Proxy Server (Pure Node.js)
 *
 * Implements Hanabank OpenAPI 예금주성명조회 (Account Holder Name Check) per
 * "[OpenAPI]_개발가이드_은행_예금주성명조회_v1.0" guide.
 *
 * Crypto spec (from guide):
 *   - Algorithm: AES-256-CBC with PKCS5/PKCS7 padding
 *   - Key:       UTF-8 bytes of (ENC_KEY + ENTR_CD + "@@"), must be 32 bytes
 *   - Output:    Base64( salt(20) ‖ IV(16) ‖ ciphertext )
 *
 * Authorization header:
 *   "bearer " + aes256Encrypt(access_token + ":" + unixTime + ":" + clientId)
 *   Valid for 15 seconds from unixTime.
 *
 * encAccountNo body field:
 *   aes256Encrypt(accountNumber)
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;

const TOKEN_URL          = process.env.TOKEN_URL;
const NAMECHECK_URL_LIVE = process.env.NAMECHECK_URL_LIVE;
const NAMECHECK_URL_DEV  = process.env.NAMECHECK_URL_DEV;
const CLIENT_ID          = process.env.CLIENT_ID;
const CLIENT_SECRET      = process.env.CLIENT_SECRET;
const APP_KEY_LIVE       = process.env.APP_KEY_LIVE;
const APP_KEY            = process.env.APP_KEY;
const ENTRCD             = process.env.ENTRCD;
const ENC_KEY            = process.env.ENC_KEY;

const RESULT_MESSAGES = {
    '0000': '조회 성공',
    '0001': '계좌 정보 없음',
    '0002': '은행 코드 오류',
    '0003': '계좌번호 형식 오류',
    '0100': '인증 오류',
    '0200': '서비스 일시 중단',
    '9999': '시스템 오류',
};

function buildEncKey() {
    const assembled = `${ENC_KEY}${ENTRCD}@@`;
    const keyBuf = Buffer.from(assembled, 'utf-8');
    if (keyBuf.length !== 32) {
        throw new Error(
            `Assembled encKey must be 32 bytes for AES-256, got ${keyBuf.length} bytes. ` +
            `(ENC_KEY="${ENC_KEY}" + ENTR_CD="${ENTRCD}" + "@@")`
        );
    }
    return keyBuf;
}

function aes256Encrypt(plaintext, keyBuf = buildEncKey()) {
    const salt = crypto.randomBytes(20);
    const iv   = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuf, iv);
    const ct = Buffer.concat([
        cipher.update(plaintext, 'utf-8'),
        cipher.final(),
    ]);
    return Buffer.concat([salt, iv, ct]).toString('base64');
}

function pickEnvironment() {
    return {
        isLive: true,
        nameCheckUrl: NAMECHECK_URL_LIVE,
        appKey:       APP_KEY_LIVE,
        clntIpAddr:   '3.37.80.178',
    };
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({ origin: '*' }));

async function fetchAccessToken() {
    const body = new URLSearchParams({
        grant_type:    'client_credentials',
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
    });
    const { data } = await axios.post(TOKEN_URL, body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 10000,
    });
    const token = data?.access_token ?? data?.accessToken ?? data;
    if (!token || typeof token !== 'string') {
        throw new Error(`Unexpected token response: ${JSON.stringify(data)}`);
    }
    return token;
}

function generateAuthorization(accessToken, keyBuf) {
    const unixTime = Math.floor(Date.now() / 1000);
    const stringToken = `${accessToken}:${unixTime}:${CLIENT_ID}`;
    return `bearer ${aes256Encrypt(stringToken, keyBuf)}`;
}

function buildNameCheckRequest({ bankCode, encryptedAccountNo, clntIpAddr, isLive }) {
    return {
        dataHeader: {
            CLNT_IP_ADDR: clntIpAddr,
            CNTY_CD: 'kr',
            ENTR_CD: ENTRCD,
            ...(isLive ? {} : { DEV_CD: 'T' }),
        },
        dataBody: {
            accountHolderBankCd: bankCode.toString(),
            encAccountNo: encryptedAccountNo,
            transactionAmount: 1,
        },
    };
}

function buildNameCheckHeaders({ authorization, appKey }) {
    return {
        Authorization: authorization,
        ENTR_CD: ENTRCD,
        APP_KEY: appKey,
        ENC_NEW: 'Y',
        Accept: 'application/json',
        'Content-Type': 'application/json;charset=UTF-8',
    };
}

app.get('/', (req, res) => {
    res.send('Success called (GET)');
});

app.get('/health', (req, res) => {
    try {
        const keyBuf = buildEncKey();
        res.json({
            status: 'ok',
            crypto: 'AES-256-CBC',
            encKeyLength: keyBuf.length,
            hasTokenUrl: !!TOKEN_URL,
            hasClientId: !!CLIENT_ID,
        });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

/**
 * POST /nameCheck
 * Body: { bankCode: string, accountNumber: string }
 * Response: { accountHolder, resultCode, verification, meta }
 *
 * Always calls Hanabank live (production) API.
 */
app.post('/nameCheck', async (req, res) => {
    console.log('[nameCheck] 요청 수신:', req.body);
    const { bankCode, accountNumber } = req.body;

    if (!bankCode || !accountNumber) {
        return res.status(400).json({
            error: true,
            code: 'MISSING_PARAMS',
            message: 'bankCode, accountNumber 는 필수입니다.',
        });
    }

    let keyBuf;
    try {
        keyBuf = buildEncKey();
    } catch (err) {
        console.error('[nameCheck] encKey 조립 실패:', err.message);
        return res.status(500).json({
            error: true,
            code: 'CONFIG_ERROR',
            message: err.message,
            verification: false,
        });
    }

    const env = pickEnvironment();

    let accessToken;
    try {
        console.log('[nameCheck] Step 1: OAuth token 발급');
        accessToken = await fetchAccessToken();
        console.log('[nameCheck] accessToken:', accessToken);
    } catch (err) {
        console.error('[nameCheck] token 발급 실패:', err.message);
        return res.status(500).json({
            error: true,
            code: 'TOKEN_FAILED',
            message: err.message,
            verification: false,
        });
    }

    let authorization, encryptedAccountNo;
    try {
        console.log('[nameCheck] Step 2: Authorization 생성 + 계좌번호 암호화');
        authorization      = generateAuthorization(accessToken, keyBuf);
        encryptedAccountNo = aes256Encrypt(accountNumber, keyBuf);
        console.log('[nameCheck] authorization:', authorization);
        console.log('[nameCheck] encryptedAccountNo:', encryptedAccountNo);
    } catch (err) {
        console.error('[nameCheck] 암호화 실패:', err.message);
        return res.status(500).json({
            error: true,
            code: 'ENCRYPT_FAILED',
            message: err.message,
            verification: false,
        });
    }

    const requestBody = buildNameCheckRequest({
        bankCode,
        encryptedAccountNo,
        clntIpAddr: env.clntIpAddr,
        isLive: env.isLive,
    });
    const headers = buildNameCheckHeaders({ authorization, appKey: env.appKey });

    try {
        console.log('[nameCheck] Step 3: 하나은행 API 호출', env.nameCheckUrl);
        console.log('[nameCheck] requestBody:', JSON.stringify(requestBody));

        const result = await axios.post(env.nameCheckUrl, requestBody, {
            headers,
            timeout: 30000,
        });
        const { dataHeader, dataBody } = result.data;

        const resultCode    = dataBody?.RSP_CD ?? dataHeader?.GW_RSLT_CD ?? null;
        const accountHolder = dataBody?.accountHolderName ?? null;
        const verification  = resultCode === '0000' && !!accountHolder;

        console.log('[nameCheck] 완료 resultCode:', resultCode, 'accountHolder:', accountHolder);
        return res.json({
            accountHolder,
            resultCode,
            verification,
            meta: {
                bankCode,
                resultMessage: RESULT_MESSAGES[resultCode] ?? `알 수 없는 응답코드 (${resultCode})`,
                gwResultCode:  dataHeader?.GW_RSLT_CD,
                gwResultMsg:   dataHeader?.GW_RSLT_MSG,
            },
        });
    } catch (err) {
        console.error('[nameCheck] 하나은행 API 오류:', err.message);
        const status = err.response?.status;
        const data   = err.response?.data;
        return res.status(500).json({
            error: true,
            code: 'BANK_API_ERROR',
            message: err.message,
            verification: false,
            details: { status, data },
        });
    }
});

app.listen(PORT, () => {
    console.log(`Hanabank proxy server (pure Node.js) running on port ${PORT}`);
    try {
        const keyBuf = buildEncKey();
        console.log(`✓ Crypto ready: AES-256-CBC, encKey ${keyBuf.length} bytes`);
    } catch (err) {
        console.error(`✗ Crypto config error: ${err.message}`);
    }
});
