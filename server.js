/**
 * Hanabank Proxy Server
 *
 * Architecture: [Client] → [Node :3002] → [Java crypto server :8080] → [Hanabank API]
 *
 * The Java server handles Hanabank SDK calls (token/auth signing/account encryption)
 * because the SDK is closed-source and only provided as a Java implementation.
 * This proxy receives client requests, delegates the 3 crypto steps to the Java
 * server, then calls the Hanabank name-check API.
 */

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;

const JAVA_URL           = process.env.JAVA_URL           || 'http://3.37.80.178:8080';
const NAMECHECK_URL_LIVE = process.env.NAMECHECK_URL_LIVE;
const NAMECHECK_URL_DEV  = process.env.NAMECHECK_URL_DEV;
const APP_KEY_LIVE       = process.env.APP_KEY_LIVE;
const APP_KEY            = process.env.APP_KEY;
const ENTRCD             = process.env.ENTRCD;

const RESULT_MESSAGES = {
    '0000': '조회 성공',
    '0001': '계좌 정보 없음',
    '0002': '은행 코드 오류',
    '0003': '계좌번호 형식 오류',
    '0100': '인증 오류',
    '0200': '서비스 일시 중단',
    '9999': '시스템 오류',
};

function pickEnvironment(alias) {
    const isLive = alias === 'live';
    return {
        isLive,
        nameCheckUrl: isLive ? NAMECHECK_URL_LIVE : NAMECHECK_URL_DEV,
        appKey:       isLive ? APP_KEY_LIVE       : APP_KEY,
        clntIpAddr:   isLive ? '3.37.80.178'      : '3.35.147.100',
    };
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({ origin: '*' }));

async function fetchAccessToken() {
    const { data } = await axios.get(`${JAVA_URL}/gettoken`, { timeout: 10000 });
    return data;
}

async function generateAuthAndEncryptAccount(accessToken, accountNumber) {
    const [authRes, encRes] = await Promise.all([
        axios.post(`${JAVA_URL}/gen-auth`, { token: accessToken }, {
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            timeout: 10000,
        }),
        axios.post(`${JAVA_URL}/encrypt-account`, accountNumber, {
            headers: { 'Content-Type': 'text/plain' },
            timeout: 10000,
        }),
    ]);
    return {
        authorization:      authRes.data,
        encryptedAccountNo: encRes.data,
    };
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

/**
 * POST /nameCheck
 * Body: { bankCode: string, accountNumber: string, alias?: 'live' | 'dev' }
 * Response: { accountHolder, resultCode, verification, meta }
 */
app.post('/nameCheck', async (req, res) => {
    console.log('[nameCheck] 요청 수신:', req.body);
    const { bankCode, accountNumber, alias } = req.body;

    if (!bankCode || !accountNumber) {
        return res.status(400).json({
            error: true,
            code: 'MISSING_PARAMS',
            message: 'bankCode, accountNumber 는 필수입니다.',
        });
    }

    const env = pickEnvironment(alias);

    let accessToken;
    try {
        console.log('[nameCheck] Step 1: gettoken');
        accessToken = await fetchAccessToken();
        console.log('[nameCheck] accessToken:', accessToken);
    } catch (err) {
        console.error('[nameCheck] gettoken 실패:', err.message);
        return res.status(500).json({
            error: true,
            code: 'TOKEN_FAILED',
            message: err.message,
            verification: false,
        });
    }

    let authorization, encryptedAccountNo;
    try {
        console.log('[nameCheck] Step 2: gen-auth + encrypt-account (병렬)');
        ({ authorization, encryptedAccountNo } =
            await generateAuthAndEncryptAccount(accessToken, accountNumber));
        console.log('[nameCheck] authorization:', authorization);
        console.log('[nameCheck] encryptedAccountNo:', encryptedAccountNo);
    } catch (err) {
        console.error('[nameCheck] gen-auth/encrypt-account 실패:', err.message);
        return res.status(500).json({
            error: true,
            code: 'AUTH_FAILED',
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
    console.log(`Hanabank proxy server running on port ${PORT}`);
});
