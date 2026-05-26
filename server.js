const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = 3002;

const JAVA_URL = 'http://3.37.80.178:8080';
const NAMECHECK_URL_LIVE = process.env.NAMECHECK_URL_LIVE;
const NAMECHECK_URL_DEV  = process.env.NAMECHECK_URL_DEV;
const APP_KEY_LIVE = process.env.APP_KEY_LIVE || 'f16b0e6660e146f7ac9fceb6b7be3c4f';
const APP_KEY      = process.env.APP_KEY      || 'c161f4251ea04adbad3c41a496f12a8b';
const ENTRCD       = process.env.ENTRCD       || 'ARG0890515';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({ origin: '*' }));

const RESULT_MESSAGES = {
    '0000': '조회 성공',
    '0001': '계좌 정보 없음',
    '0002': '은행 코드 오류',
    '0003': '계좌번호 형식 오류',
    '0100': '인증 오류',
    '0200': '서비스 일시 중단',
    '9999': '시스템 오류',
};

app.get('/', (req, res) => {
    res.send('Success called (GET)');
});

app.post('/nameCheck', async (req, res) => {
    console.log('[nameCheck] 요청 수신:', req.body);
    const { bankCode, accountNumber, alias } = req.body;

    if (!bankCode || !accountNumber) {
        return res.status(400).json({ error: true, code: 'MISSING_PARAMS', message: 'bankCode, accountNumber 는 필수입니다.' });
    }

    const isLive = alias === 'live';
    const nameCheckUrl = isLive ? NAMECHECK_URL_LIVE : NAMECHECK_URL_DEV;
    const appKey = isLive ? APP_KEY_LIVE : APP_KEY;
    const clntIpAddr = isLive ? '3.37.80.178' : '3.35.147.100';

    let accessToken, authorization, encryptedAccountNo;

    try {
        console.log('[nameCheck] Step 1: gettoken');
        const tokenRes = await axios.get(`${JAVA_URL}/gettoken`, { timeout: 10000 });
        accessToken = tokenRes.data;
        console.log('[nameCheck] accessToken:', accessToken);
    } catch (err) {
        console.error('[nameCheck] gettoken 실패:', err.message);
        return res.status(500).json({ error: true, code: 'TOKEN_FAILED', message: err.message, verification: false });
    }

    try {
        console.log('[nameCheck] Step 2: gen-auth + encrypt-account (병렬)');
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
        authorization = authRes.data;
        encryptedAccountNo = encRes.data;
        console.log('[nameCheck] authorization:', authorization);
        console.log('[nameCheck] encryptedAccountNo:', encryptedAccountNo);
    } catch (err) {
        console.error('[nameCheck] gen-auth/encrypt-account 실패:', err.message);
        return res.status(500).json({ error: true, code: 'AUTH_FAILED', message: err.message, verification: false });
    }

    const requestBody = {
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

    const headers = {
        Authorization: authorization,
        ENTR_CD: ENTRCD,
        APP_KEY: appKey,
        ENC_NEW: 'Y',
        Accept: 'application/json',
        'Content-Type': 'application/json;charset=UTF-8',
    };

    try {
        console.log('[nameCheck] Step 3: 하나은행 API 호출', nameCheckUrl);
        console.log('[nameCheck] requestBody:', JSON.stringify(requestBody));
        const result = await axios.post(nameCheckUrl, requestBody, { headers, timeout: 30000 });
        const { dataHeader, dataBody } = result.data;

        const resultCode = dataBody?.RSP_CD ?? dataHeader?.GW_RSLT_CD ?? null;
        const accountHolder = dataBody?.accountHolderName ?? null;
        const verification = resultCode === '0000' && !!accountHolder;

        console.log('[nameCheck] 완료 resultCode:', resultCode, 'accountHolder:', accountHolder);
        return res.json({
            accountHolder,
            resultCode,
            verification,
            meta: {
                bankCode,
                resultMessage: RESULT_MESSAGES[resultCode] ?? `알 수 없는 응답코드 (${resultCode})`,
                gwResultCode: dataHeader?.GW_RSLT_CD,
                gwResultMsg:  dataHeader?.GW_RSLT_MSG,
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
