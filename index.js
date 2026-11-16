const express = require('express');
const onFinished = require('on-finished');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { JwtError, Auth0KeyStore, verifyJwt } = require('./jwt');
const { loadOrCreateKeyPair, encryptJwt, decryptJwt } = require('./jwe');

try {
    process.loadEnvFile(path.join(__dirname, '.env'));
} catch (e) {
    console.warn('.env not found, using process environment');
}

const {
    AUTH0_DOMAIN,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    AUTH0_AUDIENCE,
    AUTH0_CONNECTION = 'Username-Password-Authentication',
} = process.env;

const PORT = Number(process.env.PORT) || 3000;
// За скільки секунд до завершення життя access token його треба оновити
const REFRESH_THRESHOLD = Number(process.env.REFRESH_THRESHOLD_SECONDS) || 60;
// Час життя токена сесії, який отримує клієнт
const SESSION_TOKEN_TTL = Number(process.env.SESSION_TOKEN_TTL_SECONDS) || 86400;

// AUTH0_AUDIENCE обов'язковий: без нього Auth0 видає непрозорий access token, а не JWT
for (const [name, value] of Object.entries({ AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_AUDIENCE })) {
    if (!value) {
        console.error(`Missing ${name} in .env`);
        process.exit(1);
    }
}

const AUTH0_URL = `https://${AUTH0_DOMAIN}`;
const AUTH0_ISSUER = `${AUTH0_URL}/`;
const SESSION_KEY = 'Authorization';
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
// Ключі для шифрування токена сесії (додаткове завдання)
const sessionKeys = loadOrCreateKeyPair(path.join(__dirname, 'keys'));

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------- sessions

class Session {
    #sessions = {};

    constructor() {
        try {
            this.#sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8').trim());
        } catch (e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync(SESSIONS_FILE, JSON.stringify(this.#sessions, null, 2), 'utf-8');
    }

    set(key, value) {
        this.#sessions[key] = value || {};
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init() {
        return crypto.randomUUID();
    }

    destroy(sessionId) {
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

// Клієнт отримує не id сесії, а JWT із зашифрованим payload (JWE). id сесії лежить всередині.
function issueSessionToken(sessionId, user = {}) {
    const now = nowSeconds();
    return encryptJwt({
        sid: sessionId,
        sub: user.sub,
        email: user.email,
        iat: now,
        exp: now + SESSION_TOKEN_TTL,
    }, sessionKeys.publicKey);
}

app.use((req, res, next) => {
    let sessionId = null;
    const token = req.get(SESSION_KEY);
    if (token) {
        try {
            req.sessionToken = decryptJwt(token, sessionKeys.privateKey);
            sessionId = req.sessionToken.payload.sid;
        } catch (e) {
            req.sessionTokenError = `Invalid session token: ${e.message}`;
            console.error(`[jwe] ${e.code}: ${e.message}`);
        }
    }
    let currentSession = sessionId && sessions.get(sessionId);

    if (!currentSession) {
        currentSession = {};
        sessionId = sessions.init();
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(res, () => {
        // Не зберігаємо порожні сесії анонімних запитів
        if (req.sessionDestroyed || Object.keys(req.session).length === 0) return;
        sessions.set(req.sessionId, req.session);
    });

    next();
});

// ---------------------------------------------------------------- auth0

class Auth0Error extends Error {
    constructor(status, body) {
        super(body.error_description || body.message || body.error || `Auth0 error ${status}`);
        this.status = status;
        this.body = body;
    }
}

async function auth0Request(pathname, { method = 'POST', form, json, token } = {}) {
    const headers = {};
    let body;

    if (form) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(form).toString();
    } else if (json) {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(json);
    }
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(`${AUTH0_URL}${pathname}`, { method, headers, body });
    const text = await response.text();
    let data;
    try {
        data = text ? JSON.parse(text) : {};
    } catch (e) {
        data = { message: text };
    }

    if (!response.ok) {
        throw new Auth0Error(response.status, data);
    }
    return data;
}

// Resource Owner Password grant (лаб. 3, п.1)
function passwordGrant(username, password) {
    const form = {
        grant_type: 'password',
        username,
        password,
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET,
        scope: 'openid profile email offline_access',
        audience: AUTH0_AUDIENCE,
    };

    return auth0Request('/oauth/token', { form });
}

// Refresh token grant (лаб. 3, п.2)
function refreshTokenGrant(refreshToken) {
    return auth0Request('/oauth/token', {
        form: {
            grant_type: 'refresh_token',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            refresh_token: refreshToken,
        },
    });
}

// Client credentials grant для Management API (лаб. 2, п.1), токен кешується до завершення життя
let managementToken = null;

async function getManagementToken() {
    if (managementToken && managementToken.expiresAt - 30 > nowSeconds()) {
        return managementToken.accessToken;
    }

    const data = await auth0Request('/oauth/token', {
        form: {
            grant_type: 'client_credentials',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            audience: `${AUTH0_URL}/api/v2/`,
        },
    });

    managementToken = {
        accessToken: data.access_token,
        expiresAt: nowSeconds() + data.expires_in,
    };
    return managementToken.accessToken;
}

// Створення користувача через Management API (лаб. 2, п.2-3)
async function createUser({ email, password, name }) {
    const token = await getManagementToken();
    const user = { email, password, connection: AUTH0_CONNECTION };
    if (name) user.name = name;

    return auth0Request('/api/v2/users', { json: user, token });
}

// ---------------------------------------------------------------- tokens helpers

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------- jwt verification (лаб. 5)

const keyStore = new Auth0KeyStore(AUTH0_URL);

function verifyAccessToken(token) {
    return verifyJwt(token, keyStore, { issuer: AUTH0_ISSUER, audience: AUTH0_AUDIENCE });
}

function verifyIdToken(token) {
    return verifyJwt(token, keyStore, { issuer: AUTH0_ISSUER, audience: AUTH0_CLIENT_ID });
}

// Токени від Auth0 потрапляють у сесію лише після перевірки підпису
async function verifyTokens(tokens) {
    const access = await verifyAccessToken(tokens.access_token);
    const id = tokens.id_token ? await verifyIdToken(tokens.id_token) : null;
    return { access, id };
}

function storeTokens(session, tokens, verified) {
    session.accessToken = tokens.access_token;
    session.expiresAt = nowSeconds() + tokens.expires_in;
    // Якщо rotation вимкнений, Auth0 не повертає новий refresh token - лишаємо старий
    if (tokens.refresh_token) session.refreshToken = tokens.refresh_token;
    if (verified.id) {
        const claims = verified.id.payload;
        session.idToken = tokens.id_token;
        session.user = {
            sub: claims.sub,
            email: claims.email,
            name: claims.name,
            nickname: claims.nickname,
        };
    }
}

function describeJwt({ header, payload }) {
    return {
        valid: true,
        alg: header.alg,
        kid: header.kid,
        iss: payload.iss,
        aud: payload.aud,
        sub: payload.sub,
        exp: payload.exp,
    };
}

function tokenInfo(session) {
    return {
        expiresAt: session.expiresAt,
        expiresIn: session.expiresAt - nowSeconds(),
        refreshThreshold: REFRESH_THRESHOLD,
        hasRefreshToken: Boolean(session.refreshToken),
        refreshCount: session.refreshCount || 0,
        lastRefreshAt: session.lastRefreshAt || null,
        accessToken: session.accessToken,
    };
}

async function refreshSession(session) {
    const tokens = await refreshTokenGrant(session.refreshToken);
    storeTokens(session, tokens, await verifyTokens(tokens));
    session.refreshCount = (session.refreshCount || 0) + 1;
    session.lastRefreshAt = nowSeconds();
    console.log(`[refresh] ${session.login}: new token valid for ${tokens.expires_in}s`);
}

function destroySession(req) {
    sessions.destroy(req.sessionId);
    req.sessionDestroyed = true;
}

// Перевірка життя токена: якщо до завершення лишилось менше REFRESH_THRESHOLD секунд - оновлюємо
async function requireAuth(req, res, next) {
    const session = req.session;
    if (!session.accessToken) {
        return res.status(401).json({ error: req.sessionTokenError || 'Not authenticated' });
    }
    // Токен сесії має належати тому ж користувачу, що й токени Auth0 в сесії
    if (session.user && req.sessionToken.payload.sub !== session.user.sub) {
        return res.status(401).json({ error: 'Session token does not match session user' });
    }

    const expiresIn = session.expiresAt - nowSeconds();
    if (expiresIn <= REFRESH_THRESHOLD) {
        if (!session.refreshToken) {
            if (expiresIn <= 0) {
                destroySession(req);
                return res.status(401).json({ error: 'Token expired and no refresh token available' });
            }
        } else {
            try {
                await refreshSession(session);
            } catch (e) {
                console.error('[refresh] failed:', e.message);
                destroySession(req);
                return res.status(401).json({ error: `Refresh failed: ${e.message}` });
            }
        }
    }

    // Перевірка підпису access token перед кожним захищеним запитом
    try {
        req.accessToken = await verifyAccessToken(session.accessToken);
        next();
    } catch (e) {
        if (!(e instanceof JwtError)) {
            console.error('[jwt] cannot verify token:', e.message);
            return res.status(502).json({ error: e.message });
        }
        console.error(`[jwt] ${session.login}: ${e.code}: ${e.message}`);
        destroySession(req);
        res.status(401).json({ error: `Invalid access token: ${e.message}` });
    }
}

// ---------------------------------------------------------------- routes

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) {
        return res.status(400).json({ error: 'Login and password are required' });
    }

    try {
        const tokens = await passwordGrant(login, password);
        const verified = await verifyTokens(tokens);
        console.log(`[login] ${login}: token signature is valid (${verified.access.header.alg}, kid ${verified.access.header.kid})`);
        storeTokens(req.session, tokens, verified);
        req.session.login = login;
        req.session.refreshCount = 0;

        res.json({ token: issueSessionToken(req.sessionId, req.session.user) });
    } catch (e) {
        console.error('[login] failed:', e.message);
        const status = e instanceof JwtError || e.status === 403 || e.status === 401 ? 401 : 502;
        res.status(status).json({ error: e.message });
    }
});

app.post('/api/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await createUser({ email, password, name });
        console.log(`[register] created ${user.user_id}`);
        res.status(201).json({ user_id: user.user_id, email: user.email });
    } catch (e) {
        console.error('[register] failed:', e.message);
        res.status(e.status && e.status < 500 ? e.status : 502).json({ error: e.message });
    }
});

app.get('/api/me', requireAuth, (req, res) => {
    const { user = {}, login } = req.session;
    res.json({
        username: user.name || user.email || login,
        user,
        token: tokenInfo(req.session),
        verification: {
            accessToken: describeJwt(req.accessToken),
            publicKey: keyStore.info(),
        },
        // Розшифрований вміст токена сесії - клієнт сам його прочитати не може
        sessionToken: req.sessionToken,
    });
});

// Перевірка довільного токена: підпис + iss/aud/exp (для демонстрації підробленого токена)
app.post('/api/verify', async (req, res) => {
    const { token, type = 'access' } = req.body;
    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    try {
        const verified = type === 'id' ? await verifyIdToken(token) : await verifyAccessToken(token);
        res.json({ ...describeJwt(verified), payload: verified.payload });
    } catch (e) {
        if (!(e instanceof JwtError)) {
            return res.status(502).json({ error: e.message });
        }
        res.status(401).json({ valid: false, code: e.code, error: e.message });
    }
});

// Примусове оновлення токена (для демонстрації refresh-token grant)
app.post('/api/refresh', requireAuth, async (req, res) => {
    if (!req.session.refreshToken) {
        return res.status(400).json({ error: 'No refresh token in session' });
    }
    try {
        await refreshSession(req.session);
        res.json({ token: tokenInfo(req.session) });
    } catch (e) {
        res.status(502).json({ error: e.message });
    }
});

app.post('/api/logout', (req, res) => {
    destroySession(req);
    res.status(204).end();
});

keyStore.load()
    .catch((e) => console.error('[jwt]', e.message))
    .finally(() => {
        app.listen(PORT, () => {
            console.log(`App listening on http://localhost:${PORT} (Auth0 domain: ${AUTH0_DOMAIN})`);
        });
    });
