const crypto = require('crypto');

// Перевірка підпису JWT, виданих Auth0 (RS256).
// Публічний ключ береться з https://<domain>/pem (сертифікат X.509 тенанта).

const ALLOWED_ALGORITHMS = ['RS256'];
// Допустиме розходження годинників сервера і Auth0, секунд
const CLOCK_TOLERANCE = 30;
// Як часто можна повторно завантажувати ключ, якщо підпис не зійшовся
const KEY_RELOAD_INTERVAL_MS = 60 * 1000;

class JwtError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}

function base64UrlJson(part, what) {
    try {
        return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    } catch (e) {
        throw new JwtError('malformed', `Cannot decode JWT ${what}`);
    }
}

function decodeJwt(token) {
    if (typeof token !== 'string') {
        throw new JwtError('malformed', 'Token must be a string');
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new JwtError('malformed', `JWT must have 3 parts, got ${parts.length}`);
    }
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    return {
        header: base64UrlJson(encodedHeader, 'header'),
        payload: base64UrlJson(encodedPayload, 'payload'),
        signingInput: `${encodedHeader}.${encodedPayload}`,
        signature: Buffer.from(encodedSignature, 'base64url'),
    };
}

class Auth0KeyStore {
    #domainUrl;
    #key = null;
    #loadedAt = 0;

    constructor(domainUrl) {
        this.#domainUrl = domainUrl;
    }

    async load() {
        const response = await fetch(`${this.#domainUrl}/pem`);
        if (!response.ok) {
            throw new Error(`Cannot load public key from ${this.#domainUrl}/pem: HTTP ${response.status}`);
        }
        const certificate = new crypto.X509Certificate(await response.text());
        this.#loadedAt = Date.now();
        this.#key = {
            publicKey: certificate.publicKey,
            subject: certificate.subject,
            fingerprint: certificate.fingerprint256,
            validTo: certificate.validTo,
        };
        console.log(`[jwt] public key loaded: ${certificate.subject}, sha256 ${certificate.fingerprint256}`);
        return this.#key;
    }

    async get() {
        return this.#key || this.load();
    }

    // Повторне завантаження (key rotation), не частіше ніж раз на KEY_RELOAD_INTERVAL_MS,
    // щоб підроблені токени не змушували сервер постійно ходити в Auth0
    async reload() {
        if (Date.now() - this.#loadedAt < KEY_RELOAD_INTERVAL_MS) return null;
        return this.load();
    }

    info() {
        return this.#key && {
            subject: this.#key.subject,
            fingerprint: this.#key.fingerprint,
            validTo: this.#key.validTo,
        };
    }
}

function verifySignature(decoded, publicKey) {
    return crypto.verify('RSA-SHA256', Buffer.from(decoded.signingInput), publicKey, decoded.signature);
}

function checkClaims(payload, { issuer, audience }) {
    const now = Math.floor(Date.now() / 1000);

    if (payload.iss !== issuer) {
        throw new JwtError('invalid_issuer', `Unexpected issuer: ${payload.iss}`);
    }

    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(audience)) {
        throw new JwtError('invalid_audience', `Token is not issued for ${audience}`);
    }

    if (typeof payload.exp !== 'number' || payload.exp + CLOCK_TOLERANCE < now) {
        throw new JwtError('expired', 'Token expired');
    }
    if (typeof payload.nbf === 'number' && payload.nbf - CLOCK_TOLERANCE > now) {
        throw new JwtError('not_active', 'Token is not active yet');
    }
    if (typeof payload.iat === 'number' && payload.iat - CLOCK_TOLERANCE > now) {
        throw new JwtError('invalid_iat', 'Token issued in the future');
    }
}

// Повна перевірка: формат, алгоритм, підпис, iss/aud/exp
async function verifyJwt(token, keyStore, { issuer, audience }) {
    const decoded = decodeJwt(token);
    const { header, payload } = decoded;

    // Алгоритм беремо зі списку дозволених, а не з токена: alg=none або HS256 з публічним ключем як секретом не пройдуть
    if (!ALLOWED_ALGORITHMS.includes(header.alg)) {
        throw new JwtError('invalid_algorithm', `Algorithm ${header.alg} is not allowed`);
    }

    const key = await keyStore.get();
    let valid = verifySignature(decoded, key.publicKey);
    if (!valid) {
        // Ключ тенанта могли змінити (rotation) - пробуємо завантажити його ще раз
        const newKey = await keyStore.reload();
        valid = Boolean(newKey) && verifySignature(decoded, newKey.publicKey);
    }
    if (!valid) {
        throw new JwtError('invalid_signature', 'Invalid token signature');
    }

    checkClaims(payload, { issuer, audience });

    return { header, payload };
}

module.exports = { JwtError, Auth0KeyStore, decodeJwt, verifyJwt };
