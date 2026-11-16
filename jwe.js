const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Зашифрований JWT (JWE Compact Serialization, RFC 7516):
//   BASE64URL(header).BASE64URL(encrypted key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)
// alg RSA-OAEP-256 - випадковий ключ вмісту (CEK) шифрується публічним RSA ключем сервера
// enc A256GCM      - payload шифрується AES-256-GCM ключем CEK, GCM також дає цілісність

const ALG = 'RSA-OAEP-256';
const ENC = 'A256GCM';

class JweError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}

function base64url(buffer) {
    return Buffer.from(buffer).toString('base64url');
}

// Пара ключів RSA 2048 генерується при першому запуску і зберігається в keys/
function loadOrCreateKeyPair(dir) {
    const privatePath = path.join(dir, 'private.pem');
    const publicPath = path.join(dir, 'public.pem');

    if (!fs.existsSync(privatePath)) {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(privatePath, privateKey, { mode: 0o600 });
        fs.writeFileSync(publicPath, publicKey);
        console.log(`[jwe] new RSA key pair saved to ${dir}`);
    }

    return {
        privateKey: crypto.createPrivateKey(fs.readFileSync(privatePath)),
        publicKey: crypto.createPublicKey(fs.readFileSync(publicPath)),
    };
}

function encryptJwt(payload, publicKey) {
    const header = { alg: ALG, enc: ENC, typ: 'JWT' };
    const encodedHeader = base64url(JSON.stringify(header));

    const cek = crypto.randomBytes(32);
    const encryptedKey = crypto.publicEncrypt(
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        cek,
    );

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
    // Заголовок не шифрується, але захищений від змін як additional authenticated data
    cipher.setAAD(Buffer.from(encodedHeader, 'ascii'));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return [encodedHeader, base64url(encryptedKey), base64url(iv), base64url(ciphertext), base64url(tag)].join('.');
}

function decryptJwt(token, privateKey) {
    const parts = typeof token === 'string' ? token.split('.') : [];
    if (parts.length !== 5) {
        throw new JweError('malformed', `JWE must have 5 parts, got ${parts.length}`);
    }
    const [encodedHeader, encryptedKey, iv, ciphertext, tag] = parts;

    let header;
    try {
        header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
    } catch (e) {
        throw new JweError('malformed', 'Cannot decode JWE header');
    }
    if (header.alg !== ALG || header.enc !== ENC) {
        throw new JweError('invalid_algorithm', `Unsupported JWE algorithms: ${header.alg} / ${header.enc}`);
    }

    let payload;
    try {
        const cek = crypto.privateDecrypt(
            { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
            Buffer.from(encryptedKey, 'base64url'),
        );
        const decipher = crypto.createDecipheriv('aes-256-gcm', cek, Buffer.from(iv, 'base64url'));
        decipher.setAAD(Buffer.from(encodedHeader, 'ascii'));
        decipher.setAuthTag(Buffer.from(tag, 'base64url'));
        const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]);
        payload = JSON.parse(plaintext.toString('utf8'));
    } catch (e) {
        // Неправильний ключ, змінений ciphertext/tag/header - усе це помилка розшифрування
        throw new JweError('decryption_failed', 'Cannot decrypt token');
    }

    if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) {
        throw new JweError('expired', 'Session token expired');
    }

    return { header, payload };
}

module.exports = { JweError, loadOrCreateKeyPair, encryptJwt, decryptJwt };
