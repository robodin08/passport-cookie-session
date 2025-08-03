const cookie = require('cookie');
const { encryptPassport, decryptPassport } = require('../utils/encryption');
const withTimeout = require('../utils/timeout');
const { defaultOptions } = require('../constants');
const { validateOptions, checkEncryptionFunctions } = require('../utils/validation');

/**
 * Creates a Passport-style cookie session middleware.
 * 
 * @param {Object} options - Configuration options.
 * @param {string} [options.name] - Cookie name.
 * @param {string[]} options.keys - Array of secret keys for signing/encryption.
 * @param {Object} [options.cookie] - Cookie options.
 * @param {boolean} [options.cookie.httpOnly] - HTTP-only cookie flag.
 * @param {boolean} [options.cookie.secure] - Secure cookie flag.
 * @param {'lax'|'strict'|'none'} [options.cookie.sameSite] - SameSite policy.
 * @param {string} [options.cookie.path] - Cookie path.
 * @param {string} [options.cookie.domain] - Cookie domain.
 * @param {number} [options.cookie.maxAge] - Cookie max age in seconds.
 * @param {number} [options.maxCookieSize] - Maximum allowed cookie size in bytes.
 * @param {function} [options.encrypt] - Custom encrypt function.
 * @param {function} [options.decrypt] - Custom decrypt function.
 * 
 * @returns {function} Express middleware function.
 */
function passportCookieSession(options = {}) {
    const customEncryption = validateOptions(options);
    const {
        name = defaultOptions.name,
        keys,
        cookie: userCookieOptions = {},
        maxCookieSize = defaultOptions.maxCookieSize,
        encrypt = encryptPassport,
        decrypt = decryptPassport,
    } = options;

    const [signingKey] = keys;
    const cookieOptions = { ...defaultOptions.cookie, ...userCookieOptions };

    if (customEncryption) {
        checkEncryptionFunctions(encrypt, decrypt, signingKey);
    }

    return function (req, res, next) {
        const cookies = cookie.parse(req.headers.cookie || '');
        const rawCookieValue = cookies[name];

        let session = {};
        let internalExpireAt = null;

        function finishSessionLoad() {
            req.session = session;
            req.session.save = function (cb) {
                try {
                    internalExpireAt ||= Date.now() + cookieOptions.maxAge * 1000;
                    const envelope = { data: { ...req.session }, expireAt: internalExpireAt };

                    withTimeout("Encryption", doneEncrypt => {
                        encrypt(JSON.stringify(envelope), signingKey, doneEncrypt);
                    }, (err, encrypted) => {
                        if (err) return cb?.(err);
                        const cookieString = cookie.serialize(name, encrypted, {
                            ...cookieOptions,
                            expires: new Date(internalExpireAt),
                        });
                        const encodedValue = encodeURIComponent(encrypted);
                        const cookieSize = Buffer.byteLength(encodedValue, 'utf8');
                        if (cookieSize > maxCookieSize) {
                            return cb?.(new Error(`Cookie size exceeds limit: ${cookieSize} bytes.`));
                        }
                        res.setHeader('Set-Cookie', cookieString);
                        cb?.();
                    });
                } catch (err) {
                    cb?.(err);
                }
            };

            req.session.regenerate = function (cb) {
                req.session = {};
                req.session.save = this.save;
                req.session.regenerate = this.regenerate;
                cb?.();
            };

            next();
        }

        if (!rawCookieValue) return finishSessionLoad();

        let tried = 0;
        function tryDecrypt() {
            if (tried >= keys.length) return finishSessionLoad();
            const decryptKey = keys[tried++];
            withTimeout("Decryption", doneDecrypt => {
                decrypt(rawCookieValue, decryptKey, doneDecrypt);
            }, (err, decrypted) => {
                if (!err) {
                    try {
                        const envelope = JSON.parse(decrypted);
                        if (Date.now() > envelope.expireAt) return finishSessionLoad();
                        session = { ...envelope.data, cookie: session.cookie };
                        session.cookie._expires = new Date(envelope.expireAt);
                        internalExpireAt = envelope.expireAt;
                        return finishSessionLoad();
                    } catch {
                        tryDecrypt();
                    }
                } else {
                    tryDecrypt();
                }
            });
        }

        tryDecrypt();
    };
}

module.exports = passportCookieSession;