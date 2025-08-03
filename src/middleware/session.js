const cookie = require('cookie');
const { encryptPassport, decryptPassport } = require('../utils/encryption');
const withTimeout = require('../utils/timeout');
const { defaultOptions } = require('../constants');
const { validateOptions, checkEncryptionFunctions } = require('../utils/validation');

/**
 * Creates a Passport-style cookie session middleware.
 * 
 * @param {Object} options - Configuration options.
 * @param {string} [options.name] - Cookie name. Default is 'session'.
 * @param {string[]} options.keys - Array of secret keys for signing/encryption.
 *        The first key is used for encryption; the rest are used for decryption (key rotation).
 * 
 * @param {Object} [options.cookie] - Cookie options.
 * @param {boolean} [options.cookie.httpOnly] - HTTP-only cookie flag. Default is true.
 * @param {boolean} [options.cookie.secure] - Secure cookie flag. Default is false.
 * @param {'lax'|'strict'|'none'} [options.cookie.sameSite] - SameSite policy. Default is 'lax'.
 * @param {string} [options.cookie.path] - Cookie path. Default is '/'.
 * @param {string} [options.cookie.domain] - Cookie domain. Default is current domain.
 * @param {number} [options.cookie.maxAge] - Cookie max age in seconds. Default is 86400 (1 day).
 * 
 * @param {number} [options.maxCookieSize] - Maximum allowed cookie size in bytes. Default is 4096.
 * 
 * @param {function(string, string): Promise<string>} [options.encrypt] - 
 *        Optional custom async function to encrypt string data using a signing key.
 * @param {function(string, string): Promise<string>} [options.decrypt] - 
 *        Optional custom async function to decrypt string data using a signing key.
 * 
 * @param {number} [options.timeout] - Timeout in milliseconds for encrypt/decrypt functions. Default is 3000.
 * 
 * @param {boolean} [options.checkEncryption] - 
 *        If true, performs a startup check (in non-production environments) to verify 
 *        that custom encrypt/decrypt functions can correctly round-trip test data. Default is false.
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
        timeout = defaultOptions.timout,
        checkEncryption = defaultOptions.checkEncryption,
    } = options;

    const [signingKey] = keys;
    const cookieOptions = { ...defaultOptions.cookie, ...userCookieOptions };

    return async function (req, res, next) {
        const cookies = cookie.parse(req.headers.cookie || '');
        const rawCookieValue = cookies[name];

        let session = {};
        let internalExpireAt = null;

        function finishSessionLoad() {
            req.session = session;
            req.session.save = function (cb) {
                async function save() {
                    if (!req.session?.passport || Object.keys(req.session?.passport).length === 0) {
                        const expiredCookie = cookie.serialize(name, '', {
                            ...cookieOptions,
                            expires: new Date(0), // Expire immediately
                        });
                        res.setHeader('Set-Cookie', expiredCookie);
                        return;
                    }

                    internalExpireAt ||= Date.now() + cookieOptions.maxAge * 1000;
                    const envelope = { data: { ...req.session?.passport }, expireAt: internalExpireAt };

                    const encrypted = await withTimeout("Encryption", encrypt, [JSON.stringify(envelope), signingKey], timeout);

                    const cookieString = cookie.serialize(name, encrypted, {
                        ...cookieOptions,
                        expires: new Date(internalExpireAt),
                    });

                    const encodedValue = encodeURIComponent(encrypted);
                    const cookieSize = Buffer.byteLength(encodedValue, 'utf8');
                    if (cookieSize > maxCookieSize) {
                        throw new Error(`Cookie size exceeds limit: ${cookieSize} bytes.`);
                    }

                    res.setHeader('Set-Cookie', cookieString);
                }

                save()
                    .then(() => cb?.())
                    .catch(err => cb?.(err));
            };

            req.session.regenerate = function (cb) {
                req.session = {};
                req.session.save = this.save;
                req.session.regenerate = this.regenerate;
                cb?.();
            };

            next();
        }

        if (customEncryption && checkEncryption) {
            await checkEncryptionFunctions(encrypt, decrypt, signingKey, timeout);
        }

        if (!rawCookieValue) return finishSessionLoad();

        for (const decryptKey of keys) {
            try {
                const decrypted = await withTimeout("Decryption", decrypt, [rawCookieValue, decryptKey], timeout);

                const envelope = JSON.parse(decrypted);
                if (Date.now() > envelope.expireAt) break;

                session = { passport: { ...envelope.data } };
                internalExpireAt = envelope.expireAt;
                break;
            } catch {
                // Try next key
                continue;
            }
        }

        return finishSessionLoad();
    };
}

module.exports = passportCookieSession;