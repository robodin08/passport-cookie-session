const withTimeout = require('./timeout');

function checkEncryptionFunctions(encrypt, decrypt, key) {
    const testData = { foo: "bar", date: Date.now() };
    const testDataString = JSON.stringify(testData);

    withTimeout('encrypt', (cb) => encrypt(testDataString, key, cb), (encErr, encrypted) => {
        if (encErr) {
            console.error(`[Encryption Error] Failed to encrypt test data during initialization: ${encErr.message}`);
            console.error('→ Please check your custom encrypt function implementation and ensure it calls the callback properly.');
            return;
        }

        withTimeout('decrypt', (cb) => decrypt(encrypted, key, cb), (decErr, decrypted) => {
            if (decErr) {
                console.error(`[Decryption Error] Failed to decrypt test data during initialization: ${decErr.message}`);
                console.error('→ Please check your custom decrypt function implementation and ensure it calls the callback properly.');
                return;
            }

            try {
                const parsed = JSON.parse(decrypted);
                if (parsed.foo !== testData.foo || typeof parsed.date !== 'number') {
                    console.error('[Data Mismatch] Decrypted data does not match the original test data.');
                    console.error('→ Verify that your encrypt and decrypt functions correctly preserve data integrity.');
                } else {
                    // console.log('[Success] Encryption and decryption test passed. Custom functions work correctly.');
                }
            } catch (err) {
                console.error(`[JSON Parse Error] Unable to parse decrypted data: ${err.message}`);
                console.error('→ Decrypted output might be corrupted or invalid JSON. Check your decrypt function.');
            }
        });
    });
}

function validateOptions(options) {
    const {
        name,
        keys,
        cookie: userCookieOptions = {},
        maxCookieSize,
        encrypt,
        decrypt,
    } = options;

    if (!Array.isArray(keys) || keys.length === 0 || !keys.every(k => typeof k === 'string' && k.length > 0)) {
        throw new TypeError('`keys` must be a non-empty array of non-empty strings.');
    }

    if (name !== undefined && (typeof name !== 'string' || !name.trim())) {
        throw new TypeError('`name` must be a non-empty string.');
    }

    if (maxCookieSize !== undefined) {
        if (typeof maxCookieSize !== 'number' || !Number.isFinite(maxCookieSize) || maxCookieSize <= 0) {
            throw new TypeError('`maxCookieSize` must be a finite positive number (in bytes).');
        }
    }

    if (encrypt !== undefined) {
        if (typeof encrypt !== "function") {
            throw new TypeError('`encrypt` must be a function.');
        }
        if (encrypt.constructor.name === 'AsyncFunction') {
            throw new TypeError('`encrypt` must be synchronous and use a callback, not an async function.');
        }
        if (encrypt.length < 3) {
            throw new TypeError('`encrypt` must accept at least 3 arguments: (data, signingKey, callback).');
        }
    }

    if (decrypt !== undefined) {
        if (typeof decrypt !== "function") {
            throw new TypeError('`decrypt` must be a function.');
        }
        if (decrypt.constructor.name === 'AsyncFunction') {
            throw new TypeError('`decrypt` must be synchronous and use a callback, not an async function.');
        }
        if (decrypt.length < 3) {
            throw new TypeError('`decrypt` must accept at least 3 arguments: (data, signingKey, callback).');
        }
    }

    if ((encrypt && !decrypt) || (!encrypt && decrypt)) {
        throw new TypeError('Both `encrypt` and `decrypt` functions must be provided together.');
    }

    if (typeof userCookieOptions !== 'object' || userCookieOptions === null) {
        throw new TypeError('`cookie` option must be an object.');
    }

    const allowedCookieOptions = ['httpOnly', 'secure', 'sameSite', 'path', 'domain', 'maxAge'];
    for (const key of Object.keys(userCookieOptions)) {
        if (!allowedCookieOptions.includes(key)) {
            console.warn(`Warning: Unknown cookie option "${key}" detected.`);
        }
    }

    if ('sameSite' in userCookieOptions) {
        if (typeof userCookieOptions.sameSite !== 'string') {
            throw new TypeError('`cookie.sameSite` must be a string.');
        }
        const allowedSameSiteValues = ['lax', 'strict', 'none'];
        if (!allowedSameSiteValues.includes(userCookieOptions.sameSite.toLowerCase())) {
            throw new TypeError('`cookie.sameSite` must be one of: "lax", "strict", or "none".');
        }
    }

    if ('secure' in userCookieOptions && typeof userCookieOptions.secure !== 'boolean') {
        throw new TypeError('`cookie.secure` must be a boolean.');
    }

    if ('httpOnly' in userCookieOptions && typeof userCookieOptions.httpOnly !== 'boolean') {
        throw new TypeError('`cookie.httpOnly` must be a boolean.');
    }

    if ('path' in userCookieOptions && typeof userCookieOptions.path !== 'string') {
        throw new TypeError('`cookie.path` must be a string.');
    }

    if ('domain' in userCookieOptions && typeof userCookieOptions.domain !== 'string') {
        throw new TypeError('`cookie.domain` must be a string.');
    }

    if ('maxAge' in userCookieOptions) {
        if (typeof userCookieOptions.maxAge !== 'number' || !Number.isFinite(userCookieOptions.maxAge) || userCookieOptions.maxAge < 0) {
            throw new TypeError('`cookie.maxAge` must be a finite non-negative number (in seconds).');
        }
    }

    return Boolean(encrypt && decrypt);
}

module.exports = { validateOptions, checkEncryptionFunctions };