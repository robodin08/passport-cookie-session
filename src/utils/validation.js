const withTimeout = require('./timeout');

async function checkEncryptionFunctions(encrypt, decrypt, key, timeout) {
    const testData = { foo: "bar", date: Date.now() };
    const testDataString = JSON.stringify(testData);

    try {
        // Attempt to encrypt within the timeout
        const encrypted = await withTimeout("Encryption", encrypt, [testDataString, key], timeout);

        // Attempt to decrypt within the timeout
        const decrypted = await withTimeout("Decryption", decrypt, [encrypted, key], timeout);

        try {
            const parsed = JSON.parse(decrypted);

            // Check if decrypted data matches the original test data
            if (parsed.foo !== testData.foo || typeof parsed.date !== 'number') {
                console.error('[Data Mismatch] Decrypted data does not match the original test data.');
                console.error('→ Verify that your encrypt and decrypt functions correctly preserve data integrity.');
                throw new Error('Decrypted data integrity check failed.');
            } else {
                console.log('[Success] Encryption and decryption test passed. Custom functions work correctly.');
            }
        } catch (parseError) {
            console.error(`[JSON Parse Error] Unable to parse decrypted data: ${parseError.message}`);
            console.error('→ Decrypted output might be corrupted or invalid JSON. Check your decrypt function.');
            throw new Error('Failed to parse decrypted data.');
        }
    } catch (error) {
        console.error(`[Encryption/Decryption Check Error] ${error.message}`);
        console.error('→ Please check your custom encrypt/decrypt function implementations and ensure they call the callback properly.');
        throw error; // re-throw to allow calling code to handle
    }
}

function validateOptions(options) {
    const {
        name,
        keys,
        cookie: userCookieOptions = {},
        maxCookieSize,
        encrypt,
        decrypt,
        timeout,
        checkEncryption,
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
        if (encrypt.constructor.name !== 'AsyncFunction') {
            throw new TypeError('`encrypt` must be an async function (declared with `async`).');
        }
        if (encrypt.length < 2) {
            throw new TypeError('`encrypt` must accept at least 3 arguments: (data, signingKey).');
        }
    }

    if (decrypt !== undefined) {
        if (typeof decrypt !== "function") {
            throw new TypeError('`decrypt` must be a function.');
        }
        if (decrypt.constructor.name !== 'AsyncFunction') {
            throw new TypeError('`decrypt` must be an async function (declared with `async`).');
        }
        if (decrypt.length < 2) {
            throw new TypeError('`decrypt` must accept at least 3 arguments: (data, signingKey).');
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

    if (timeout !== undefined) {
        if (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout <= 0) {
            throw new TypeError('`timeout` must be a finite positive number (in milliseconds).');
        }
    }

    if (checkEncryption !== undefined && typeof checkEncryption !== 'boolean') {
        throw new TypeError('`checkEncryption` must be a boolean.');
    }

    return Boolean(encrypt && decrypt);
}

module.exports = { validateOptions, checkEncryptionFunctions };