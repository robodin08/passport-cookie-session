const cookie = require('cookie');
const crypto = require('crypto');

const defaultOptions = {
  name: "session",
  maxCookieSize: 4096,
  cookie: {
    path: '/',
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60, // 1 day in seconds
  },
};

function withTimeout(mode, fn, cb, timeoutMs = 5000) {
  let called = false;

  const timer = setTimeout(() => {
    if (!called) {
      called = true;
      cb(new Error(`${mode} function timed out. Ensure you call the callback or return properly.`));
    }
  }, timeoutMs);

  fn((...args) => {
    if (!called) {
      called = true;
      clearTimeout(timer);
      cb(...args);
    }
  });
}

function checkEncryptionFunctions(encrypt, decrypt, key) {
  const testPayload = { foo: "bar", time: Date.now() };
  const data = JSON.stringify(testPayload);

  withTimeout("Encryption", doneEncrypt => {
    encrypt(data, key, doneEncrypt);
  }, (err, encrypted) => {
    if (err) {
      return console.error("Encryption error:", err.message || err);
    }

    withTimeout("Decryption", doneDecrypt => {
      decrypt(encrypted, key, doneDecrypt);
    }, (err, decrypted) => {
      if (err) {
        return console.error("Decryption error:", err.message || err);
      }

      try {
        const parsed = JSON.parse(decrypted);
        if (parsed.foo !== testPayload.foo || parsed.time !== testPayload.time) {
          return console.error("Decryption validation error: decrypted data does not match expected structure.");
        }
        // console.info("Encryption and decryption functions validated successfully.");
      } catch {
        console.error("Decryption validation error: decrypted data is not valid JSON.");
      }
    });
  });
}

function encryptPassport(data, signingKey, cb) {
  try {
    const iv = crypto.randomBytes(12);
    const key = crypto.createHash('sha256').update(signingKey).digest();

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    const result = Buffer.concat([iv, tag, encrypted]).toString('base64');
    cb(null, result);
  } catch (err) {
    cb(err);
  }
}

function decryptPassport(data, signingKey, cb) {
  try {
    const buffer = Buffer.from(data, 'base64');
    const iv = buffer.subarray(0, 12);
    const tag = buffer.subarray(12, 28);
    const encrypted = buffer.subarray(28);

    const key = crypto.createHash('sha256').update(signingKey).digest();

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    cb(null, decrypted.toString('utf8'));
  } catch (err) {
    cb(err);
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
  const customEncryptAndDecrypt = validateOptions(options);

  const {
    name = defaultOptions.name,
    keys,
    cookie: userCookieOptions = {},
    maxCookieSize = defaultOptions.maxCookieSize,
    encrypt = encryptPassport,
    decrypt = decryptPassport,
  } = options;

  const [signingKey] = keys;

  const cookieOptions = {
    ...defaultOptions.cookie,
    ...userCookieOptions,
  };

  if (customEncryptAndDecrypt) {
    checkEncryptionFunctions(encrypt, decrypt, signingKey);
  }

  return function (req, res, next) {
    const cookies = cookie.parse(req.headers.cookie || '');
    const rawCookieValue = cookies[name];

    let session = {
      cookie: {
        path: cookieOptions.path,
        httpOnly: cookieOptions.httpOnly,
        secure: cookieOptions.secure,
        sameSite: cookieOptions.sameSite,
        originalMaxAge: cookieOptions.maxAge * 1000,
        _expires: null,
      },
    };

    let internalExpireAt = null;

    function finishSessionLoad() {
      req.session = session;

      req.session.save = function (saveCb) {
        try {
          internalExpireAt = internalExpireAt || (Date.now() + (cookieOptions.maxAge * 1000));
          const envelope = {
            data: { ...req.session },
            expireAt: internalExpireAt,
          };
          delete envelope.data.cookie;

          encrypt(JSON.stringify(envelope), signingKey, (err, encrypted) => {
            if (err) return saveCb && saveCb(err);

            const cookieString = cookie.serialize(name, encrypted, {
              ...cookieOptions,
              expires: new Date(internalExpireAt),
            });

            const encodedValue = encodeURIComponent(encrypted);
            const cookieSize = Buffer.byteLength(encodedValue, 'utf8');
            if (cookieSize > maxCookieSize) {
              return saveCb && saveCb(new Error(`Cookie size exceeds limit: ${cookieSize} bytes, max allowed is ${maxCookieSize} bytes.`));
            }

            res.setHeader('Set-Cookie', cookieString);
            saveCb && saveCb();
          });
        } catch (err) {
          saveCb && saveCb(err);
        }
      };

      req.session.regenerate = function (regenerateCb) {
        req.session = {
          cookie: session.cookie,
        };
        req.session.save = this.save;
        req.session.regenerate = this.regenerate;
        regenerateCb && regenerateCb();
      };

      next();
    }

    if (!rawCookieValue) {
      return finishSessionLoad();
    }

    let tried = 0;

    function tryDecrypt() {
      if (tried >= keys.length) {
        return finishSessionLoad();
      }

      const decryptKey = keys[tried++];
      decrypt(rawCookieValue, decryptKey, (err, decrypted) => {
        if (!err) {
          try {
            const envelope = JSON.parse(decrypted);
            if (Date.now() > envelope.expireAt) {
              return finishSessionLoad();
            }

            session = {
              ...envelope.data,
              cookie: session.cookie,
            };
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
