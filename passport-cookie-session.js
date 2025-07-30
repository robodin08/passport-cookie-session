const cookie = require('cookie');
const crypto = require('crypto');

function encrypt(data, secret) {
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash('sha256').update(secret).digest();

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decrypt(encryptedBase64, secret) {
  const b = Buffer.from(encryptedBase64, 'base64');
  const iv = b.subarray(0, 12);
  const tag = b.subarray(12, 28);
  const encrypted = b.slice(28);

  const key = crypto.createHash('sha256').update(secret).digest();

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

// --- Validation function ---
function validateOptions(options) {
  const {
    name = 'session',
    keys,
    cookie: userCookieOptions = {},
  } = options;

  if (!Array.isArray(keys) || keys.length === 0 || !keys.every(k => typeof k === 'string' && k.length > 0)) {
    throw new TypeError('`keys` must be a non-empty array of non-empty strings.');
  }

  if (typeof name !== 'string' || !name.trim()) {
    throw new TypeError('`name` must be a non-empty string.');
  }

  if (typeof userCookieOptions !== 'object') {
    throw new TypeError('`cookie` option must be an object.');
  }

  const allowedSameSite = ['lax', 'strict', 'none'];

  if ('sameSite' in userCookieOptions && !allowedSameSite.includes(userCookieOptions.sameSite)) {
    throw new TypeError('`cookie.sameSite` must be one of: "lax", "strict", or "none".');
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

  if ('maxAge' in userCookieOptions && typeof userCookieOptions.maxAge !== 'number') {
    throw new TypeError('`cookie.maxAge` must be a number (in seconds).');
  }
}

function passportCookieSession(options = {}) {
  validateOptions(options);

  const {
    name = 'session',
    keys,
    cookie: userCookieOptions = {},
  } = options;

  const [signingKey] = keys;

  const defaultCookieOptions = {
    path: '/',
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 // 1 day in seconds
  };

  const cookieOptions = {
    ...defaultCookieOptions,
    ...userCookieOptions,
  };

  return function (req, res, next) {
    const cookies = cookie.parse(req.headers.cookie || '');
    const raw = cookies[name];
    let sessionData = {};

    if (raw) {
      for (const decryptKey of keys) {
        try {
          const decrypted = decrypt(raw, decryptKey);
          sessionData = JSON.parse(decrypted);
          break;
        } catch (_) {}
      }
    }

    req.session = sessionData;

    req.session.save = function (cb) {
      try {
        const encrypted = encrypt(JSON.stringify(req.session), signingKey);
        res.setHeader('Set-Cookie', cookie.serialize(name, encrypted, cookieOptions));
        cb && cb();
      } catch (err) {
        cb && cb(err);
      }
    };

    req.session.regenerate = function (cb) {
      req.session = {};
      req.session.save = this.save;
      req.session.regenerate = this.regenerate;
      cb && cb();
    };

    const _end = res.end;
    res.end = function (...args) {
      req.session.save(() => {
        _end.apply(res, args);
      });
    };

    next();
  };
}

module.exports = passportCookieSession;