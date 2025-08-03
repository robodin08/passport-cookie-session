const crypto = require('crypto');
const { ALGORITHM, IV_LENGTH, TAG_LENGTH } = require('../constants');

function encryptPassport(data, signingKey, cb) {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = crypto.createHash('sha256').update(signingKey).digest();
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
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
    const iv = buffer.subarray(0, IV_LENGTH);
    const tag = buffer.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encrypted = buffer.subarray(IV_LENGTH + TAG_LENGTH);
    const key = crypto.createHash('sha256').update(signingKey).digest();
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    cb(null, decrypted.toString('utf8'));
  } catch (err) {
    cb(err);
  }
}

module.exports = { encryptPassport, decryptPassport };