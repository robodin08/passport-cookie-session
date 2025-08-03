# passport-cookie-session

[![npm version](https://img.shields.io/npm/v/passport-cookie-session.svg)](https://www.npmjs.com/package/passport-cookie-session)
[![npm downloads](https://img.shields.io/npm/dw/passport-cookie-session.svg)](https://www.npmjs.com/package/passport-cookie-session)

A simple Express middleware to manage encrypted cookie sessions, **specially designed to work seamlessly with [PassportJS](https://www.passportjs.org) authentication**.

This package stores session data directly in an encrypted cookie, eliminating the need for a server-side session store.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API](#api)
- [Security Notes](#security-notes)
- [License](#license)

---

## Features

- 🔐 AES-256-GCM encryption (or custom)
- 🔁 Key rotation support
- 🪪 **Built for PassportJS**
- 💡 Lightweight & stateless

---

## Installation

```bash
npm install passport-cookie-session
```

---

## Usage

```js
const express = require('express');
const passport = require('passport');
const passportCookieSession = require('passport-cookie-session');
const app = express();

app.use(passportCookieSession({
    name: 'auth', // Optional. Default: 'session'
    keys: ['super-secret-key', 'old-key'], // Required. First key is used for encryption. Others are for decryption only.

    cookie: {
        httpOnly: true,      // Optional. Default: true
        secure: false,       // Optional. Default: false
        sameSite: 'lax',     // Optional. Default: 'lax'
        path: '/',           // Optional. Default: '/'
        maxAge: 60 * 60,     // Optional. Default: 24 * 60 * 60 (1 day)
        // domain: 'example.com' // Optional. Default: current domain
    },

    maxCookieSize: 4096,  // Optional. Default is 4096 bytes, must not exceed browser limits

    // Optional encryption function (must use callback, not async/await, NOT secure!)  
    // If not provided, default encryption uses AES-256-GCM with random IV and SHA-256 hashed key
    encrypt: function (data, signingKey, cb) {
        try {
            const secretChars = signingKey.split('').map(c => c.charCodeAt(0));
            const textChars = data.split('').map(c => c.charCodeAt(0));
            const encryptedChars = textChars.map((ch, i) => ch ^ secretChars[i % secretChars.length]);
            const result = Buffer.from(encryptedChars).toString('base64');
            cb(null, result);
        } catch (err) {
            cb(err);
        }
    },

    // Optional encryption function (must use callback, not async/await, NOT secure!)  
    // If not provided, default encryption uses AES-256-GCM with random IV and SHA-256 hashed key
    decrypt: function (data, signingKey, cb) {
        try {
            const secretChars = signingKey.split('').map(c => c.charCodeAt(0));
            const encryptedChars = Buffer.from(data, 'base64');
            const decryptedChars = [...encryptedChars].map((ch, i) => ch ^ secretChars[i % secretChars.length]);
            const result = String.fromCharCode(...decryptedChars);
            cb(null, result);
        } catch (err) {
            cb(err);
        }
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// You must add and configure a Passport strategy for authentication, e.g.:
// passport.use(new LocalStrategy(...));

// Example serialization/deserialization
passport.serializeUser((user, done) => {
  done(null, { id: user.id, username: user.username });
});
passport.deserializeUser((user, done) => done(null, user));
```

---

## API

### passport-cookie-session(options)

Creates Express middleware for encrypted cookie sessions.

Options:

- `name` (string) – Cookie name (default: 'session')

- `keys` (string[]) – Array of secret keys:
  - The first key is used for encryption + decryption.
  - The rest are for decryption only (support key rotation).

- `cookie` (object) – Cookie options (see cookie npm docs):
  - `path` (default '/')
  - `httpOnly` (default true)
  - `secure` (default false)
  - `sameSite` (default 'lax')
  - `maxAge` (in seconds; default 86400)
  - `domain` (optional)

- `maxCookieSize` (number) – Optional. Maximum allowed cookie size in bytes. Default is 4096.  
  Make sure this stays within browser limits (usually 4096 bytes).  
  If the encrypted session exceeds this size, it will be rejected.
  **Keep in mind**: session size may vary depending on user data (e.g., long usernames, emails, etc.), so plan accordingly.

- `encrypt(data, key, cb)` (function) – Optional. Custom encryption function with callback.

- `decrypt(encrypted, key, cb)` (function) – Optional. Custom decryption function with callback.

---

## Security Notes

- Always use HTTPS in production and set secure: true.
- Rotate keys by adding new keys at the start of the keys array.
- Custom encrypt/decrypt should be cryptographically secure in real applications.
- Avoid storing large or sensitive data in the session cookie — keep payload minimal (e.g., user ID).
- Pay attention to the maxCookieSize to avoid cookie overflow and unexpected behavior.

---

## License

MIT © robodin08