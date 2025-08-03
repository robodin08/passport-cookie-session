# passport-cookie-session

[![npm version](https://img.shields.io/npm/v/passport-cookie-session.svg)](https://www.npmjs.com/package/passport-cookie-session)
[![npm downloads](https://img.shields.io/npm/dm/passport-cookie-session.svg)](https://www.npmjs.com/package/passport-cookie-session)

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
  name: 'auth',  // Optional. Default: 'session' — session cookie name

  keys: ['super-secret-key', 'old-key'],
  // Required. First key encrypts new cookies.
  // Others are accepted for decrypting old cookies (key rotation support).

  cookie: {
    httpOnly: true,     // Optional. Default: true — prevents JS access to cookie
    secure: false,      // Optional. Default: false — set true if using HTTPS
    sameSite: 'lax',    // Optional. Default: 'lax' — helps prevent CSRF
    path: '/',          // Optional. Default: '/' — cookie path scope
    maxAge: 60 * 60,    // Optional. Default: 86400 (1 day) — duration in seconds
    // domain: 'example.com' // Optional. Default: current domain
  },

  maxCookieSize: 4096,  // Optional. Default: 4096 bytes — max size, stay within browser limits

  // 🔐 Custom async encryption/decryption functions (optional)
  // Must return within the timeout or will throw.
  // ⚠️ WARNING: Example uses insecure XOR cipher. Do NOT use in production!

  encrypt: async function (data, signingKey) {
    const secretChars = signingKey.split('').map(c => c.charCodeAt(0));
    const textChars = data.split('').map(c => c.charCodeAt(0));
    const encryptedChars = textChars.map((ch, i) => ch ^ secretChars[i % secretChars.length]);
    return Buffer.from(encryptedChars).toString('base64');
  },

  decrypt: async function (data, signingKey) {
    const secretChars = signingKey.split('').map(c => c.charCodeAt(0));
    const encryptedChars = Buffer.from(data, 'base64');
    const decryptedChars = [...encryptedChars].map((ch, i) => ch ^ secretChars[i % secretChars.length]);
    return String.fromCharCode(...decryptedChars);
  },

  timeout: 3000,         // Optional. Default: 3000ms — max allowed time for encrypt/decrypt

  checkEncryption: true, // Optional. Default: false
  // Runs a startup check of your custom encrypt/decrypt functions in non-production environments.
  // Recommended during development to ensure your functions correctly round-trip data.
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

- `name` (string) — Cookie name (default: `'session'`).

- `keys` (string[]) — Secret keys:
  - First key is used to encrypt new cookies.
  - Remaining keys are accepted for decrypting old cookies (key rotation).

- `cookie` (object) — Cookie options (see [cookie npm docs](https://github.com/jshttp/cookie#options-1)):
  - `path` (default `'/'`)
  - `httpOnly` (default `true`)
  - `secure` (default `false`)
  - `sameSite` (default `'lax'`)
  - `maxAge` (seconds; default `86400`)
  - `domain` (optional)

- `maxCookieSize` (number) — Maximum allowed cookie size in bytes (default: `4096`).  
  Keep within browser limits (typically 4096 bytes). Sessions exceeding this size will be rejected.  
  *Note:* Session size may vary with user data length, so plan accordingly.

- `encrypt(data, key)` (async function) — Optional custom encryption function.

- `decrypt(encrypted, key)` (async function) — Optional custom decryption function.

- `timeout` (number) — Optional timeout in milliseconds for encrypt/decrypt functions (default: `3000`).

- `checkEncryption` (boolean) — Optional (default: `false`).  
  Enables a startup check that runs your custom encrypt/decrypt functions to verify correct round-trip encryption.  
  Runs only in non-production environments. Strongly recommended during development if using custom functions.

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