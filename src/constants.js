module.exports = {
  ALGORITHM: 'aes-256-gcm',
  IV_LENGTH: 12,
  TAG_LENGTH: 16,
  defaultOptions: {
    name: "session",
    maxCookieSize: 4096,
    cookie: {
      path: '/',
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60, // 1 day
    },
  },
};