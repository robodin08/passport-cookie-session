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

module.exports = withTimeout;