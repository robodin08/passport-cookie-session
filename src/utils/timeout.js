async function withTimeout(mode, asyncFunc, args = [], timeout) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${mode} function timed out. Ensure you call the callback or return properly within ${timeout}ms.`));
    }, timeout);

    asyncFunc(...args)
      .then(result => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch(err => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

module.exports = withTimeout;