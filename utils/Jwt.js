const Jwt = require('jsonwebtoken');

module.exports = {
  signAsync: (payload, secret, opts = {}) => {
    return new Promise((res, rej) => {
      Jwt.sign(payload, secret, opts, (err, token) => {
        if (err) return rej(err);
        res(token);
      })
    })
  },

  verifyAsync: (token, key, opts = {}) => {
    return new Promise((res, rej) => {
      Jwt.verify(token, key, opts, (err, decoded) => {
        if (err) return rej(err);
        res(decoded);
      })
    })
  }
}