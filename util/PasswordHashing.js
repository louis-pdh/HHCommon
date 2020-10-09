const Bcrypt = require('bcrypt');

module.exports = {
  hashPasswordAsync: (str, saltRounds) => {
    return new Promise((res, rej) => {
      Bcrypt.hash(str, saltRounds, (err, hashed) => {
        if (err) return rej(err);
        res(hashed);
      })
    })
  },

  compPasswordAsync: (str, hashed) => {
    return new Promise((res, rej) => {
      Bcrypt.compare(str, hashed, (err, valid) => {
        if (err) return rej(err);
        res(valid);
      })
    })
  }
}