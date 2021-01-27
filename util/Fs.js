const Fs = require('fs');
const StringBuilder = require('string-builder');

module.exports = {
  readFileAsync: (path, opts) => {
    return new Promise((res, rej) => {
      Fs.readFile(path, opts, (err, data) => {
        if (err) return rej(err);
        res(data);
      })
    })
  },

  readFileStream: (path, opts) => {
    return new Promise((res, rej) => {
      const sb = new StringBuilder();
      const readStream = Fs.createReadStream(path, opts);
      readStream
        .on('data', (chunk) => sb.append(chunk))
        .on('end', () => res(sb.toString()))
        .on('error', (err) => rej(err));
    })
  }
}