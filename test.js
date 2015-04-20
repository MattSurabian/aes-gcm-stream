var test = require('tape');
var aesgcm = require('./');

test('basic', function (t) {
  t.plan(1);
  var config = {
    key: aesgcm.createKeyBuffer()
  };

  var encrypt = aesgcm.encrypt(config);
  var decrypt = aesgcm.decrypt(config);

  var data = [
    'Everything that is written into the stream will be encrypted.\n',
    'But it will be held in memory as encrypted cipher text.\n',
    'It won\'t continue to be streamed until end is called or triggered.\n',
    'That\'s because GCM creates a MAC based on ALL the cipher text.\n',
    'Authentication requires the MAC and Nonce BEFORE decryption begins.\n',
    'That\'s why the first 28 bytes from encrypt are the Nonce and MAC.\n'
  ];
  var outData = [];
  encrypt.pipe(decrypt).on('data', function (d) {
    outData.push(d.toString());
  }).on('finish', function () {
    t.equals(data.join(''), outData.join(''));
  }).on('error', function (e) {
    t.error(e);
  });
  data.forEach(function (s) {
    encrypt.write(s);
  });
  encrypt.end();
});
