'use strict';

var test = require('tape');
var aesgcm = require('./');

test('basic', function(t) {
  t.plan(1);
  var config = {
    key: aesgcm.createKeyBuffer()
  };

  var encrypt = aesgcm.encrypt(config);
  var decrypt = aesgcm.decrypt(config);

  var data = [
    'Everything that is written into the stream will be encrypted.\n',
    'But because GCM creates a MAC based on ALL the cipher text,\n',
    'it\'s necessary to explicitly call end when writing to the stream.\n',
    'Otherwise you won\'t be able to authenticate and decrypt the data.\n',
    'The decrypter relies on the first 12 bytes of the cipher text being the nonce,\n',
    'and the last 16 bytes of the cipherText being the MAC;\n',
    'which is only generated and sent on flush.\n'
  ];

  var outData = [];
  encrypt.pipe(decrypt).on('data', function(d) {
    outData.push(d.toString());
  }).on('finish', function() {
    t.equals(data.join(''), outData.join(''));
  }).on('error', function(e) {
    t.error(e);
  });
  data.forEach(function(s) {
    encrypt.write(s);
  });
  encrypt.end();
});
