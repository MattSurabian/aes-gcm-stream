/**
 * This example shows how to use AES GCM Stream with strings.
 */
'use strict';

var aesgcm = require('../index.js');

var config = {
  key: aesgcm.createKeyBuffer()
};

var encrypt = aesgcm.encrypt(config);
var decrypt = aesgcm.decrypt(config);

encrypt.write('Everything that is written into the stream will be encrypted.\n');
encrypt.write('But because GCM creates a MAC based on ALL the cipher text,\n');
encrypt.write('it\'s necessary to explicitly call end when writing to the stream.\n');
encrypt.write('Otherwise you won\'t be able to authenticate and decrypt the data.\n');
encrypt.write('The decrypter relies on the first 12 bytes of the cipher text being the nonce,\n');
encrypt.write('and the last 16 bytes of the cipherText being the MAC;\n');
encrypt.end('which is only generated and sent on flush.\n');

encrypt.pipe(decrypt).pipe(process.stdout);
