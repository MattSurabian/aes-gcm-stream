/**
 * This example shows how to use AES GCM Stream with a key file on disk.
 */
'use strict';

var fs = require('fs');
var aesgcm = require('../index.js');
var keyfilePath = './keyfile';

fs.writeFileSync(keyfilePath, aesgcm.createEncodedKey(), 'utf-8');

// there isn't a helper for reading keys from files because of encoding edge cases
var key = fs.readFileSync(keyfilePath, 'utf-8');

var config = {
  key: key
};

var encrypt = aesgcm.encrypt(config);
var decrypt = aesgcm.decrypt(config);

encrypt.end('This was encrypted and decrypted by a key read from a file\n');

encrypt.pipe(decrypt).pipe(process.stdout);
