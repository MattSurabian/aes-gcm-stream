/**
 * This example shows how to use AES GCM Stream with files.
 */
'use strict';

var fs = require('fs');
var aesgcm = require('../index.js');

// that's right h8rs, Nickelback ipsum
var reader = fs.createReadStream('./nickelbackIpsum.txt');
var writer = fs.createWriteStream('./output.txt');

var config = {
  key: aesgcm.createKeyBuffer()
};

var encrypt = aesgcm.encrypt(config);
var decrypt = aesgcm.decrypt(config);

reader.pipe(encrypt).pipe(decrypt).pipe(writer);
