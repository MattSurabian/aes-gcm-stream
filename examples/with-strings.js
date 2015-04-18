/**
 * This example shows how to use AES GCM Stream with strings.
 */

var aesgcm = require('../index.js');

var config = {
  key: aesgcm.createKeyBuffer()
};

var encrypt = aesgcm.encrypt(config);
var decrypt = aesgcm.decrypt(config);

encrypt.write('Everything that is written into the stream will be encrypted.\n');
encrypt.write('But it will be held in memory as encrypted cipher text.\n');
encrypt.write('It won\'t continue to be streamed until end is called or triggered.\n');
encrypt.write('That\'s because GCM creates a MAC based on ALL the cipher text.\n');
encrypt.write('Authentication requires the MAC and Nonce BEFORE decryption begins.\n');
encrypt.end('That\'s why the first 28 bytes from encrypt are the Nonce and MAC.\n');

encrypt.pipe(decrypt).pipe(process.stdout);