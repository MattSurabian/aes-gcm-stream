/**
 * AES GCM Stream
 * This module exports encrypt and decrypt stream constructors which can be
 * used to protect data with authenticated encryption.
 *
 * Helper methods are also provided to do things like generate secure keys
 * and salt.
 */
'use strict';

var stream = require('stream');
var Transform = stream.Transform;
var util = require('util');
var crypto = require('crypto');

var PBKDF2_PASS_LENGTH = 256;
var PBKDF2_SALT_LENGTH = 32;
var PBKDF2_ITERATIONS = 5000;
var PBKDF2_DIGEST = 'sha256';
var KEY_LENGTH = 32; // bytes
var GCM_NONCE_LENGTH = 12; //bytes
var GCM_MAC_LENGTH = 16; //bytes

var keyEncoding = 'base64';

/**
 * Private helper method to validate keys passed into the Encrypt and Decrypt streams
 * @param key
 * @returns {boolean}
 */
var validateKey = function(key) {
  if (key && (key instanceof Buffer || typeof key === 'string')) {
    return true;
  } else {
    throw new Error('Key is required! Expected binary encoded string or buffer.');
  }
};

exports.encrypt = EncryptionStream;
exports.decrypt = DecryptionStream;

/**
 * getEncoding
 * Helper which returns the current encoding being used for keys
 * @returns {string}
 */
exports.getKeyEncoding = function() {
  return keyEncoding;
};

/**
 * setEncoding
 * Helper to set the encoding being used for keys
 * @param enc
 */
exports.setKeyEncoding = function(enc) {
  keyEncoding = Buffer.isEncoding(enc) ? enc : keyEncoding;
};

/**
 * createSalt
 * Helper method that returns a salt
 * @returns string
 * @throws error
 */
exports.createSalt = function(length) {
  try {
    return crypto.randomBytes(length);
  } catch (ex) {
    console.error('Problem reading random data and generating salt!');
    throw ex;
  }
};

/**
 * createKeyBuffer
 * Method which returns a buffer representing a secure key generated with PBKDF2
 * @returns Buffer
 */
exports.createKeyBuffer = function() {
  try {
    var passphrase = crypto.randomBytes(PBKDF2_PASS_LENGTH).toString('binary');
    var salt = this.createSalt(PBKDF2_SALT_LENGTH).toString('binary');
    return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, PBKDF2_DIGEST);
  } catch (ex) {
    console.error('Problem reading random data and generating a key!');
    throw ex;
  }
};

/**
 * createEncodedKey
 * Helper method that returns an encoded key
 * @returns string
 * @throws error
 */
exports.createEncodedKey = function() {
  return exports.createKeyBuffer().toString(keyEncoding);
};

/**
 * EncryptionStream
 * A constructor which returns an encryption stream
 * The stream first outputs a 12 byte nonce then a 16 byte MAC
 * Finally the stream outputs all the cipher text generated from the streamed in data.
 * @param options Object Object.key is the only required param
 * @returns {EncryptionStream}
 * @constructor
 */
function EncryptionStream(options) {
  if (!(this instanceof EncryptionStream)) {
    return new EncryptionStream(options);
  }

  // It stinks the we have to store all the
  // encrypted chunks in memory but such is life
  this._cipherTextChunks = [];

  this._started = false;
  this._nonce = options.nonce || exports.createSalt(12);

  if (validateKey(options.key)) {
    this._key = options.key;
    this._cipher = crypto.createCipheriv('aes-256-gcm', this._key, this._nonce);
  }

  Transform.call(this, options);
}
util.inherits(EncryptionStream, Transform);

EncryptionStream.prototype._transform = function(chunk, enc, cb) {
  if (!this._started) {
    this._started = true;
    this.push(this._nonce);
  }

  this._cipherTextChunks.push(this._cipher.update(chunk));

  if (typeof(cb) === 'function') {
    cb();
  }
};

EncryptionStream.prototype._flush = function(cb) {
  // final must be called on the cipher before generating a MAC
  this._cipherTextChunks.push(this._cipher.final());
  var mac = this._cipher.getAuthTag();
  this.push(mac); // 16 bytes

  for (var i = 0; i< this._cipherTextChunks.length; i++) {
    this.push(this._cipherTextChunks.shift());
  }

  if (typeof(cb) === 'function') {
    cb();
  }
};


/**
 * DecryptionStream
 * A constructor which returns a decryption stream
 * The stream assumes the first 28 bytes of data are the nonce followed by the MAC
 * @param options Object Object.key is the only required param
 * @returns {DecryptionStream}
 * @constructor
 */
function DecryptionStream(options) {
  if (!(this instanceof DecryptionStream)) {
    return new DecryptionStream(options);
  }

  this._started = false;
  this._nonce = new Buffer(12);
  this._mac = new Buffer(16);
  this._nonceBytesRead = 0;
  this._macBytesRead = 0;

  if (validateKey(options.key)) {
    this._key = options.key;
  }

  Transform.call(this, options);
}
util.inherits(DecryptionStream, Transform);

DecryptionStream.prototype._transform = function(chunk, enc, cb) {
  var chunkLength = chunk.length;
  var chunkOffset = 0;
  if (!this._started) {
    if (this._nonceBytesRead < GCM_NONCE_LENGTH) {
      var nonceRemaining = GCM_NONCE_LENGTH - this._nonceBytesRead;
      chunkOffset = chunkLength <= nonceRemaining ? chunkLength : nonceRemaining;
      chunk.copy(this._nonce, this._nonceBytesRead, 0, chunkOffset);
      chunk = chunk.slice(chunkOffset);
      chunkLength = chunk.length;
      this._nonceBytesRead += chunkOffset;
    }

    if (this._macBytesRead < GCM_MAC_LENGTH) {
      var macRemaining = GCM_MAC_LENGTH - this._macBytesRead;
      chunkOffset = chunkLength <= macRemaining ? chunkLength : macRemaining;
      chunk.copy(this._mac, this._macBytesRead, 0, chunkOffset);
      chunk = chunk.slice(chunkOffset);
      this._macBytesRead += chunkOffset;
    }

    if (this._nonceBytesRead === GCM_NONCE_LENGTH && this._macBytesRead === GCM_MAC_LENGTH) {
      this._decipher = crypto.createDecipheriv('aes-256-gcm', this._key, this._nonce);
      this._decipher.setAuthTag(this._mac);
      this._started = true;
    }
  }

  // We can't use an else because we have no idea how long our chunks will be
  // all we know is that once we've got a nonce and mac decryption can begin
  if (this._started) {
    this.push(this._decipher.update(chunk));
  }

  if (typeof(cb) === 'function') {
    cb();
  }
};