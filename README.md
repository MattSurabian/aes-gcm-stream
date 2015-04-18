# aes-gcm-stream
A NodeJS Module with no dependencies that implements AES256 GCM encryption and decryption using streams.
This module requires node v.0.12.0+ as it relies on its updated crypto library.

## Installation
This module can be brought into your project using NPM:

```
npm install aes-gcm-stream --save
```

## Why does this module exist?
It's non-trivial to use GCM mode in NodeJS for more than simple string and buffer data. By implementing
GCM encryption and decryption as transform streams it's easier to do complex tasks like encrypting data
coming from child processes (like database dumps) or files while still using authenticated encryption.

## What is authenticated encryption and why should I care?
Authenticated encryption is a way of ensuring both confidentially AND integrity of data. Using GCM
we can be certain that the cipher text has not been tampered with and that only someone in possession
of the secret key could have been the author.

## What are the downsides to this module?
The main downside is that the entirety of the data you're trying to encrypt at any one time needs to fit
in memory. So if your data is very large and/or you're memory constrained this module will probably not
be a good fit. To authenticate and decrypt data secured with GCM both the nonce used during encryption and
the MAC generated by the encryption cipher are needed BEFORE decryption can begin. This is what makes
using GCM mode with streams in Node so painful in the first place.

This module handles that by having the encrypter store all of the encrypted cipher text in memory
until the stream is flushed. At which point the MAC is computed and sent through the stream followed by
the entirety of the encrypted cipher text. This allows the decrypter to assume the
first 28 bytes it receives are a 12 byte nonce and 16 byte MAC.

## Usage Examples
Robustly documented usage examples are provided in the [examples directory](https://github.com/MattSurabian/aes-gcm-stream/tree/master/examples) of the repository.
 - [With files](https://github.com/MattSurabian/aes-gcm-stream/blob/master/examples/with-a-file.js)
 - [With strings/buffers](https://github.com/MattSurabian/aes-gcm-stream/blob/master/examples/with-strings.js)
 - [Writing/reading keys to and from disk](https://github.com/MattSurabian/aes-gcm-stream/blob/master/examples/read-write-key-file.js)
 - [What happens when decryption fails](https://github.com/MattSurabian/aes-gcm-stream/blob/master/examples/failed-decryption.js)

Each of these examples can be run using node, and are intended to be run from the examples directory:

```
cd examples
node with-strings.js
```

### Keys
Helper methods are provided to generate encoded keys which can be written to disk or STDOUT. A key
MUST be passed via the options hash to the encrypter and decrypter. Keys should be kept safe and
shared securely. See the examples directory for code to read encoded keys from disk and use them.

### Nonces
The encrypter can be explicitly passed a nonce in the constructor's options object, if one is
not passed in, one will be securely generated automatically. It's recommended that you allow the
encrypter to generate its own nonce as it hopefully discourages reuse of the same nonce for additional
encryption streams.

### Calling End
Remember that if you're not using `pipe` to get data into the encrypter but are explicitly calling
`write` on the stream, it's necessary to also explicitly call `end` on the stream before cipher text
will be output. Prior to the stream being flushed only the nonce will be output. The [with-strings.js
example file](https://github.com/MattSurabian/aes-gcm-stream/blob/master/examples/with-strings.js) shows this in detail.

If you're using `pipe` then flushing will happen automatically. See the [with-a-file.js example](https://github.com/MattSurabian/aes-gcm-stream/blob/master/examples/with-a-file.js) for more.

## Contributing
Issues and pull requests are welcome! If you're interested in opening a PR please ensure `jscs` and `jshint` compliance.