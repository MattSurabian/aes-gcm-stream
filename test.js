'use strict';

var Benchmark = require('benchmark');
var suite = new Benchmark.Suite();
var test = require('tape');
var aesgcm = require('./');
var stream = require('stream');
var util = require('util');

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

test('mixed up chunks', function(t) {
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
  encrypt.pipe(new MixingStream()).pipe(decrypt).on('data', function(d) {
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
test('incorect tag', function(t) {
  t.plan(2);
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
  function onError (e) {
    t.error(e);
  }
  encrypt.pipe(new MixingStream(true)).pipe(decrypt).on('data', function(d) {
    outData.push(d.toString());
  }).on('finish', function() {
    t.notEqual(data.join(''), outData.join(''));
  }).on('error', onError);
  data.forEach(function(s) {
    encrypt.write(s);
  });
  decrypt.removeListener('error', onError);
  decrypt.on('error', function(e) {
    t.ok(e, 'throws');
  });
  encrypt.end();
});

test('benchmark relationships', function(t) {
  var key = aesgcm.createEncodedKey();
  var config = {
    key: key
  };
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

  var setupBenchmarkEncrypt = aesgcm.encrypt(config);
  setupBenchmarkEncrypt.on('data', function(d) {
    outData.push(d);
  });

  /**
   * Because Benchmark doesn't support asynchronous setup (or teardown)
   * we need to only run the benchmark tests after we have some cipherText
   * to decrypt. Otherwise we won't be able to run the decrypt benchmark test,
   * or will get unexpected output.
   */
  setupBenchmarkEncrypt.on('end', function() {
    suite.add('Encryption', function() {
      var encrypt = aesgcm.encrypt(config);

      data.forEach(function(d) {
        encrypt.write(d);
      });

      encrypt.end();

    }).add('Decryption', function() {

      var decrypt = aesgcm.decrypt(config);
      var pt = [];
      decrypt.on('data', function(d) {
        pt.push(d.toString());
      }).on('error', function(err) {
        t.fail('Decryption Benchmark ' + err);
        suite.abortSuite();
      });

      outData.forEach(function(d) {
        decrypt.write(d);
      });
      decrypt.end();

    }).add('Key Generation', function() {

      aesgcm.createKeyBuffer();

    }).on('cycle', function(event) {

      if (event.target.count > 0) {
        t.ok(true, String(event.target));
      } else {
        t.fail(String(event.target) + ' Benchmark test failed.');
      }

    }).on('complete', function() {

      t.deepEqual(this.filter('slowest').pluck('name'), ['Key Generation'], 'Key generation should be ' +
        'much slower than encryption and decryption');
      t.end();

    });

    suite.run();
  });

  data.forEach(function(d) {
    setupBenchmarkEncrypt.write(d);
  });
  setupBenchmarkEncrypt.end();
});

function MixingStream(evil) {
  stream.Transform.call(this);
  this.previous = null;
  this.evil = !!evil;
}
util.inherits(MixingStream, stream.Transform);
MixingStream.prototype._transform = function(chunk, _, next) {
  var previous = this.previous;
  var mid = ~~(chunk.length / 2);
  var start = chunk.slice(0, mid);
  this.previous = chunk.slice(mid);
  if (previous) {
    this.push(Buffer.concat([previous, start]));
  } else {
    this.push(start);
  }
  next();
};

MixingStream.prototype._flush = function(next) {
  if (this.previous) {
    if (this.evil) {
      this.previous[0] = ~this.previous[0];
    }
    this.push(this.previous);
  }
  next();
};
