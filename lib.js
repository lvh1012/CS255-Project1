"use strict";

var sjcl = require("./sjcl");


////////////////////////////////////////////////////////////////////////////////
//  Cryptographic primitives
////////////////////////////////////////////////////////////////////////////////


var KDF = function(password, salt) {
  // Runs PBDKF2. Password is a string, and salt is a bitarray (see below for more on bitarrays).
  // Returns a bitarray.
  return sjcl.misc.pbkdf2(password, salt, 100000);
  // Takes about a second on a commodity laptop.
};

var HMAC = function(key, data) {
  // Returns the HMAC on the data.
  // key is a bitarray, while data can be a
  // bitarray or a string.
  return (new sjcl.misc.hmac(key)).encrypt(data);
};

var SHA256 = function(bitarray) {
  return sjcl.hash.sha256.hash(bitarray);
};

var setupCipher = function(secretKey) {
  // Takes a secret key (for AES-128) and initializes SJCL's internal
  // cipher data structure.
  if (bitarrayLen(secretKey) != 128) {
    throw "setupCipher: only accepts keys for AES-128";
  }
  return new sjcl.cipher.aes(secretKey);
};

var encryptWithGCM = function(cipher, plaintext, authenticatedData) {
  // Encrypts using the GCM mode.
  // Note that the first argument must be a cipher data structure
  // (initialized by setupCipher).
  // plaintext has to be a bitarray of the message you want to encrypt.
  // authenticatedData is an optional argument (can be a string of bitarray).
  // The authenticatedData is not encrypted into the ciphertext, but it will
  // not be possible to decrypt the ciphertext unless it is passed.
  // (If there is no authenticatedData passed when encrypting, then it is not
  // necessary while decrypting.)
  var iv = randomBitarray(128);
  var v = sjcl.mode.gcm.encrypt(cipher, plaintext, iv, authenticatedData);
  var ciphertext = sjcl.bitArray.concat(iv, v);
  return ciphertext;
};

var decryptWithGCM = function(cipher, ciphertext, authenticatedData) {
  // Decrypts using the GCM mode.
  // Note that the first argument must be a cipher data structure
  // (initialized by setupCipher).
  // ciphertext has to be the output of a call to encryptWithGCM
  // authenticatedData is optional, but if it was passed when
  // encrypting, it has to be passed now, otherwise the decrypt will fail.
  var iv = sjcl.bitArray.bitSlice(ciphertext, 0, 128);
  var c = sjcl.bitArray.bitSlice(ciphertext, 128);
  return sjcl.mode.gcm.decrypt(cipher, c, iv, authenticatedData);
};




////////////////////////////////////////////////////////////////////////////////
//  Conversions between data representations
////////////////////////////////////////////////////////////////////////////////

// Note that "bitarray" is a special SJCL-internal data structure.
// It is /not/ just an array of 0/1 values.

var bitarraySlice = function(bitarray, a, b) {
  // Returns bits [a,...,b) (half-open interval)
  //   -- i.e., slice(01010001, 1, 4) = 101
  return sjcl.bitArray.bitSlice(bitarray, a, b);
};

var bitarrayToString = function(bitarray) {
  return sjcl.codec.utf8String.fromBits(bitarray);
};

var stringToBitarray = function(str) {
  return sjcl.codec.utf8String.toBits(str);
};

var bitarrayToHex = function(bitarray) {
  return sjcl.codec.hex.fromBits(bitarray);
};

var hexToBitarray = function(hexStr) {
  return sjcl.codec.hex.toBits(hexStr);
};

var bitarrayToBase64 = function(bitarray) {
  return sjcl.codec.base64.fromBits(bitarray);
};

var base64ToBitarray = function(base64Str) {
  // Throws an exception if the string is not valid base64.
  return sjcl.codec.base64.toBits(base64Str);
};

var byteArrayToHex = function(a) {
  var s = "";
  for (var i = 0; i < a.length; i++) {
    if (a[i] < 0 || a[i] >= 256) {
      throw "byteArrayToHex: value outside byte range";
    }
    s += ((a[i]|0) + 256).toString(16).substr(1);
  }
  return s;
};

var hexToByteArray = function(s) {
  var a = [];
  if (s.length % 2 != 0) {
    throw "hexToByteArray: odd length";
  }
  for (var i = 0; i < s.length; i += 2) {
    a.push(parseInt(s.substr(i,2),16)|0);
  }
  return a;
};

// Internal: you should not need this function.
var wordToBytesAcc = function(word, bytes) {
  // word is a nonnegative integer, at most 2^31-1
  if (word < 0) {
    throw "wordToBytesAcc: can't convert negative integer";
  }
  for (var i = 0; i < 4; i++) {
    bytes.push(word & 0xff);
    word = word >>> 8;
  }
};

// Internal: you should not need this function.
var wordFromBytesSub = function(bytes, i_start) {
  if (!Array.isArray(bytes)) {
    console.log(bytes);
    console.trace();
    throw "wordFromBytesSub: received non-array";
  }
  if (bytes.length < 4) {
    throw "wordFromBytesSub: array too short";
  }
  var word = 0;
  for (var i = i_start + 3; i >= i_start; i--) {
    word <<= 8;
    word |= bytes[i];
  }
  return word;
};




////////////////////////////////////////////////////////////////////////////////
//  Conversions including padding
////////////////////////////////////////////////////////////////////////////////

var stringToPaddedByteArray = function(inputStr, paddedLen) {
  if (typeof(inputStr) !== "string") {
    throw "to_padded_byte_array: received non-string";
  }
  var s = unescape(encodeURIComponent(inputStr));
  var l = s.length;
  if (l > paddedLen) {
    throw "to_padded_byte_array: string too long";
  }
  var bytes = [];
  wordToBytesAcc(l, bytes);
  for (var i = 0; i < paddedLen; i++) {
    // Note: in general, this kind of code may be vulnerable to timing attacks
    // (not considered in our threat model).  For our use case, these attacks
    // do not seem relevant (nor is it clear how one could mitigate them, since
    // the user will eventually manipulate passwords in memory in the clear).
    if (i < l) {
      bytes.push(s.charCodeAt(i));
    } else {
      bytes.push(0);
    }
  }
  return bytes;
};

var stringToPaddedBitarray = function(inputStr, paddedLen) {
  return sjcl.codec.hex.toBits(
    byteArrayToHex(stringToPaddedByteArray(inputStr, paddedLen)));
};

var paddedByteArrayToString = function(a, paddedLen) {
  if (a.length != paddedLen + 4) {
    throw "paddedByteArrayToString: wrong length";
  }
  var l = wordFromBytesSub(a, 0);
  var s = "";
  for (var i = 4; i < Math.min(4 + l, a.length); i++) {
    s += String.fromCharCode(a[i]);
  }
  var s_utf8 = decodeURIComponent(escape(s));
  return s_utf8;
};

var paddedBitarrayToString = function(a, paddedLen) {
  return paddedByteArrayToString(
    hexToByteArray(sjcl.codec.hex.fromBits(a)), paddedLen)
};




////////////////////////////////////////////////////////////////////////////////
//  Other utility functions
////////////////////////////////////////////////////////////////////////////////

var randomBitarray = function(len) {
  if (len % 32 != 0) {
    throw "random_bit_array: len not divisible by 32";
  }
  return sjcl.random.randomWords(len / 32, 0);
};

var bitarrayEqual = function(a1, a2) {
  return sjcl.bitArray.equal(a1, a2);
};

var bitarrayLen = function(a) {
  return sjcl.bitArray.bitLength(a);
};

var bitarrayConcat = function(a1, a2) {
  return sjcl.bitArray.concat(a1, a2);
};

var objectHasKey = function(obj, key) {
    return obj.hasOwnProperty(key);
};

module.exports = {
    KDF: KDF,
    HMAC: HMAC,
    SHA256: SHA256,
    setupCipher: setupCipher,
    encryptwithGCM: encryptWithGCM,
    decryptWithGCM: decryptWithGCM,
    bitarraySlice: bitarraySlice,
    bitarrayToString: bitarrayToString,
    stringToBitarray: stringToBitarray,
    bitarrayToBase64: bitarrayToBase64,
    base64ToBitarray: base64ToBitarray,
    stringToPaddedBitarray: stringToPaddedBitarray,
    paddedBitarrayToString: paddedBitarrayToString,
    randomBitarray: randomBitarray,
    bitarrayEqual: bitarrayEqual,
    bitarrayLen: bitarrayLen,
    bitarrayConcat: bitarrayConcat,
    objectHasKey: objectHasKey
};
