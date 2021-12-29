"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setupCipher = lib.setupCipher,
    encryptwithGCM = lib.encryptwithGCM,
    decryptWithGCM = lib.decryptWithGCM,
    bitarraySlice = lib.bitarraySlice,
    bitarrayToString = lib.bitarrayToString,
    stringToBitarray = lib.stringToBitarray,
    bitarrayToBase64 = lib.bitarrayToBase64,
    base64ToBitarray = lib.base64ToBitarray,
    stringToPaddedBitarray = lib.stringToPaddedBitarray,
    paddedBitarrayToString = lib.paddedBitarrayToString,
    randomBitarray = lib.randomBitarray,
    bitarrayEqual = lib.bitarrayEqual,
    bitarrayLen = lib.bitarrayLen,
    bitarrayConcat = lib.bitarrayConcat,
    objectHasKey = lib.objectHasKey;


/********* Implementation ********/


var keychainClass = function() {

  // Private instance variables.
    
  // Use this variable to store everything you need to.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  var AES_KEY_LENGTH_BITS = 128;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  var kdf_salt = "6LmX8nEstYPvKQB9"

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    priv.secrets.salt = stringToBitarray(kdf_salt); 
    var master_key = KDF(password, priv.secrets.salt);

    priv.secrets.key_auth = bitarraySlice(HMAC(master_key,"AUTH KEY"), 0, AES_KEY_LENGTH_BITS);
    priv.secrets.key_hmac = bitarraySlice(HMAC(master_key,"HMAC KEY"), 0, AES_KEY_LENGTH_BITS);
    priv.secrets.key_gcm  = bitarraySlice(HMAC(master_key,"GCM KEY"),  0, AES_KEY_LENGTH_BITS);

    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trustedDataCheck) {
    ready = false;
	  if (trustedDataCheck = undefined || !bitarrayEqual(stringToBitarray(SHA256(stringToBitarray(repr))),stringToBitarray(trustedDataCheck))){
	    throw "Failed integrity check.";
    }

	  var data = JSON.parse(repr).kvs;
    var auth_message = JSON.parse(repr).auth_message;
    var salt = stringToBitarray(kdf_salt);
    var master_key = KDF(password, salt);
    var key_auth = bitarraySlice(HMAC(master_key,"AUTH KEY"), 0, AES_KEY_LENGTH_BITS);
    var cipher = setupCipher(key_auth);
    try {
      var authenticated_output = decryptWithGCM(cipher, auth_message);  
    } catch(err) {
      return false;
    }   
    if (!bitarrayEqual(authenticated_output, stringToBitarray("AUTHENTICATE"))) 
      return false;

    priv.secrets.salt = salt;
    priv.secrets.key_auth = key_auth;
    priv.secrets.key_hmac = bitarraySlice(HMAC(master_key,"HMAC KEY"), 0, AES_KEY_LENGTH_BITS);
    priv.secrets.key_gcm  = bitarraySlice(HMAC(master_key,"GCM KEY"),  0, AES_KEY_LENGTH_BITS);

    // delete data["auth_message"];
    priv.data = {...data};

    ready = true;
    return true;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
  	if (ready) {
  		var auth_message = encryptwithGCM(setupCipher(priv.secrets.key_auth), stringToBitarray("AUTHENTICATE"));
      var data_str = JSON.stringify({kvs: priv.data, auth_message})
  		var SHA_hash = lib.SHA256(stringToBitarray(data_str));
  		return [data_str , SHA_hash];
    }
    else{
      return null;  
    }
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if (ready) {
		  var hmac_domain = HMAC(priv.secrets.key_hmac, name); 
		  if(!(hmac_domain in priv.data)) return null;	
		
      var ciphertext = priv.data[hmac_domain];
      var cipher = setupCipher(priv.secrets.key_gcm);	 
      var plaintext = decryptWithGCM(cipher, ciphertext);
      var padded_pwd = bitarraySlice(plaintext, 0, bitarrayLen(plaintext)-bitarrayLen(hmac_domain));
      var verification_hmac = bitarraySlice(plaintext, bitarrayLen(plaintext)-bitarrayLen(hmac_domain), bitarrayLen(plaintext));
      if(!bitarrayEqual(hmac_domain, verification_hmac)) {
        throw "SWAPPING ATTACK DETECTED!"
      }
      var password = paddedBitarrayToString(padded_pwd, MAX_PW_LEN_BYTES);
      return password;
    } else {
      throw "Keychain not initialized.";
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if (ready) {
      var hmac_domain = HMAC(priv.secrets.key_hmac, name);
      var cipher = setupCipher(priv.secrets.key_gcm);
      var padded_pwd = stringToPaddedBitarray(value, MAX_PW_LEN_BYTES);
      padded_pwd = bitarrayConcat(padded_pwd, hmac_domain);
      var ciphertext = encryptwithGCM(cipher, padded_pwd);
      priv.data[hmac_domain] = ciphertext;
      console.log()
    } else {
      throw "Keychain not initialized.";
    }
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
  	if (ready) {
  		var hmac_domain = HMAC(priv.secrets.key_hmac, name);
      if(hmac_domain in priv.data) {
  			delete priv.data[hmac_domain];
  			return true;
  		}
      else{
        return false;
      }
  	} else {
      throw "Keychain not initialized.";      
    }
  };

  return keychain;
};


module.exports.keychain = keychainClass;
