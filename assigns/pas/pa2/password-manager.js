"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    // get salt
    // make master kdf from password and salt
    priv.data.version = "CS 255 Password Manager v1.0";
    priv.secrets.salt = random_bitarray(32);
    var master_key = KDF(password, priv.secrets.salt);
    var parts = split(master_key);
    priv.secrets.k_hmac = parts[0];
    priv.secrets.k_enc = parts[1];
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    if (trusted_data_check !== undefined) {
      var repr_hash = SHA256(string_to_bitarray(repr));
      var check_matches = bitarray_equal(string_to_bitarray(repr_hash), string_to_bitarray(trusted_data_check));
      if (!check_matches) {
        throw "SHA-256 check did not pass";
      }
    }

    var manager = JSON.parse(repr);
    var verification = manager['verification'];
    var master_key = KDF(password, manager['master_salt']);
    var parts = split(master_key);
    var gcm_cipher = setup_cipher(parts[0]);

    // If the wrong master password is provided, this operation
    // will fail, so we will not complete load()
    priv.data.version = dec_gcm(gcm_cipher, verification);
    keychain = manager['keychain'];
    priv.secrets.k_hmac = parts[0];
    priv.secrets.k_enc = parts[1];
    priv.secrets.salt = manager['master_salt'];
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
    var gcm_cipher = setup_cipher(priv.secrets.k_hmac);

    var tag = string_to_bitarray(priv.data.version)
    var verification = enc_gcm(gcm_cipher, tag);
    var to_save = {
      'keychain': keychain,
      'verification': verification,
      'master_salt': priv.secrets.salt
    }
    var keychain_string = JSON.stringify(to_save);
    var hash = SHA256(string_to_bitarray(keychain_string));
    return [keychain_string, hash];
  }

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
    var hmaced_name = HMAC(priv.secrets.k_hmac, name);
    var enc_value = keychain[hmaced_name];
    if (enc_value == undefined) {
      return null;
    }
    var key_binded_to_name = HMAC(priv.secrets.k_enc, hmaced_name);
    key_binded_to_name = split(key_binded_to_name)[0];
    var gcm_cipher = setup_cipher(key_binded_to_name);
    var password_candidate = dec_gcm(gcm_cipher, enc_value)
    return string_from_padded_bitarray(password_candidate, MAX_PW_LEN_BYTES);

  }

  var split = function(array) {
    var len = bitarray_len(array);
    var front = bitarray_slice(array, 0, len/2);
    var back = bitarray_slice(array, len/2, len);
    return [front, back];
  }

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
    var hmaced_name = HMAC(priv.secrets.k_hmac, name);
    var key_binded_to_name = HMAC(priv.secrets.k_enc, hmaced_name);
    key_binded_to_name = split(key_binded_to_name)[0] //need it to be 128 bits
    var gcm_cipher = setup_cipher(key_binded_to_name);

    var value_bit_array = string_to_padded_bitarray(value, MAX_PW_LEN_BYTES);
    var enc_value = enc_gcm(gcm_cipher, value_bit_array);
    keychain[hmaced_name] = enc_value;
  }

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
    var hmaced_name = HMAC(priv.secrets.k_hmac, name);
    var enc_value = keychain[hmaced_name];
    if (enc_value == undefined) {
      return false;
    }
    return delete keychain[hmaced_name];
  }

  return keychain;
}

module.exports.keychain = keychain;
