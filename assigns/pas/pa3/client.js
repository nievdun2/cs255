
var lib = require('./lib');
var sjcl = require('./sjcl');

var tls = require('tls');

var client = function(client_sec_key_base64, client_sec_key_password, ca_cert, name) {
  if (typeof(name) === 'undefined') {
    var name = 'client';
  }
  var client_log = lib.log_with_prefix(name);
  var TYPE = lib.TYPE;

  var socket;
  var protocol_state = 'START';

  var ca_cert = ca_cert;

  function unwrap_client_sec_key() {
    var key_enc = lib.base64_to_bitarray(client_sec_key_base64);
    var salt = lib.bitarray_slice(key_enc, 0, 128);
    var key_enc_main = lib.bitarray_slice(key_enc, 128);
    var sk_der = lib.bitarray_slice(lib.KDF(client_sec_key_password, salt), 0, 128);
    var sk_cipher = lib.setup_cipher(sk_der);
    var pair_sec_bits = lib.dec_gcm(sk_cipher, key_enc_main);
    var pair_sec = sjcl.bn.fromBits(pair_sec_bits);
    return new sjcl.ecc['ecdsa'].secretKey(curve, pair_sec);
  }

  function protocol_abort() {
    client_log('protocol error');
    socket.destroy();
    protocol_state = 'ABORT';
  }

  var curve = sjcl.ecc.curves['c256'];

  var client_sec_key = unwrap_client_sec_key();

  var session_callback = null;
  var session_close_callback = null;

  // Helper function to check if an object contains a list of properties
  function check_properties(obj, properties){
    for (var i = 0; i < properties.length; i++) {
      if (!obj.hasOwnProperty(properties[i])) {
        return false;
      }
    }
    return true;
  }

  function check_cert(crt) {
    // Make sure these fields are present in certificate
    required_keys = ['valid_from', 'valid_to', 'issuer', 'subject', 'fingerprint'];
    if (!check_properties(crt, required_keys)){
      protocol_abort();
      return false;
    }
    var now = new Date()
    var from = new Date(crt.valid_from)
    var to = new Date(crt.valid_to)
    var expiration_date = to;
    expiration_date.setDate(expiration_date.getDate() - 7)
    if (!(now.getTime() >= from.getTime() && now.getTime() <= expiration_date.getTime())){
      protocol_abort(); // certificate time invalid
    }

    // Make sure these fields are present in the 'subject' object
    required_keys = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress'];
    if (!check_properties(crt.subject, required_keys)){
      protocol_abort();
      return false;
    }

    return true;
  }

  function process_server_msg(json_data) {
    data = JSON.parse(json_data);
    switch(data.type) {
      case TYPE['CHALLENGE']:

        if (protocol_state != 'START') {
          protocol_abort();
          return;
        }
        protocol_state = 'CHALLENGE';
        // TODO: respond to challenge
        console.log("challenge is " + data.message);
        message_bit = lib.string_to_bitarray(data.message);
        var signature = lib.ECDSA_sign(client_sec_key, message_bit);
        console.log(signature)
        //console.log(lib.bitarray_to_string(signature));
        lib.send_message(socket, TYPE['RESPONSE'], signature);
        break;

      case TYPE['SESSION_MESSAGE']:
        if (protocol_state != 'SUCCESS') {
          protocol_abort();
          return;
        }
        client_log('received session message: ' + data.msg);
        break;

      case TYPE['SUCCESS']:
        if (protocol_state != 'CHALLENGE') {
          protocol_abort();
          return;
        }
        protocol_state = 'SUCCESS';
        if (session_callback != null) {
          session_callback();
        }
        socket.end();
        break;

      default:
        protocol_abort();
        return;
    }
  }

  client = {};

  client.connect = function(host, port, session_callback_f, session_close_callback_f) {
    var client_options = {
      // TODO: Fill in options
      ca: ca_cert,
      host: host
    };
    
    session_callback = session_callback_f;
    socket = tls.connect(port, client_options, function() {
      client_log('connected to server');

      if (!check_cert(socket.getPeerCertificate())) {
        client_log('bad certificate received');
        socket.end();
      }
    });

    socket.setEncoding('utf8');

    socket.on('data', function(msg) {
      process_server_msg(msg)
    });

    socket.on('close', function() {
      protocol_state = 'END';
      client_log('connection closed');

      if (typeof(session_close_callback_f) !== 'undefined') {
        session_close_callback_f();  
      }
    });
  }

  client.get_state = function() {
    return protocol_state;
  }

  client.session_send = function(msg) {
    if (protocol_state != 'SUCCESS') {
      throw ("client: tried to send session message in state: " + protocol_state);
    }
    lib.send_message(socket, TYPE['SESSION_MESSAGE'], msg);
    client_log('sent session message: ' + msg);
  }
  
  client.disconnect = function() {
    protocol_state = 'END';
    socket.end();
  }

  return client;
}

module.exports.client = client;
