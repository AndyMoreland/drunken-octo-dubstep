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
  var protocol_state;

	// FIXME: could store key on disk -- would allow attacker w/ access to disk to screw you
	// FIXME: if the attacker has access to disk and we didn't use a password, then the attcaker could replace the secret key with their own
  function unwrap_client_sec_key() {
		try {
			var key_enc = lib.base64_to_bitarray(client_sec_key_base64);
			var salt = lib.bitarray_slice(key_enc, 0, 128);
			var key_enc_main = lib.bitarray_slice(key_enc, 128);
			var sk_der = lib.bitarray_slice(lib.KDF(client_sec_key_password, salt), 0, 128);
			var sk_cipher = lib.setup_cipher(sk_der);
			var pair_sec_bits = lib.dec_gcm(sk_cipher, key_enc_main);
			var pair_sec = sjcl.bn.fromBits(pair_sec_bits);
			return new sjcl.ecc['ecdsa'].secretKey(curve, pair_sec);
		} catch (e) {
			console.warn("Failed to load key. Exiting");
			protocol_abort();
		}
  }

  function protocol_abort() {
    client_log('protocol error');
		console.trace("Protocol abort");
    socket.destroy();
    protocol_state = 'ABORT';
  }

  var curve = sjcl.ecc.curves['c256'];

  var client_sec_key = unwrap_client_sec_key();

  var session_callback = null;
  var session_close_callback = null;

  function check_cert(crt) {
		try {
			// Make sure the cert has reasonable properties
			var fields = ["valid_from", "valid_to", "issuer", "subject", "fingerprint"];
			for (var i in fields) {
				if(!crt.hasOwnProperty(fields[i])) { protocol_abort(); }
			}

			var valid_from = new Date(crt.valid_from);
			var valid_to = new Date(crt.valid_to);
			var current_time = new Date();
			var one_week_in_future = new Date(current_time);
			one_week_in_future.setDate(one_week_in_future.getDate() + 7);

			// Make sure that the cert hasn't expired
			if (!(valid_from < current_time) || !(current_time < valid_to)) { protocol_abort(); }

			// Make sure that the cert won't expire in the next week
			if (one_week_in_future > valid_to) { protocol_abort(); }

			var desired_values = {
				C: "US",
				ST: "CA",
				L: "Stanford",
				O: "CS 255",
				OU: "Project 3",
				CN: "localhost",
				emailAddress: "cs255ta@cs.stanford.edu"
			};

			// Check that the certificate is correct
			for (var key in desired_values) {
				if (desired_values.hasOwnProperty(key)) {
					if (desired_values[key] != crt.subject[key]) { protocol_abort(); }
				}
			}

		} catch (e) {
			protocol_abort();
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
			// FIXME make sure this is printable
      lib.send_message(socket, TYPE['RESPONSE'], 
											 lib.bitarray_to_base64(lib.ECDSA_sign(client_sec_key, lib.base64_to_bitarray(data.message))));
      break;

    case TYPE['SESSION_MESSAGE']:
      if (protocol_state != 'SUCCESS') {
        protocol_abort();
        return;
      }
      client_log('received session message: ' + data.message);
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
		// FIXME check
    var client_options = {
      ca: ca_cert,
      host: host,
      port: port,
      rejectUnauthorized: true
    };
    
    session_callback = session_callback_f;
    socket = tls.connect(port, client_options, function() {
      client_log('connected to server');
			protocol_state = 'START';

      if (!check_cert(socket.getPeerCertificate())) {
        client_log('bad certificate received');
				protocol_abort();
      }
    });

		socket.on('error', function (err) {
			protocol_abort();
		});

    socket.setEncoding('utf8');

    socket.on('data', function(msg) {
      process_server_msg(msg)
    });

    socket.on('close', function() {
      client_log('connection closed');
      protocol_state = 'END';

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
