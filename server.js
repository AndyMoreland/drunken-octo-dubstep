var lib = require('./lib');
var sjcl = require('./sjcl');

var tls = require('tls');
var fs = require('fs');

var server = function(server_key, server_key_password, server_cert, client_pub_key_base64) {
  var server_log = lib.log_with_prefix('server');
  var TYPE = lib.TYPE;

  var tls_server;
  var socket = null;
  var protocol_state;
	var challenge_bitarray;
	var connection_count = 0;
	var initial_randomness = lib.random_bitarray(256);

  function unwrap_client_pub_key() {
    var pair_pub_pt = sjcl.ecc.curves['c256'].fromBits(
      lib.base64_to_bitarray(client_pub_key_base64));
    return new sjcl.ecc['ecdsa'].publicKey(sjcl.ecc.curves['c256'], pair_pub_pt);
  }

  function protocol_abort() {
    server_log('protocol error');
    socket.destroy();
    protocol_state = 'ABORT';
  }

  var client_pub_key = unwrap_client_pub_key();

	// FIXME is this long enough?
  function get_new_challenge() {
		challenge_bitarray = lib.HMAC(initial_randomness, lib.string_to_bitarray("" + connection_count));
    return lib.bitarray_to_base64(challenge_bitarray);
  }

  function process_client_msg(json_data) {
    var data;
    try {
      data = JSON.parse(json_data);
    } catch (ex) {
      protocol_abort();
      return;
    }

    switch (data.type) {
    case TYPE['RESPONSE']:
      if (protocol_state != 'CHALLENGE') {
        protocol_abort();
        return;
      }

      protocol_state = 'ABORT';

			var response_correct = lib.ECDSA_verify(client_pub_key, challenge_bitarray, lib.base64_to_bitarray(data.message));

      if (response_correct) {
        server_log('authentication succeeded')
        lib.send_message(socket, TYPE['SUCCESS'], '');

        protocol_state = 'SUCCESS';
      } else {
        server_log('authentication failed');
        protocol_abort();
      }
      break;

    case TYPE['SESSION_MESSAGE']:
      if (protocol_state != 'SUCCESS') {
        protocol_abort();
        return;
      }
      server_log('received session message: ' + data.message);
      var l = data.message.length;
      lib.send_message(socket, TYPE['SESSION_MESSAGE'], l);
      server_log('sent session message: ' + l);
      break;

    default:
      protocol_abort();
      break;
    }
  }

  function on_connect(connection_socket) {
    if (socket != null) {
      server_log('rejecting additional client connections');
      connection_socket.end();
      return;
    }

    socket = connection_socket;

    socket.setEncoding('utf8');
    socket.on('data', function(msg) {
      process_client_msg(msg, socket);
    });
    socket.on('end', function(msg) {
      server_log('connection closed');
      socket = null;
    });
		socket.on('error', function(err) {
			protocol_abort();
		});

    server_log('received client connection');

    var challenge = get_new_challenge(); 
    server_log('generated challenge: ' + challenge);

    protocol_state = 'CHALLENGE';
    lib.send_message(socket, TYPE['CHALLENGE'], challenge);
    server_log('sent challenge to client');
		connection_count++;
  }

  server = {};

  server.start = function(port) {
    var server_options = {
			rejectUnauthorized: true,
      key: server_key,
      cert: server_cert,
      passphrase: server_key_password
    };

    tls_server = tls.createServer(server_options, on_connect);

    tls_server.listen(port, function() {
      server_log('listening on port ' + port);

			tls_server.on('close', function() {
				console.warn('closing server');
			});
			
			tls_server.on('clientError', function () {
				console.warn('client error');
			});
    });

  }

  return server;
}

module.exports.server = server;
