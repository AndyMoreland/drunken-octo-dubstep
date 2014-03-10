
var lib = require('./lib');
var sjcl = require('./sjcl');

var tls = require('tls');

var server = function(server_key, server_key_password, server_cert, client_pub_key_base64) {
  var server_log = lib.log_with_prefix('server');
  var TYPE = lib.TYPE;

  var tls_server;
  var socket = null;
  var protocol_state;

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

  function get_new_challenge() {
    // TODO: generate challenge
    return 'what is your favorite color?';
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
        var response_correct = false;
        // TODO: check challenge response
        response_correct = true;
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

    server_log('received client connection');

    var challenge = get_new_challenge(); 
    server_log('generated challenge: ' + challenge);

    protocol_state = 'CHALLENGE';
    lib.send_message(socket, TYPE['CHALLENGE'], challenge);
    server_log('sent challenge to client');
  }

  server = {};

  server.start = function(port) {
    var server_options = {
      // TODO: initialize TLS server options
      key: null,
      cert: null,
      passphrase: null
    };

    tls_server = tls.createServer(server_options, on_connect);

    tls_server.listen(port, function() {
      server_log('listening on port ' + port);
    });
  }

  return server;
}

module.exports.server = server;
