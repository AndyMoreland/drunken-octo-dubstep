
// Change these for testing:
var test_server_key_password = 'serverpw';
var test_client_key_password = 'clientpw';



var server = require('./server');
var client = require('./client');

var fs = require('fs');

var server_key = fs.readFileSync('data/server.key');
var server_crt = fs.readFileSync('data/server.crt');
var ca_crt = fs.readFileSync('data/rootCA.pem')

var client_pub_key_base64 = fs.readFileSync('data/client_pub_key').toString('utf8');
var client_sec_key_base64 = fs.readFileSync('data/client_sec_key').toString('utf8');

var server1 = server.server(server_key, test_server_key_password,
                server_crt, client_pub_key_base64);

var client1 = client.client(client_sec_key_base64, test_client_key_password,
                ca_crt, 'client 1');

var port = 8000;

server1.start(port);

client1.connect('localhost', port, function() {
  client1.session_send('Hello World!');
  client1.disconnect();
}, function() {
  console.log('client disconnected');
});
