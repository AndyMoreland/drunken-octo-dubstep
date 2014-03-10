
var lib = require("./lib");
var sjcl = require("./sjcl");

function proc(password) {
  var curve = sjcl.ecc.curves['c256'];
  var pair_sec = sjcl.bn.random(curve.r);
  var pair_sec_bits = pair_sec.toBits();
  var pair_pub_bits = curve.G.mult(pair_sec).toBits();
  var output = {};
  output.pub = lib.bitarray_to_base64(pair_pub_bits);
  var salt = lib.random_bitarray(128);
  var sk_der = lib.bitarray_slice(lib.KDF(password, salt), 0, 128);
  var sk_cipher = lib.setup_cipher(sk_der);
  var pair_sec_enc = lib.enc_gcm(sk_cipher, pair_sec_bits);
  output.sec = lib.bitarray_to_base64(lib.bitarray_concat(salt, pair_sec_enc));

  process.stdout.write(JSON.stringify(output));
  process.stdout.write('\n');
  process.exit();
}

process.stdin.resume();
process.stdin.once('data', function(data) {
  password = data.toString().trim();
  proc(password);
});
