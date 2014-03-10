#!/usr/bin/env python2

import getpass
import json
import os
import subprocess
import sys

def run(cmd, inputs=None):
    print >>sys.stderr, '-- Run:', cmd
    #raw_input()
    ret = None
    if inputs is None:
        ret = subprocess.call(cmd)
    else:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        for s in inputs:
            p.stdin.write(s)
            p.stdin.write('\n')
        out, err = p.communicate()
        ret = p.returncode
    if ret != 0:
        print >>sys.stderr, ' *** Command failed; return value', ret
        sys.exit(1)

def run_p(cmd_str, inputs=None):
    run(cmd_str.split(' '), inputs)

def log(s):
    print >>sys.stderr, s


CA_KEY_PASSWORD = getpass.getpass('CA key password: ')
SERVER_KEY_PASSWORD = getpass.getpass('Server key password: ')
CLIENT_KEY_PASSWORD = getpass.getpass('Client key password: ')

run_p('mkdir -p data')

log('Generating private key for CA.')
run_p('openssl req -passout stdin -new -x509 -days 365 -config conf/rootCA.cnf -keyout data/rootCA.key -out data/rootCA.pem',
      [CA_KEY_PASSWORD])

log('Generating server key pair.')
run_p('openssl genrsa -passout stdin -aes128 -out data/server.key 2048',
      [SERVER_KEY_PASSWORD])

log('Generating signed certificate for server.')
run_p('openssl req -new -config conf/server.cnf -passin stdin -key data/server.key -out data/server.csr',
      [SERVER_KEY_PASSWORD])
run_p('openssl x509 -req -days 365 -passin stdin -in data/server.csr -CA data/rootCA.pem '
      '-CAkey data/rootCA.key -CAcreateserial -out data/server.crt',
      [CA_KEY_PASSWORD])

log('Verify certificate properly signed.')
run_p('openssl verify -CAfile data/rootCA.pem data/server.crt')

SCRIPT_DIR = os.path.realpath(os.path.dirname(sys.argv[0]))

os.chdir(SCRIPT_DIR)

p = subprocess.Popen(['node', './gen_client_keys.js'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
p.stdin.write(CLIENT_KEY_PASSWORD)
p.stdin.write('\n')
client_keys = json.load(p.stdout)

p.communicate()
if p.returncode != 0:
    print >>sys.stderr, 'generation of client key pair failed; return code', p.returncod

with open('data/client_sec_key', 'wb') as f_sec:
    f_sec.write(client_keys['sec'])
    f_sec.write('\n')

with open('data/client_pub_key', 'wb') as f_pub:
    f_pub.write(client_keys['pub'])
    f_pub.write('\n')
