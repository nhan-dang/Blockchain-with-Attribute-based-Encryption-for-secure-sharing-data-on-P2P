'''
title           : blockchain_client.py
description     : A blockchain client implemenation, with the following features
                  - Wallets generation using Public/Private key encryption (based on RSA algorithm)
                  - Generation of transactions with RSA encryption      
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
version         : 0.3
usage           : python blockchain_client.py
                  python blockchain_client.py -p 8080
                  python blockchain_client.py --port 8080
python_version  : 3.6.1
Comments        : Wallet generation and transaction signature is based on [1]
References      : [1] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''

from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import base64
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as cip_PKCS
import sys
import os
from flask import Flask, jsonify, request, render_template
from werkzeug.utils import secure_filename
import struct

from api.cp_abe import(
    cpabe_keygen,
    cpabe_encrypt,
    cpabe_decrypt,
    read_key_from_file,
    read_key_from_content
)
import io
import shutil
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes


class Transaction:

    def __init__(self, sender_address,
                 sender_private_key,
                 recipient_address, iv, sym_key, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        # self.data_owner_address = data_owner_address
        self.iv = iv
        self.sym_key = sym_key
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            # 'data_owner_address': self.data_owner_address,
                            'iv': self.iv,
                            'sym_key': self.sym_key,
                            'value': self.value
                            })

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(
            binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


group = PairingGroup('SS512')

PROJECT_HOME = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = os.path.join(PROJECT_HOME, 'upload')
public_key_folder = os.path.join(PROJECT_HOME, 'public_key')
secret_key_folder = os.path.join(PROJECT_HOME, 'secret_key')
private_key_folder = os.path.join(PROJECT_HOME, 'private_key')
negative_attribute_folder = os.path.join(PROJECT_HOME, 'negative_attribute')
ptxt_folder = os.path.join(PROJECT_HOME, 'ptxt')
ptxt_fname = os.path.join(ptxt_folder, 'ptxt.data')
base64_fname = os.path.join(ptxt_folder, 'b64.data')
music_fname = os.path.join(ptxt_folder, 'ptxt.mp3')
negative_attribute_folder = os.path.join(PROJECT_HOME, 'negative_attribute')
ctxt_folder = os.path.join(PROJECT_HOME, 'ctxt')
ctxt_fname = os.path.join(ctxt_folder, 'ctxt.data')
file_path = os.path.join(negative_attribute_folder,
                         'negative_attribute_file')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


@app.route('/encryption')
def configure():
    return render_template('./encryption.html')


@app.route('/decryption')
def encryption():
    return render_template('./decryption.html')


@app.route('/decryption/get/abe/request')
def decryption_abe_request():
    return render_template('./decryption_get_abe.html')


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.
                                        exportKey(format='DER')).
        decode('ascii'),
        'public_key': binascii.hexlify(public_key.
                                       exportKey(format='DER')).
        decode('ascii')
    }

    return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    public_key_raw = os.path.join(public_key_folder, 'mpk.key')
    public_key_data = read_key_from_file(public_key_raw, group)
    secret_key_raw = os.path.join(secret_key_folder, 'msk.key')
    secret_key_data = read_key_from_file(secret_key_raw, group)
    attributes_list = []

    sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    data_owner_address = request.form['data_owner_address']

    attributes_list.append(
        data_owner_address.upper())
    attributes_list.append(
        recipient_address.upper())

    ABE_private_key = cpabe_keygen(group,
                                   secret_key_data,
                                   public_key_data,
                                   attributes_list)

    RSA_public_key = RSA.importKey(binascii.unhexlify(recipient_address))

    asym_cipher = cip_PKCS.new(RSA_public_key)

    iv = Random.new().read(AES.block_size)

    sym_key = Random.get_random_bytes(AES.block_size)

    sym_cipher = AES.new(sym_key, AES.MODE_CFB, iv)

    value = objectToBytes(ABE_private_key, group)

    enc_val = sym_cipher.encrypt(value)

    enc_iv = asym_cipher.encrypt(iv)

    enc_sym_key = asym_cipher.encrypt(sym_key)

    transaction = Transaction(
        sender_address, sender_private_key,
        recipient_address, str((base64.b64encode(enc_iv)).decode()),
        str((base64.b64encode(enc_sym_key)).decode()), str((base64.b64encode(enc_val)).decode()))

    response = {'transaction': transaction.to_dict(),
                'data_owner_address': data_owner_address,
                'signature': transaction.sign_transaction()}

    return jsonify(response), 200


@app.route('/data/encrypt', methods=['POST'])
def encrypt_data():
    input_files = request.files
    input_text = request.form
    public_key = input_files['public_key']
    file_encrypt = input_files['data_encrypted']
    policy = input_text.get('policy')

    pk_filename = secure_filename(public_key.filename)
    fe_filename = secure_filename(file_encrypt.filename)
    public_key.save(os.path.join(app.config['UPLOAD_FOLDER'], pk_filename))
    file_encrypt.save(os.path.join(app.config['UPLOAD_FOLDER'], fe_filename))

    ptxt = io.open(os.path.join(app.config['UPLOAD_FOLDER'],
                                fe_filename), 'rb')
    b64_ptxt = base64.b64encode(ptxt.read())
    ptxt.close()

    try:
        file = io.open(base64_fname, 'wb')
        file.write(b64_ptxt)
        file.flush()
    except error:
        print('Something went wrong!')
        sys.exit(0)

    ptxt_b64 = io.open(base64_fname, 'rb')

    mpk_raw = read_key_from_file(os.path.join(
        app.config['UPLOAD_FOLDER'], pk_filename), group)

    ctxt = cpabe_encrypt(group, mpk_raw,
                         ptxt_b64, policy.upper())

    with io.open(ctxt_fname, 'wb') as ctxt_file:
        for b in ctxt:
            ctxt_file.write(bytes([b]))
            ctxt_file.flush()

    shutil.copy(ctxt_fname, '{}/static'.format(PROJECT_HOME))
    response = {'down_link': "http://localhost:8080/static/ctxt.data"}
    return jsonify(response), 200


@app.route('/data/decrypt', methods=['POST'])
def decrypt_data():
    input_files = request.files
    input_text = request.form
    public_key = input_files['public_key']
    file_encrypt = input_files['data_encrypted']
    private_key = input_text['private_key']  # input_files['private_key']
    public_key_revoke = input_text.getlist('public_key_revoke')

    fe_filename = secure_filename(file_encrypt.filename)
    file_encrypt.save(os.path.join(app.config['UPLOAD_FOLDER'],
                                   fe_filename))
    ctxt = io.open(os.path.join(app.config['UPLOAD_FOLDER'],
                                fe_filename), 'rb')

    pk_filename = secure_filename(public_key.filename)
    public_key.save(os.path.join(app.config['UPLOAD_FOLDER'], pk_filename))
    mpk = read_key_from_file(os.path.join(
        app.config['UPLOAD_FOLDER'], pk_filename), group)

    prvk = read_key_from_content(private_key, group)

    for negative_attribute in public_key_revoke:
        if negative_attribute.split('\r')[0].upper() in prvk['S']:
            response = {'down_link': "Your key has already been revoked"}
            return jsonify(response), 200
        else:
            continue

    ptxt_raw = cpabe_decrypt(group, mpk,
                             prvk,
                             ctxt)

    with io.open(ptxt_fname, 'wb') as ptxt:
        for b in ptxt_raw:
            ptxt.write(bytes([b]))
            ptxt.flush()

    with io.open(ptxt_fname, 'rb') as ptxt_b64:
        b = base64.b64decode(ptxt_b64.read())
        with io.open(music_fname, 'wb') as mp3:
            mp3.write(b)
            mp3.flush()

    shutil.copy(music_fname, '{}/static'.format(PROJECT_HOME))
    response = {'down_link': "http://localhost:8080/static/ptxt.mp3"}
    return jsonify(response), 200


@app.route('/decrypt/get/abe', methods=['POST'])
def decrypt_encrypted_abe():
    input_text = request.form
    iv = input_text['iv']
    sym_key = input_text['sym_key']
    abe = input_text['abe_private_key']
    wallet_private_key = input_text['rsa_private_key']

    dsize = SHA.digest_size
    sentinel = Random.new().read(15 + dsize)

    iv_raw = base64.b64decode(iv.encode())
    sym_key_raw = base64.b64decode(sym_key.encode())
    abe_raw = base64.b64decode(abe.encode())
    private_key_raw = RSA.importKey(
        binascii.unhexlify(wallet_private_key))

    cipher = cip_PKCS.new(private_key_raw)
    iv_ori = cipher.decrypt(iv_raw, sentinel)
    sym_key_ori = cipher.decrypt(sym_key_raw, sentinel)
    symcipher = AES.new(sym_key_ori, AES.MODE_CFB, iv_ori)

    abe_ori = symcipher.decrypt(abe_raw)

    response = {'msg': str(abe_ori.decode())}
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
