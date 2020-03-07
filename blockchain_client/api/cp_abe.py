import io
import struct

from charm.toolbox.pairinggroup import GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as sha

from Crypto.Cipher import AES
from Crypto import Random


def cpabe_setup(group):

    return CPabe_BSW07(group).setup()


def cpabe_keygen(group, msk, mpk, attributes):

    return CPabe_BSW07(group).keygen(mpk, msk, attributes)


def cpabe_encrypt(group, mpk, ptxt, policy):

    cpabe = CPabe_BSW07(group)

    session_key = group.random(GT)
    session_key_ctxt = cpabe.encrypt(mpk, session_key, policy)

    ctxt = io.BytesIO()

    iv = Random.new().read(AES.block_size)
    symcipher = AES.new(sha(session_key)[0:32], AES.MODE_CFB, iv)

    ctxt.write(bytes(iv))

    session_key_ctxt_b = objectToBytes(session_key_ctxt, group)
    ctxt.write(struct.pack('<Q', len(session_key_ctxt_b)))
    ctxt.write(session_key_ctxt_b)

    for b in read_data(bin_data=ptxt, chunksize=AES.block_size):
        ctxt.write(symcipher.encrypt(b))
        ctxt.flush()

    return ctxt.getvalue()


def cpabe_decrypt(group, mpk, deckey, ctxt):
    cpabe = CPabe_BSW07(group)
    ptxt = io.BytesIO()

    iv = ctxt.read(AES.block_size)
    session_key_size = struct.unpack('<Q', ctxt.read(struct.calcsize('Q')))[0]
    session_key_ctxt = bytesToObject(ctxt.read(session_key_size), group)

    session_key = cpabe.decrypt(mpk, deckey, session_key_ctxt)

    if session_key:
        symcipher = AES.new(sha(session_key)[0:32], AES.MODE_CFB, iv)
        for b in read_data(bin_data=ctxt, chunksize=AES.block_size):
            ptxt.write(symcipher.decrypt(b))
            ptxt.flush()
        return ptxt.getvalue()
    else:
        raise PebelDecryptionException("Unable to decrypt given cipher-text.")


# ############################################################################################
"""
            ULTILITIES FUNCTIONS
"""


# ############################################################################################

def write_key_to_file(fname, data, group):
    with io.open(fname, 'wb') as f:
        f.write(objectToBytes(data, group))
        f.flush()


def read_key_from_file(fname, group):
    with io.open(fname, 'rb') as f:
        data = f.read()
    return bytesToObject(data, group)


def read_key_from_content(content, group):
	
    return bytesToObject(content.encode('utf-8'), group)

def read_data(bin_data, chunksize=16):

    with bin_data as src:
        while True:
            data = src.read(chunksize)
            if data:
                yield data
            else:
                break


# ###########################################################################################
"""
                    EXCEPTIONS ERRORS
"""
# ###########################################################################################


class PebelException(Exception):
    """Base class for exceptions within Pebel"""
    pass


class PebelDecryptionException(PebelException):
    """Raised for errors during decryption"""
    pass
