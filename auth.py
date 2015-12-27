# CRYPTOGRAPHY MODULE
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions


def _get_privatekey(path):
    # TODO: 
    # handle encrypted keys
    with open(path, 'rb') as kfile:
        pk = serialization.load_pem_private_key(
                kfile.read(),
                password=None,
                backend=default_backend()
                )
        return pk

def _public_key(content):
    pk = serialization.load_ssh_public_key(
            content,
            backend=default_backend()
            )
    return pk

def sign(message, kpath):
    pk = _get_privatekey(kpath)
    signer = pk.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
    signer.update(message)
    return base64.b64encode(signer.finalize())

def verify(signature, message, key):
    pk = _public_key(key)
    verifier = pk.verifier(
            base64.b64decode(signature),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
    verifier.update(message)
    try:
        verifier.verify()
        return True
    except cryptography.exceptions.InvalidSignature:
        return False

# END OF CRYPTOGRAPHY MODULE
