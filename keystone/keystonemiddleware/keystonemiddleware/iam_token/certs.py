# Copyright (c) 2024 ICOS


from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
import base64

from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def load_cert(x5c):
    cert = x509.load_der_x509_certificate(base64.b64decode(x5c),
                                          backends.default_backend())
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    pubkey = cert.public_key()
    pubkey_bytes = pubkey.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.PKCS1)
    return {'cert': cert_bytes, 'pubkey': pubkey_bytes}


def load_certs(body):
    certs = {}
    for key in body['keys']:
        LOG.info('load_certs for kid="%s"' % (key['kid'],))
        cert = {'key': key, 'x5c': []}
        for x5c in key['x5c']:
            cert['x5c'].append(load_cert(x5c))
        certs[key['kid']] = cert
    return certs



