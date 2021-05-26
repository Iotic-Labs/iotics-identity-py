# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import hmac
from _sha512 import sha512

import base58
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.crypto.key_pair_secrets import KeyPairSecretsHelper
from iotics.lib.identity.crypto.keys import KeysHelper
from iotics.lib.identity.error import IdentityValidationError


@pytest.fixture
def master(valid_seed_16_bytes):
    return hmac.new(valid_seed_16_bytes, b'passwdPlop', sha512).digest()


@pytest.fixture
def private_ecdsa():
    return ec.derive_private_key(122222222222222222222222222222222, ec.SECP256K1(), default_backend())


@pytest.fixture
def key_pair(valid_key_pair_secrets):
    return KeyPairSecretsHelper.get_key_pair(valid_key_pair_secrets)


def test_get_private_ecdsa(master):
    private_ecdsa = KeysHelper.get_private_ECDSA(master, key_path=b'plopPLOPplop')
    assert private_ecdsa
    assert private_ecdsa.key_size == ec.SECP256K1().key_size
    assert private_ecdsa.curve.name == ec.SECP256K1().name


def test_get_public_keys_from_private_ecdsa(private_ecdsa):
    public_bytes, public_base58 = KeysHelper.get_public_keys_from_private_ECDSA(private_ecdsa)
    assert public_bytes
    assert public_base58
    assert base58.b58encode(public_bytes).decode('ascii') == public_base58

    public_bytes_bis, public_base58_bis = KeysHelper.get_public_keys_from_private_ECDSA(private_ecdsa)
    assert public_bytes == public_bytes_bis
    assert public_base58 == public_base58_bis


def test_get_public_ecdsa_from_base58(valid_public_base58):
    public_bytes = KeysHelper.get_public_ECDSA_from_base58(valid_public_base58)
    assert public_bytes.key_size == ec.SECP256K1().key_size
    assert public_bytes.curve.name == ec.SECP256K1().name


def test_get_public_ecdsa_from_base58_raises_validation_error_if_invalid_key(valid_public_base58):
    invalid_public_base58_key = valid_public_base58 + 'a'
    with pytest.raises(IdentityValidationError) as err_wrapper:
        KeysHelper.get_public_ECDSA_from_base58(invalid_public_base58_key)
    assert isinstance(err_wrapper.value.__cause__, ValueError)
