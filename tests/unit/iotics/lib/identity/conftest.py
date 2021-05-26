# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.crypto.issuer import Issuer, IssuerKey
from iotics.lib.identity.crypto.key_pair_secrets import DIDType, KeyPairSecrets, KeyPairSecretsHelper
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder


@pytest.fixture
def valid_bip39_seed():
    return b'd2397e8b83cf4a7073a26c1a1cdb6b65'


@pytest.fixture
def valid_key_pair_secrets(valid_bip39_seed):
    return KeyPairSecrets.build(valid_bip39_seed, 'iotics/0/something/user')


@pytest.fixture
def valid_private_key(valid_key_pair_secrets):
    return KeyPairSecretsHelper.get_private_key(valid_key_pair_secrets)


@pytest.fixture
def valid_key_pair(valid_key_pair_secrets):
    return KeyPairSecretsHelper.get_key_pair(valid_key_pair_secrets)


@pytest.fixture
def valid_issuer_key(valid_issuer, valid_key_pair):
    return IssuerKey.build(valid_issuer.did, valid_issuer.name, valid_key_pair.public_base58)


@pytest.fixture
def valid_issuer():
    return Issuer.build('did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEgY', '#aName')


@pytest.fixture
def other_issuer():
    return Issuer.build('did:iotics:iotHHHmKpPGWyEC4FFo4d6oyzVVk6MXLmEgY', '#aName')


@pytest.fixture
def register_doc(valid_key_pair_secrets, valid_issuer):
    proof = Proof.build(valid_key_pair_secrets, valid_issuer, content=valid_issuer.did.encode())
    key_pair = KeyPairSecretsHelper.get_key_pair(valid_key_pair_secrets)
    return RegisterDocumentBuilder() \
        .add_public_key(valid_issuer.name, key_pair.public_base58, revoked=False) \
        .build(valid_issuer.did, DIDType.USER, proof.signature, revoked=False)


@pytest.fixture
def other_key_pair_secrets():
    return KeyPairSecrets.build(b'd2397e8b83cf4a7073a26c1a1cdb6666', 'iotics/0/plop/plop')


@pytest.fixture
def other_private_key(other_key_pair_secrets):
    return KeyPairSecretsHelper.get_private_key(other_key_pair_secrets)


@pytest.fixture
def other_key_pair(other_key_pair_secrets):
    return KeyPairSecretsHelper.get_key_pair(other_key_pair_secrets)


@pytest.fixture
def doc_did():
    return 'did:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEgY'


@pytest.fixture
def deleg_doc_did():
    return 'did:iotics:iotHHHHKpPGWWWC4FFo4d6oyzVVk6MXLmEgY'
