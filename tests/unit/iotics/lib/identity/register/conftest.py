# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from uuid import uuid4

import pytest

from iotics.lib.identity.const import SUPPORTED_VERSIONS
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import DIDType, KeyPairSecrets, KeyPairSecretsHelper
from iotics.lib.identity.register.document import Metadata, RegisterDocument
from iotics.lib.identity.register.document_builder import get_unix_time_ms
from iotics.lib.identity.register.keys import RegisterAuthenticationPublicKey, RegisterDelegationProof, \
    RegisterPublicKey


def get_public_base_58_key() -> str:
    secrets = KeyPairSecrets.build(b'a' * 32, f'iotics/0/something/{uuid4()}')
    key_pair = KeyPairSecretsHelper.get_key_pair(secrets)
    return key_pair.public_base58


@pytest.fixture
def valid_key_name():
    return '#AKeyName'


@pytest.fixture
def valid_public_key_base58():
    return get_public_base_58_key()


@pytest.fixture
def a_controller():
    return Issuer('did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXEEEEE', '#AController')


@pytest.fixture
def b_controller():
    return Issuer('did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXXXXXX', '#AController')


@pytest.fixture
def a_proof():
    return 'a_proof_validated_by_the_resolver'


@pytest.fixture
def doc_proof(a_proof):
    return a_proof


@pytest.fixture
def doc_controller(a_controller):
    return a_controller


@pytest.fixture
def doc_keys(a_controller):
    return {
        '#pub_key1': RegisterPublicKey(name='#pub_key1', base58=get_public_base_58_key(), revoked=False),
        '#pub_key2': RegisterPublicKey(name='#pub_key2', base58=get_public_base_58_key(), revoked=True),
        '#auth_key1': RegisterAuthenticationPublicKey(name='#auth_key1', base58=get_public_base_58_key(),
                                                      revoked=False),
        '#auth_key2': RegisterAuthenticationPublicKey(name='#auth_key2', base58=get_public_base_58_key(), revoked=True),
        '#deleg_control_key1': RegisterDelegationProof(name='#deleg_control_key1', controller=a_controller,
                                                       proof='a_deleg_proof_validated_by_the_resolver',
                                                       revoked=False),
        '#deleg_control_key2': RegisterDelegationProof(name='#deleg_control_key2', controller=a_controller,
                                                       proof='a_deleg_proof_validated_by_the_resolver',
                                                       revoked=True),
        '#deleg_auth_key1': RegisterDelegationProof(name='#deleg_auth_key1', controller=a_controller,
                                                    proof='a_deleg_proof_validated_by_the_resolver', revoked=False),
        '#deleg_auth_key2': RegisterDelegationProof(name='#deleg_auth_key2', controller=a_controller,
                                                    proof='a_deleg_proof_validated_by_the_resolver', revoked=True),

    }


@pytest.fixture
def min_doc_owner_pub_key():
    return RegisterPublicKey('#Owner', 'pubbase58 value', revoked=False)


@pytest.fixture
def minimal_doc(doc_did, doc_proof, min_doc_owner_pub_key):
    return RegisterDocument(did=doc_did,
                            purpose=DIDType.TWIN,
                            proof=doc_proof,
                            revoked=True,
                            public_keys={min_doc_owner_pub_key.name: min_doc_owner_pub_key},
                            auth_keys={},
                            control_delegation_proof={},
                            auth_delegation_proof={},
                            update_time=get_unix_time_ms())


@pytest.fixture
def full_doc(doc_keys, doc_did, doc_proof, doc_controller):
    return RegisterDocument(did=doc_did,
                            purpose=DIDType.TWIN,
                            proof=doc_proof,
                            revoked=True,
                            metadata=Metadata.build('a label', 'a comment', 'http://a/url'),
                            creator='did:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MEEEEgY',
                            spec_version=SUPPORTED_VERSIONS[0],
                            update_time=get_unix_time_ms(),
                            controller=doc_controller,
                            public_keys={doc_keys['#pub_key1'].name: doc_keys['#pub_key1'],
                                         doc_keys['#pub_key2'].name: doc_keys['#pub_key2']},
                            auth_keys={doc_keys['#auth_key1'].name: doc_keys['#auth_key1'],
                                       doc_keys['#auth_key2'].name: doc_keys['#auth_key2']},
                            control_delegation_proof={
                                doc_keys['#deleg_control_key1'].name: doc_keys['#deleg_control_key1'],
                                doc_keys['#deleg_control_key2'].name: doc_keys['#deleg_control_key2']},
                            auth_delegation_proof={doc_keys['#deleg_auth_key1'].name: doc_keys['#deleg_auth_key1'],
                                                   doc_keys['#deleg_auth_key2'].name: doc_keys['#deleg_auth_key2']}
                            )
