# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import jwt
import pytest
from jwt import DecodeError

from iotics.lib.identity.const import TOKEN_ALGORITHM
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.crypto.key_pair_secrets import KeyPairSecrets, SeedMethod
from iotics.lib.identity.crypto.proof import build_new_challenge_token, Proof
from iotics.lib.identity.error import IdentityInvalidRegisterIssuerError, IdentityValidationError
from tests.unit.iotics.lib.identity.fake import ResolverClientTest


def test_can_build_proof(valid_key_pair_secrets, valid_issuer):
    content = b'a content'
    proof = Proof.build(valid_key_pair_secrets, valid_issuer, content)
    assert proof.issuer == valid_issuer
    assert proof.content == content
    assert proof.signature


@pytest.fixture
def invalid_key_pair_secrets():
    return KeyPairSecrets(seed=b'invalid secret', path='plop', seed_method=SeedMethod.SEED_METHOD_BIP39, password='')


def test_build_proof_raises_validation_error_if_invalid_inputs(invalid_key_pair_secrets, valid_issuer):
    with pytest.raises(IdentityValidationError) as err_wrapper:
        Proof.build(invalid_key_pair_secrets, valid_issuer, b'a content')
    assert isinstance(err_wrapper.value.__cause__, ValueError)


def test_can_build_challenge_token(valid_private_key, valid_key_pair_secrets, valid_issuer):
    content = b'a content'
    proof = Proof.build(valid_key_pair_secrets, valid_issuer, content)
    challenge_token = build_new_challenge_token(proof, valid_private_key)
    assert challenge_token
    decoded = JwtTokenHelper.decode_token(challenge_token)
    assert decoded['iss'] == str(valid_issuer)
    assert decoded['aud'] == content.decode('ascii')
    assert decoded['proof'] == proof.signature


def test_build_challenge_token_raises_validation_error_if_can_not_create_token(valid_key_pair_secrets, valid_issuer):
    proof = Proof.build(valid_key_pair_secrets, valid_issuer, b'a content')
    with pytest.raises(IdentityValidationError) as err_wrapper:
        build_new_challenge_token(proof, private_key='not a private key')
    assert isinstance(err_wrapper.value.__cause__, ValueError)


def test_can_build_proof_from_challenge_token(valid_private_key, valid_key_pair_secrets, valid_issuer, register_doc):
    proof = Proof.build(valid_key_pair_secrets, valid_issuer, content=b'a content')
    challenge_token = build_new_challenge_token(proof, valid_private_key)
    resolver_client = ResolverClientTest(docs={register_doc.did: register_doc})

    deserialized_proof = Proof.from_challenge_token(resolver_client, challenge_token)
    assert deserialized_proof.issuer == proof.issuer
    assert deserialized_proof.content == proof.content
    assert deserialized_proof.signature == proof.signature


def test_build_proof_from_challenge_token_raises_validation_error_if_invalid_token(register_doc):
    resolver_client = ResolverClientTest(docs={register_doc.did: register_doc})
    with pytest.raises(IdentityValidationError) as err_wrapper:
        Proof.from_challenge_token(resolver_client, 'invalid token')
    assert isinstance(err_wrapper.value.__cause__, DecodeError)


def test_build_proof_from_challenge_token_raises_validation_error_if_invalid_token_data(register_doc,
                                                                                        valid_private_key):
    invalid_challenge_token = jwt.encode({'invalid': 'data'}, valid_private_key, algorithm=TOKEN_ALGORITHM)

    resolver_client = ResolverClientTest(docs={register_doc.did: register_doc})
    with pytest.raises(IdentityValidationError):
        Proof.from_challenge_token(resolver_client, invalid_challenge_token)


def test_build_proof_from_challenge_token_raises_issuer_error_if_issuer_not_in_doc(register_doc, valid_private_key,
                                                                                   valid_key_pair_secrets):
    other_issuer = Issuer.build(register_doc.did, '#OtherIssuer')
    proof = Proof.build(valid_key_pair_secrets, other_issuer, content=b'a content')
    challenge_token = build_new_challenge_token(proof, valid_private_key)

    resolver_client = ResolverClientTest(docs={register_doc.did: register_doc})

    with pytest.raises(IdentityInvalidRegisterIssuerError):
        Proof.from_challenge_token(resolver_client, challenge_token)
