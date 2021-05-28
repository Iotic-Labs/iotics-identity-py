# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.const import DOCUMENT_AUTHENTICATION_TYPE, DOCUMENT_PUBLIC_KEY_TYPE
from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.register.keys import RegisterAuthenticationPublicKey, RegisterDelegationProof, \
    RegisterPublicKey
from tests.unit.iotics.lib.identity.register.conftest import get_public_base_58_key


def test_can_build_register_public_key(valid_key_name, valid_public_key_base58):
    key = RegisterPublicKey.build(valid_key_name, valid_public_key_base58, revoked=False)
    assert key.name == valid_key_name
    assert key.base58 == valid_public_key_base58
    assert not key.revoked

    assert key.to_dict() == {'id': valid_key_name,
                             'type': DOCUMENT_PUBLIC_KEY_TYPE,
                             'publicKeyBase58': valid_public_key_base58,
                             'revoked': False}


def test_build_register_public_key_raises_validation_error_if_invalid_name(valid_public_key_base58):
    with pytest.raises(IdentityValidationError):
        RegisterPublicKey.build('Invalid_name', valid_public_key_base58, revoked=False)


def test_build_register_public_key_from_dict_raises_validation_error_if_invalid_dict():
    with pytest.raises(IdentityValidationError):
        RegisterPublicKey.from_dict({'invalid': 'data'})


def test_can_build_register_auth_key(valid_key_name, valid_public_key_base58):
    key = RegisterAuthenticationPublicKey.build(valid_key_name, valid_public_key_base58, revoked=False)
    assert key.name == valid_key_name
    assert key.base58 == valid_public_key_base58
    assert not key.revoked

    assert key.to_dict() == {'id': valid_key_name,
                             'type': DOCUMENT_AUTHENTICATION_TYPE,
                             'publicKeyBase58': valid_public_key_base58,
                             'revoked': False}


def test_build_register_auth_key_raises_validaion_error_if_invalid_name(valid_public_key_base58):
    with pytest.raises(IdentityValidationError):
        RegisterAuthenticationPublicKey.build('Invalid_name', valid_public_key_base58, revoked=False)


def test_build_register_auth_key_from_dict_raises_validation_error_if_invalid_dict():
    with pytest.raises(IdentityValidationError):
        RegisterAuthenticationPublicKey.from_dict({'invalid': 'data'})


def test_can_build_register_delegation_proof(valid_key_name, a_proof, a_controller):
    key = RegisterDelegationProof(name=valid_key_name, controller=a_controller,
                                  proof=a_proof, revoked=False)
    assert key.name == valid_key_name
    assert key.controller == a_controller
    assert key.proof == a_proof
    assert not key.revoked

    assert key.to_dict() == {'id': valid_key_name,
                             'controller': str(a_controller),
                             'proof': a_proof,
                             'revoked': False}


def test_build_register_delegation_proof_raises_validation_error_if_invalid_name(a_proof, a_controller):
    with pytest.raises(IdentityValidationError):
        RegisterDelegationProof.build(name='InvalidName', controller=a_controller, proof=a_proof, revoked=False)


def test_build_register_delegation_proof_from_dict_raises_validation_error_if_invalid_dict():
    with pytest.raises(IdentityValidationError):
        RegisterDelegationProof.from_dict({'invalid': 'data'})


def test_is_equal_register_delegation_proof(valid_key_name, a_proof, a_controller):
    key1 = RegisterDelegationProof(name=valid_key_name, controller=a_controller,
                                   proof=a_proof, revoked=False)
    key2 = RegisterDelegationProof(name=valid_key_name, controller=a_controller,
                                   proof='difference_ignored', revoked=False)
    assert key1.is_equal(key2)


def test_not_is_equal_register_delegation_proof(valid_key_name, a_proof, a_controller, b_controller):
    key1 = RegisterDelegationProof(name=valid_key_name, controller=a_controller,
                                   proof=a_proof, revoked=False)
    key2 = RegisterDelegationProof(name=valid_key_name, controller=b_controller,
                                   proof='difference_ignored', revoked=False)
    assert not key1.is_equal(key2)


def test_is_equal_register_public_key(valid_key_name, valid_public_key_base58):
    key1 = RegisterPublicKey.build(valid_key_name, valid_public_key_base58, revoked=False)
    key2 = RegisterPublicKey.build(valid_key_name, valid_public_key_base58, revoked=False)
    assert key1.is_equal(key2)


def test_not_is_equal_register_public_key(valid_key_name, valid_public_key_base58):
    key1 = RegisterPublicKey.build(valid_key_name, valid_public_key_base58, revoked=False)
    key2 = RegisterPublicKey.build(valid_key_name, get_public_base_58_key(), revoked=False)
    assert not key1.is_equal(key2)
