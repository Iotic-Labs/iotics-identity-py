# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.const import DOCUMENT_VERSION, SUPPORTED_VERSIONS
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import DIDType
from iotics.lib.identity.error import IdentityInvalidDocumentError, IdentityRegisterDocumentKeyConflictError, \
    IdentityValidationError
from iotics.lib.identity.register.document import Metadata
from iotics.lib.identity.register.document_builder import get_unix_time_ms, RegisterDocumentBuilder
from iotics.lib.identity.register.keys import RegisterAuthenticationPublicKey, RegisterDelegationProof, RegisterKey, \
    RegisterPublicKey
from tests.unit.iotics.lib.identity.register.conftest import get_public_base_58_key


def compare_key(key1: RegisterKey, key2: RegisterKey):
    assert key1.name == key2.name
    assert key1.base58 == key2.base58
    assert key1.revoked == key2.revoked


def compare_delegation(key1: RegisterDelegationProof, key2: RegisterDelegationProof):
    assert key1.name == key2.name
    assert key1.controller == key2.controller
    assert key1.proof == key2.proof
    assert key1.revoked == key2.revoked


def test_can_build_a_register_doc_with_min_data(doc_did, doc_proof, min_doc_owner_pub_key):
    now_before_create = get_unix_time_ms()
    new_doc = RegisterDocumentBuilder() \
        .add_public_key_obj(min_doc_owner_pub_key) \
        .build(did=doc_did,
               purpose=DIDType.USER,
               proof=doc_proof,
               revoked=False)
    assert new_doc.did == doc_did
    assert new_doc.proof == doc_proof
    assert new_doc.purpose == DIDType.USER
    assert not new_doc.revoked
    # Default values
    assert new_doc.spec_version == DOCUMENT_VERSION
    assert new_doc.metadata == Metadata()
    assert not new_doc.creator
    assert now_before_create <= new_doc.update_time <= get_unix_time_ms()
    assert not new_doc.controller
    assert new_doc.public_keys == {min_doc_owner_pub_key.name: min_doc_owner_pub_key}
    assert not new_doc.auth_keys
    assert not new_doc.auth_delegation_proof
    assert not new_doc.control_delegation_proof


def test_can_build_a_register_doc_with_controller_and_not_owner_public_key(doc_did, doc_proof):
    controller = 'did:iotics:iotHHHHKpPGWWWC4FFo4d6oyzVVk6MXLmEgY#AController'
    new_doc = RegisterDocumentBuilder() \
        .build(did=doc_did,
               purpose=DIDType.USER,
               proof=doc_proof,
               revoked=False,
               controller=controller)
    assert not new_doc.public_keys
    assert new_doc.controller == controller


def test_can_build_a_register_doc_with_full_data(doc_keys, doc_did, another_doc_did, doc_proof, doc_controller):
    now_before_create = get_unix_time_ms()
    metadata = Metadata.build('a label', 'a comment', 'http://a/url')
    spec_version = SUPPORTED_VERSIONS[0]
    creator = another_doc_did
    new_doc = RegisterDocumentBuilder() \
        .add_public_key(doc_keys['#pub_key1'].name, doc_keys['#pub_key1'].base58, doc_keys['#pub_key1'].revoked) \
        .add_public_key_obj(doc_keys['#pub_key2']) \
        .add_authentication_key(doc_keys['#auth_key1'].name, doc_keys['#auth_key1'].base58,
                                doc_keys['#auth_key1'].revoked) \
        .add_authentication_key_obj(doc_keys['#auth_key2']) \
        .add_control_delegation(doc_keys['#deleg_control_key1'].name, doc_keys['#deleg_control_key1'].controller,
                                doc_keys['#deleg_control_key1'].proof,
                                doc_keys['#deleg_control_key1'].revoked) \
        .add_control_delegation_obj(doc_keys['#deleg_control_key2']) \
        .add_authentication_delegation(doc_keys['#deleg_auth_key1'].name, doc_keys['#deleg_auth_key1'].controller,
                                       doc_keys['#deleg_auth_key1'].proof,
                                       doc_keys['#deleg_auth_key1'].revoked) \
        .add_authentication_delegation_obj(doc_keys['#deleg_auth_key2']) \
        .build(did=doc_did,
               purpose=DIDType.TWIN,
               proof=doc_proof,
               revoked=True,
               metadata=metadata,
               creator=creator,
               spec_version=spec_version,
               controller=doc_controller)

    assert new_doc.did == doc_did
    assert new_doc.proof == doc_proof
    assert new_doc.purpose == DIDType.TWIN
    assert new_doc.revoked
    assert new_doc.spec_version == spec_version
    assert new_doc.metadata == metadata
    assert new_doc.creator == creator
    assert now_before_create <= new_doc.update_time <= get_unix_time_ms()
    assert new_doc.controller == doc_controller
    assert len(new_doc.public_keys) == 2
    compare_key(doc_keys['#pub_key1'], new_doc.public_keys['#pub_key1'])
    compare_key(doc_keys['#pub_key2'], new_doc.public_keys['#pub_key2'])
    assert len(new_doc.auth_keys) == 2
    compare_key(doc_keys['#auth_key1'], new_doc.auth_keys['#auth_key1'])
    compare_key(doc_keys['#auth_key2'], new_doc.auth_keys['#auth_key2'])
    assert len(new_doc.control_delegation_proof) == 2
    compare_delegation(doc_keys['#deleg_control_key1'], new_doc.control_delegation_proof['#deleg_control_key1'])
    compare_delegation(doc_keys['#deleg_control_key2'], new_doc.control_delegation_proof['#deleg_control_key2'])
    assert len(new_doc.public_keys) == 2
    compare_delegation(doc_keys['#deleg_auth_key1'], new_doc.auth_delegation_proof['#deleg_auth_key1'])
    compare_delegation(doc_keys['#deleg_auth_key2'], new_doc.auth_delegation_proof['#deleg_auth_key2'])


@pytest.mark.parametrize('is_minimal', (True, False))
def test_can_build_a_register_doc_from_dict(minimal_doc, full_doc, is_minimal):
    doc = minimal_doc if is_minimal else full_doc
    doc_as_dict = doc.to_dict()
    new_doc = RegisterDocumentBuilder().build_from_dict(doc_as_dict)
    assert new_doc.did == doc.did
    assert new_doc.purpose == doc.purpose
    assert new_doc.proof == doc.proof
    assert new_doc.revoked == doc.revoked
    assert new_doc.spec_version == doc.spec_version
    assert new_doc.metadata == doc.metadata
    assert new_doc.creator == doc.creator
    assert new_doc.update_time == doc.update_time
    assert new_doc.controller == doc.controller
    assert new_doc.public_keys == doc.public_keys
    assert new_doc.auth_keys == doc.auth_keys
    assert new_doc.control_delegation_proof == doc.control_delegation_proof
    assert new_doc.auth_delegation_proof == doc.auth_delegation_proof


def test_can_build_a_register_doc_from_minimal_dict(minimal_doc):
    doc_as_dict = minimal_doc.to_dict()
    doc_as_dict.pop('authentication')
    doc_as_dict.pop('delegateControl')
    doc_as_dict.pop('delegateAuthentication')

    new_doc = RegisterDocumentBuilder().build_from_dict(doc_as_dict)
    assert new_doc.did == minimal_doc.did
    assert new_doc.purpose == minimal_doc.purpose
    assert new_doc.proof == minimal_doc.proof
    assert new_doc.revoked == minimal_doc.revoked
    assert new_doc.spec_version == minimal_doc.spec_version
    assert new_doc.metadata == minimal_doc.metadata
    assert new_doc.public_keys == minimal_doc.public_keys
    assert not new_doc.auth_keys
    assert not new_doc.control_delegation_proof
    assert not new_doc.auth_delegation_proof


@pytest.mark.parametrize('is_minimal', (True, False))
def test_can_build_a_register_doc_from_an_other_doc(minimal_doc, full_doc, is_minimal):
    doc = minimal_doc if is_minimal else full_doc
    new_doc = RegisterDocumentBuilder().build_from_existing(doc)
    assert new_doc.did == doc.did
    assert new_doc.purpose == doc.purpose
    assert new_doc.proof == doc.proof
    assert new_doc.revoked == doc.revoked
    assert new_doc.spec_version == doc.spec_version
    assert new_doc.metadata == doc.metadata
    assert new_doc.creator == doc.creator
    assert new_doc.controller == doc.controller
    assert new_doc.public_keys == doc.public_keys
    assert new_doc.auth_keys == doc.auth_keys
    assert new_doc.control_delegation_proof == doc.control_delegation_proof
    assert new_doc.auth_delegation_proof == doc.auth_delegation_proof
    assert new_doc.update_time >= doc.update_time


def test_can_build_a_register_doc_from_an_other_doc_overriding_values(full_doc):
    existing_doc = full_doc
    new_creator = 'did:iotics:iotA5H2cacnZyRCcuKd6wxPkbNxhAw7WCL2G'
    new_controller = Issuer.build('did:iotics:iotB4X2uEA4ZCAHkMjCci8HzD8gU1UoeRH53', '#NewController')
    new_metadata = Metadata(label='a label')
    new_version = SUPPORTED_VERSIONS[0]
    new_pub_key = RegisterPublicKey(name='#new_pub_key1', base58=get_public_base_58_key(), revoked=False)
    new_auth_key = RegisterAuthenticationPublicKey(name='#new_auth_key1', base58=get_public_base_58_key(),
                                                   revoked=False)
    a_controller = Issuer.from_string('did:iotics:iotC3MU9Bhfx6o2CMq8rJb5sbLJTd5HoJmH5#AController')
    new_control_deleg_proof = RegisterDelegationProof(name='#new_deleg_control_key1', controller=a_controller,
                                                      proof='a_deleg_proof_validated_by_the_resolver',
                                                      revoked=False)
    new_auth_deleg_key = RegisterDelegationProof(name='#new_deleg_auth_key1', controller=a_controller,
                                                 proof='a_deleg_proof_validated_by_the_resolver',
                                                 revoked=False)

    new_doc = RegisterDocumentBuilder() \
        .add_public_key_obj(new_pub_key) \
        .add_authentication_key_obj(new_auth_key) \
        .add_control_delegation_obj(new_control_deleg_proof) \
        .add_authentication_delegation_obj(new_auth_deleg_key) \
        .build_from_existing(existing_doc,
                             revoked=True,
                             metadata=new_metadata,
                             creator=new_creator,
                             spec_version=new_version,
                             controller=new_controller)
    # Can not change
    assert new_doc.did == existing_doc.did
    assert new_doc.purpose == existing_doc.purpose
    assert new_doc.proof == existing_doc.proof
    # Overridden values
    assert new_doc.revoked
    assert new_doc.metadata == new_metadata
    assert new_doc.creator == new_creator
    assert new_doc.spec_version == new_version
    assert new_doc.controller == new_controller

    assert new_doc.public_keys == {**existing_doc.public_keys, **{new_pub_key.name: new_pub_key}}
    assert new_doc.auth_keys == {**existing_doc.auth_keys, **{new_auth_key.name: new_auth_key}}
    assert new_doc.control_delegation_proof == {**existing_doc.control_delegation_proof,
                                                **{new_control_deleg_proof.name: new_control_deleg_proof}}
    assert new_doc.auth_delegation_proof == {**existing_doc.auth_delegation_proof,
                                             **{new_auth_deleg_key.name: new_auth_deleg_key}}
    assert new_doc.update_time >= existing_doc.update_time


@pytest.mark.parametrize('remove_key_name,get_key_set', (
    ('#pub_key1', lambda doc: doc.public_keys),
    ('#auth_key1', lambda doc: doc.auth_keys),
    ('#deleg_control_key1', lambda doc: doc.control_delegation_proof),
    ('#deleg_auth_key1', lambda doc: doc.auth_delegation_proof),
))
def test_can_remove_public_key_building_from_existing_doc(doc_did, doc_proof, doc_keys, remove_key_name, get_key_set):
    existing_doc = RegisterDocumentBuilder() \
        .add_public_key_obj(doc_keys['#pub_key1']) \
        .add_public_key_obj(doc_keys['#pub_key2']) \
        .add_authentication_key_obj(doc_keys['#auth_key1']) \
        .add_authentication_key_obj(doc_keys['#auth_key2']) \
        .add_control_delegation_obj(doc_keys['#deleg_control_key1']) \
        .add_control_delegation_obj(doc_keys['#deleg_control_key2']) \
        .add_authentication_delegation_obj(doc_keys['#deleg_auth_key1']) \
        .add_authentication_delegation_obj(doc_keys['#deleg_auth_key2']) \
        .build(did=doc_did,
               purpose=DIDType.TWIN,
               proof=doc_proof,
               revoked=True)
    new_doc = RegisterDocumentBuilder() \
        .set_keys_from_existing(existing_doc) \
        .remove_key(remove_key_name) \
        .build_from_existing(existing_doc, populate_with_doc_keys=False)
    existing_doc_key_set = get_key_set(existing_doc)
    assert len(existing_doc_key_set) == 2
    assert remove_key_name in existing_doc_key_set
    new_doc_key_set = get_key_set(new_doc)
    assert len(new_doc_key_set) == 1
    assert remove_key_name not in new_doc_key_set
    existing_doc_key_set.pop(remove_key_name)
    assert existing_doc_key_set == new_doc_key_set


@pytest.mark.parametrize('get_key_set', (lambda doc: doc.public_keys,
                                         lambda doc: doc.auth_keys,
                                         lambda doc: doc.control_delegation_proof,
                                         lambda doc: doc.auth_delegation_proof))
def test_can_remove_not_existing_key_without_error(doc_did, doc_proof, doc_keys, get_key_set):
    existing_doc = RegisterDocumentBuilder() \
        .add_public_key_obj(doc_keys['#pub_key1']) \
        .add_authentication_key_obj(doc_keys['#auth_key1']) \
        .add_control_delegation_obj(doc_keys['#deleg_control_key1']) \
        .add_authentication_delegation_obj(doc_keys['#deleg_auth_key1']) \
        .build(did=doc_did,
               purpose=DIDType.TWIN,
               proof=doc_proof,
               revoked=True)
    new_doc = RegisterDocumentBuilder() \
        .set_keys_from_existing(existing_doc) \
        .remove_key('#NotExistingKey') \
        .build_from_existing(existing_doc, populate_with_doc_keys=False)
    existing_doc_key_set = get_key_set(existing_doc)
    new_doc_key_set = get_key_set(new_doc)
    assert existing_doc_key_set == new_doc_key_set


def test_building_a_register_doc_does_not_raises_if_same_key_is_added_twice(doc_keys):
    RegisterDocumentBuilder() \
        .add_public_key_obj(doc_keys['#pub_key1']) \
        .add_public_key_obj(doc_keys['#pub_key1'])


def test_building_a_register_doc_raises_if_same_key_is_added_twice(doc_keys):
    duplicate_pub_key1 = RegisterPublicKey(name=doc_keys['#pub_key1'].name,
                                           base58=get_public_base_58_key(),
                                           revoked=doc_keys['#pub_key1'].revoked)
    with pytest.raises(IdentityRegisterDocumentKeyConflictError):
        RegisterDocumentBuilder() \
            .add_public_key_obj(doc_keys['#pub_key1']) \
            .add_public_key_obj(duplicate_pub_key1)


def test_building_a_register_doc_does_not_raises_if_same_delegation_is_added_twice(doc_keys):
    RegisterDocumentBuilder() \
        .add_control_delegation_obj(doc_keys['#deleg_control_key1']) \
        .add_control_delegation_obj(doc_keys['#deleg_control_key1'])


def test_building_a_register_doc_raises_if_same_delegation_is_added_twice(doc_keys):
    duplicate_deleg_control_key1 = RegisterDelegationProof(name=doc_keys['#deleg_control_key1'].name,
                                                           controller=Issuer(
                                                               'did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXFFFFF',
                                                               '#AController'),
                                                           proof=doc_keys['#deleg_control_key1'].proof,
                                                           revoked=doc_keys['#deleg_control_key1'].revoked)
    with pytest.raises(IdentityRegisterDocumentKeyConflictError):
        RegisterDocumentBuilder() \
            .add_control_delegation_obj(doc_keys['#deleg_control_key1']) \
            .add_control_delegation_obj(duplicate_deleg_control_key1)


def test_building_a_register_doc_raises_a_validation_error_if_invalid_key(doc_keys):
    with pytest.raises(IdentityValidationError):
        RegisterDocumentBuilder() \
            .add_public_key('invalid_name', doc_keys['#pub_key1'].base58, revoked=False)


def test_building_a_register_doc_raises_a_validation_error_if_unsupported_version(doc_did, doc_proof,
                                                                                  min_doc_owner_pub_key):
    with pytest.raises(IdentityInvalidDocumentError):
        RegisterDocumentBuilder() \
            .add_public_key_obj(min_doc_owner_pub_key) \
            .build(did=doc_did,
                   purpose=DIDType.USER,
                   proof=doc_proof,
                   revoked=False,
                   spec_version='!!unsupported!!')


def test_building_a_register_doc_raises_a_validation_error_if_no_controller_and_no_pub_key(doc_did, doc_proof):
    with pytest.raises(IdentityInvalidDocumentError):
        RegisterDocumentBuilder() \
            .build(did=doc_did,
                   purpose=DIDType.USER,
                   proof=doc_proof,
                   revoked=False)


@pytest.mark.parametrize('invalid_data_mutation', (lambda d: d.pop('publicKey'),
                                                   lambda d: d.update({'ioticsDIDType': 'not in enum'})))
def test_building_a_register_doc_from_dict_raises_a_validation_error_if_invalid_data(full_doc, invalid_data_mutation):
    doc_as_dict = full_doc.to_dict()
    invalid_data_mutation(doc_as_dict)
    with pytest.raises(IdentityValidationError):
        RegisterDocumentBuilder() \
            .build_from_dict(doc_as_dict)
