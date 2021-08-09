# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from collections import namedtuple
from typing import Dict, Tuple

import pytest

from iotics.lib.identity.crypto.identity import make_identifier
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import DIDType
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.document_helper import RegisterDocumentHelper
from iotics.lib.identity.register.keys import RegisterAuthenticationPublicKey, RegisterDelegationProof, \
    RegisterPublicKey
from tests.unit.iotics.lib.identity.helper import get_doc_with_keys


@pytest.fixture
def public_keys():
    return {'#Key1': RegisterPublicKey.build('#Key1', 'base58Key1', revoked=False),
            '#Key2': RegisterPublicKey.build('#Key2', 'base58Key2', revoked=False),
            '#Key3': RegisterPublicKey.build('#Key3', 'base58Key3', revoked=False)}


@pytest.fixture
def auth_keys():
    return {'#AuthKey1': RegisterAuthenticationPublicKey.build('#AuthKey1', 'base58Key1', revoked=False),
            '#AuthKey2': RegisterAuthenticationPublicKey.build('#AuthKey2', 'base58Key2', revoked=False),
            '#AuthKey3': RegisterAuthenticationPublicKey.build('#AuthKey3', 'base58Key3', revoked=False)}


def test_can_get_issuer_from_public_keys(public_keys):
    doc = get_doc_with_keys(public_keys=public_keys.values())
    issuer_name = '#Key2'
    issuer_key = RegisterDocumentHelper.get_issuer_register_key(issuer_name, doc, include_auth=False)
    assert issuer_key == public_keys[issuer_name]


def test_get_issuer_from_public_keys_returns_none_if_not_found(public_keys):
    doc = get_doc_with_keys(public_keys=public_keys.values())
    issuer_name = '#DoesNotExist'
    issuer_key = RegisterDocumentHelper.get_issuer_register_key(issuer_name, doc, include_auth=False)
    assert not issuer_key


def test_can_get_issuer_from_auth_keys(auth_keys, min_doc_owner_pub_key):
    doc = get_doc_with_keys(auth_keys=auth_keys.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#AuthKey2'
    issuer_key = RegisterDocumentHelper.get_issuer_register_key(issuer_name, doc, include_auth=True)
    assert issuer_key == auth_keys[issuer_name]


def test_get_issuer_from_auth_keys_returns_none_if_not_found(auth_keys, min_doc_owner_pub_key):
    doc = get_doc_with_keys(auth_keys=auth_keys.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#DoesNotExist'
    issuer_key = RegisterDocumentHelper.get_issuer_register_key(issuer_name, doc, include_auth=True)
    assert not issuer_key


def test_get_issuer_from_auth_keys_returns_none_if_in_auth_keys_but_auth_not_included(auth_keys, min_doc_owner_pub_key):
    doc = get_doc_with_keys(auth_keys=auth_keys.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#AuthKey2'
    assert issuer_name in doc.auth_keys
    issuer_key = RegisterDocumentHelper.get_issuer_register_key(issuer_name, doc, include_auth=False)
    assert not issuer_key


@pytest.mark.parametrize('issuer_name,include_auth,expected_res', (('#Key2', False, True),
                                                                   ('#DoesNotExists', False, False),
                                                                   ('#AuthKey2', False, False),
                                                                   ('#AuthKey2', True, True),
                                                                   ('#DoesNotExists', True, False)))
def test_is_issuer_in_keys_returns_true_if_issuer_in_auth_keys(public_keys, auth_keys, issuer_name, include_auth,
                                                               expected_res):
    doc = get_doc_with_keys(public_keys.values(), auth_keys.values())
    assert RegisterDocumentHelper.is_issuer_in_keys(issuer_name, doc, include_auth) == expected_res


@pytest.fixture
def control_deleg_proof():
    issuer1 = Issuer.from_string('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7#ctrl1')
    issuer2 = Issuer.from_string('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7#ctrl2')
    issuer3 = Issuer.from_string('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7#ctrl3')
    return {'#DelegCtrlKey1': RegisterDelegationProof.build('#DelegCtrlKey1',
                                                            issuer1,
                                                            proof='proof', revoked=False),
            '#DelegCtrlKey2': RegisterDelegationProof.build('#DelegCtrlKey2',
                                                            issuer2,
                                                            proof='proof', revoked=False),
            '#DelegCtrlKey3': RegisterDelegationProof.build('#DelegCtrlKey3',
                                                            issuer3,
                                                            proof='proof', revoked=False), }


@pytest.fixture
def auth_deleg_proof():
    issuer1 = Issuer.from_string('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7#ctrl1')
    issuer2 = Issuer.from_string('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7#ctrl2')
    issuer3 = Issuer.from_string('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7#ctrl3')
    return {'#DelegAuthKey1': RegisterDelegationProof.build('#DelegAuthKey1',
                                                            issuer1,
                                                            proof='proof', revoked=False),
            '#DelegAuthKey2': RegisterDelegationProof.build('#DelegAuthKey2',
                                                            issuer2,
                                                            proof='proof', revoked=False),
            '#DelegAuthKey3': RegisterDelegationProof.build('#DelegAuthKey3',
                                                            issuer3,
                                                            proof='proof', revoked=False), }


def test_can_get_issuer_from_control_delegation(control_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_control=control_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#DelegCtrlKey2'
    issuer_key = RegisterDocumentHelper.get_issuer_register_delegation_proof(issuer_name, doc, include_auth=False)
    assert issuer_key == control_deleg_proof[issuer_name]


def test_get_issuer_from_control_delegation_returns_none_if_not_found(control_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_control=control_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#DoesNotExist'
    issuer_key = RegisterDocumentHelper.get_issuer_register_delegation_proof(issuer_name, doc, include_auth=False)
    assert not issuer_key


def test_can_get_issuer_from_auth_delegation(auth_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_auth=auth_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#DelegAuthKey2'
    issuer_key = RegisterDocumentHelper.get_issuer_register_delegation_proof(issuer_name, doc, include_auth=True)
    assert issuer_key == auth_deleg_proof[issuer_name]


def test_get_issuer_from_auth_delegation_returns_none_if_not_found(auth_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_auth=auth_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#DoesNotExist'
    issuer_key = RegisterDocumentHelper.get_issuer_register_delegation_proof(issuer_name, doc, include_auth=True)
    assert not issuer_key


def test_get_issuer_from_auth_delegation_returns_none_if_in_auth_keys_but_auth_not_included(auth_deleg_proof,
                                                                                            min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_auth=auth_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    issuer_name = '#DelegAuthKey2'
    assert issuer_name in doc.auth_delegation_proof
    issuer_key = RegisterDocumentHelper.get_issuer_register_delegation_proof(issuer_name, doc, include_auth=False)
    assert not issuer_key


def test_can_get_control_delegation_by_controller(control_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_control=control_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    delegation_name = '#DelegCtrlKey2'
    expected_deleg_proof = control_deleg_proof[delegation_name]
    deleg_proof = RegisterDocumentHelper.get_register_delegation_proof_by_controller(expected_deleg_proof.controller,
                                                                                     doc, include_auth=False)
    assert deleg_proof == expected_deleg_proof


def test_get_control_delegation_by_controller_returns_none_if_not_found(control_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_control=control_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    issuer = Issuer.build('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7', '#DoesNotExist')
    deleg_proof = RegisterDocumentHelper.get_register_delegation_proof_by_controller(issuer, doc, include_auth=False)
    assert not deleg_proof


def test_can_get_auth_delegation_by_controller(auth_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_auth=auth_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    delegation_name = '#DelegAuthKey2'
    expected_deleg_proof = auth_deleg_proof[delegation_name]
    deleg_proof = RegisterDocumentHelper.get_register_delegation_proof_by_controller(expected_deleg_proof.controller,
                                                                                     doc, include_auth=True)
    assert deleg_proof == expected_deleg_proof


def test_get_auth_delegation_by_controller_returns_none_if_not_found(auth_deleg_proof, min_doc_owner_pub_key):
    doc = get_doc_with_keys(deleg_auth=auth_deleg_proof.values(), public_keys=[min_doc_owner_pub_key])
    issuer = Issuer.build('did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7', '#DoesNotExist')
    deleg_proof = RegisterDocumentHelper.get_register_delegation_proof_by_controller(issuer, doc, include_auth=True)
    assert not deleg_proof


def get_docs_for_issuer_key_from_public_keys(doc_did: str, issuer: Issuer) -> Dict[str, RegisterDocument]:
    """
    The issuer is directly in the current doc public keys
    """
    doc = get_doc_with_keys(public_keys=[RegisterPublicKey.build(issuer.name, 'base58Key1', revoked=False)])
    return {doc_did: doc}


def get_docs_for_issuer_key_from_control_delegation(doc_did: str, deleg_doc_did: str,
                                                    issuer: Issuer) -> Dict[str, RegisterDocument]:
    """
    The issuer is in the control delegation of the provided doc
    And the issuer is in the public key of the delegation doc
    """

    doc = get_doc_with_keys(deleg_control=[RegisterDelegationProof.build(issuer.name,
                                                                         controller=Issuer('deleg_doc_did', '#plop'),
                                                                         proof='proof',
                                                                         revoked=False), ])
    deleg_doc = get_doc_with_keys(public_keys=[RegisterPublicKey.build(issuer.name, 'base58Key1', revoked=False)])
    return {doc_did: doc,
            deleg_doc_did: deleg_doc}


def get_docs_for_issuer_key_from_auth_keys(doc_did: str, issuer: Issuer) -> Dict[str, RegisterDocument]:
    """
    The issuer is directly in the current doc auth keys
    """
    doc = get_doc_with_keys(auth_keys=[RegisterAuthenticationPublicKey.build(issuer.name, 'base58Key1', revoked=False)])
    return {doc_did: doc}


def get_docs_for_issuer_key_from_auth_delegation(doc_did: str, deleg_doc_did: str,
                                                 issuer: Issuer) -> Dict[str, RegisterDocument]:
    """
    The issuer is in the auth delegation of the provided doc
    And the issuer is in the auth keys of the delegation doc
    """

    doc = get_doc_with_keys(deleg_control=[RegisterDelegationProof.build(issuer.name,
                                                                         controller=Issuer('deleg_doc_did', '#plop'),
                                                                         proof='proof',
                                                                         revoked=False), ])
    deleg_doc = get_doc_with_keys(public_keys=[RegisterPublicKey.build(issuer.name, 'base58Key1', revoked=False)])
    return {doc_did: doc,
            deleg_doc_did: deleg_doc}


KeysIssuerTest = namedtuple('KeysIssuerTest',
                            (
                                'key_only_in_doc_pub_keys',
                                'key_only_in_doc_auth_keys',
                                'key_in_doc_control_deleg_and_deleg_doc_pub_keys',
                                'key_in_doc_control_deleg_and_deleg_doc_auth_keys',
                                'key_in_doc_control_deleg_and_not_in_deleg_doc',
                                'key_in_doc_auth_deleg_and_deleg_doc_pub_keys',
                                'key_in_doc_auth_deleg_and_deleg_doc_auth_keys',
                                'key_in_doc_auth_deleg_and_not_in_deleg_doc',
                                'key_does_not_exist'
                            ))
KEYS_NAMES = KeysIssuerTest(key_only_in_doc_pub_keys='#OnlyDocPubKeys',
                            key_only_in_doc_auth_keys='#OnlyDocAuthKeys',
                            key_in_doc_control_deleg_and_deleg_doc_pub_keys='#CtrlDlgAndDlgDocPubKs',
                            key_in_doc_control_deleg_and_deleg_doc_auth_keys='#CtrlDlgAndDlgDocAuthKs',
                            key_in_doc_control_deleg_and_not_in_deleg_doc='#CtrlDlgAndNotInDlgDoc',
                            key_in_doc_auth_deleg_and_deleg_doc_pub_keys='#AuthDlgAndDlgDocPubKs',
                            key_in_doc_auth_deleg_and_deleg_doc_auth_keys='#AuthDlgAndDlgDocAuthKs',
                            key_in_doc_auth_deleg_and_not_in_deleg_doc='#AuthDlgAndNotInDlgDoc',
                            key_does_not_exist='#DoesNotExist')


@pytest.fixture
def register_doc_and_deleg_doc(doc_did: str, deleg_doc_did: str) -> Tuple[RegisterDocument, RegisterDocument]:
    """
    Creates a document and a delegation document with all the key combinations (See KEY_NAMES)
    for the "get issuer from" tests with and without delegation and with and without included authentication
    """
    doc = get_doc_with_keys(
        did=doc_did,
        public_keys=[RegisterPublicKey.build(KEYS_NAMES.key_only_in_doc_pub_keys, 'base58Key1', revoked=False)],
        auth_keys=[
            RegisterAuthenticationPublicKey.build(KEYS_NAMES.key_only_in_doc_auth_keys, 'base58Key2', revoked=False)],
        deleg_control=[
            RegisterDelegationProof.build(KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_pub_keys,
                                          controller=Issuer('deleg_doc_did', '#plop1'), proof='aproof', revoked=False),
            RegisterDelegationProof.build(KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_auth_keys,
                                          controller=Issuer('deleg_doc_did', '#plop2'), proof='aproof', revoked=False),
            RegisterDelegationProof.build(KEYS_NAMES.key_in_doc_control_deleg_and_not_in_deleg_doc,
                                          controller=Issuer('deleg_doc_did', '#plop3'), proof='aproof', revoked=False),
        ],
        deleg_auth=[
            RegisterDelegationProof.build(KEYS_NAMES.key_in_doc_auth_deleg_and_deleg_doc_pub_keys,
                                          controller=Issuer('deleg_doc_did', '#plop4'), proof='aproof', revoked=False),
            RegisterDelegationProof.build(KEYS_NAMES.key_in_doc_auth_deleg_and_deleg_doc_auth_keys,
                                          controller=Issuer('deleg_doc_did', '#plop5'), proof='aproof', revoked=False),
            RegisterDelegationProof.build(KEYS_NAMES.key_in_doc_auth_deleg_and_not_in_deleg_doc,
                                          controller=Issuer('deleg_doc_did', '#plop6'), proof='aproof', revoked=False),
        ],
    )

    deleg_doc = get_doc_with_keys(
        did=deleg_doc_did,
        public_keys=[
            RegisterPublicKey.build(KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_pub_keys, 'base58K11',
                                    revoked=False),
            RegisterPublicKey.build(KEYS_NAMES.key_in_doc_auth_deleg_and_deleg_doc_pub_keys, 'base58K12',
                                    revoked=False)],
        auth_keys=[
            RegisterAuthenticationPublicKey.build(KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_auth_keys,
                                                  'base58K13',
                                                  revoked=False),
            RegisterAuthenticationPublicKey.build(KEYS_NAMES.key_in_doc_auth_deleg_and_deleg_doc_auth_keys, 'base58K14',
                                                  revoked=False)
        ]

    )
    return doc, deleg_doc


@pytest.mark.parametrize('issuer_name', (KEYS_NAMES.key_only_in_doc_pub_keys,
                                         KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_pub_keys))
def test_can_get_valid_issuer_for_control_only(issuer_name, register_doc_and_deleg_doc):
    doc, deleg_doc = register_doc_and_deleg_doc

    def get_ctrl_doc(did: str):
        assert did.startswith(did)
        return deleg_doc

    assert issuer_name in doc.public_keys or issuer_name in deleg_doc.public_keys
    issuer_key = RegisterDocumentHelper.get_valid_issuer_key_for_control_only(doc, issuer_name, get_ctrl_doc)
    assert issuer_key.issuer == Issuer.build(doc.did, issuer_name)
    expected_base58 = doc.public_keys.get(issuer_name, deleg_doc.public_keys.get(issuer_name))
    assert expected_base58, f'test setup error, {issuer_name} should be in one of the docs public keys'
    assert issuer_key.public_key_base58 == expected_base58.base58


@pytest.mark.parametrize('issuer_name', (KEYS_NAMES.key_only_in_doc_auth_keys,
                                         KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_auth_keys,
                                         KEYS_NAMES.key_in_doc_auth_deleg_and_deleg_doc_pub_keys,
                                         KEYS_NAMES.key_in_doc_auth_deleg_and_deleg_doc_auth_keys,
                                         # From control
                                         KEYS_NAMES.key_only_in_doc_pub_keys,
                                         KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_pub_keys,
                                         ))
def test_can_get_valid_issuer_for_auth(issuer_name, register_doc_and_deleg_doc):
    doc, deleg_doc = register_doc_and_deleg_doc

    def get_ctrl_doc(did: str):
        assert did.startswith(did)
        return deleg_doc

    all_keys = list(doc.public_keys) + list(doc.auth_keys) + list(deleg_doc.public_keys) + list(deleg_doc.auth_keys)
    assert issuer_name in all_keys
    issuer_key = RegisterDocumentHelper.get_valid_issuer_key_for_auth(doc, issuer_name, get_ctrl_doc)
    assert issuer_key.issuer == Issuer.build(doc.did, issuer_name)
    exp_base58 = doc.public_keys.get(issuer_name, doc.auth_keys.get(issuer_name))
    exp_base58 = exp_base58 or deleg_doc.public_keys.get(issuer_name,
                                                         deleg_doc.auth_keys.get(issuer_name))
    assert exp_base58, f'test setup error, {issuer_name} should be in one of the docs public or auth keys'
    assert issuer_key.public_key_base58 == exp_base58.base58


@pytest.mark.parametrize('issuer_name', (k for k in KEYS_NAMES if k not
                                         in (KEYS_NAMES.key_only_in_doc_pub_keys,
                                             KEYS_NAMES.key_in_doc_control_deleg_and_deleg_doc_pub_keys)
                                         ))
def test_get_valid_issuer_for_control_only_returns_none_if_not_found(issuer_name, register_doc_and_deleg_doc):
    def get_ctrl_doc(did: str):
        assert did.startswith(did)
        return deleg_doc

    doc, deleg_doc = register_doc_and_deleg_doc
    issuer_key = RegisterDocumentHelper.get_valid_issuer_key_for_control_only(doc, issuer_name, get_ctrl_doc)
    assert not issuer_key


@pytest.mark.parametrize('issuer_name', (KEYS_NAMES.key_in_doc_control_deleg_and_not_in_deleg_doc,
                                         KEYS_NAMES.key_in_doc_auth_deleg_and_not_in_deleg_doc,
                                         KEYS_NAMES.key_does_not_exist,
                                         ))
def test_get_valid_issuer_for_auth_returns_none_if_not_found(issuer_name, register_doc_and_deleg_doc):
    def get_ctrl_doc(did: str):
        assert did.startswith(did)
        return deleg_doc

    doc, deleg_doc = register_doc_and_deleg_doc
    issuer_key = RegisterDocumentHelper.get_valid_issuer_key_for_auth(doc, issuer_name, get_ctrl_doc)
    assert not issuer_key


def test_can_get_owner_public_key(valid_key_pair, other_key_pair):
    doc_id = make_identifier(valid_key_pair.public_bytes)
    owner_key = RegisterPublicKey('#Owner', valid_key_pair.public_base58, revoked=False)
    doc = RegisterDocumentBuilder() \
        .add_public_key_obj(owner_key) \
        .add_public_key_obj(RegisterPublicKey('#NotOwner', other_key_pair.public_base58, revoked=False)) \
        .build(doc_id,
               DIDType.TWIN,
               proof='a proof, does not matter here',
               revoked=False)
    key = RegisterDocumentHelper.get_owner_register_public_key(doc)
    assert key == owner_key


def test_get_owner_public_key_returns_none_if_not_found(valid_key_pair, other_key_pair):
    doc_id = make_identifier(valid_key_pair.public_bytes)
    doc = RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey('#NotOwner', other_key_pair.public_base58, revoked=False)) \
        .build(doc_id,
               DIDType.TWIN,
               proof='a proof, does not matter here',
               revoked=False)
    key = RegisterDocumentHelper.get_owner_register_public_key(doc)
    assert not key


def test_can_get_issuer_by_public_key(valid_key_pair):
    doc_did = make_identifier(valid_key_pair.public_bytes)
    key_issuer = Issuer.build(doc_did, '#AnIssuer')
    doc = RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey(key_issuer.name, valid_key_pair.public_base58, revoked=False)) \
        .build(key_issuer.did,
               DIDType.TWIN,
               proof='a proof, does not matter here',
               revoked=False)
    issuer = RegisterDocumentHelper.get_issuer_from_public_key(doc, valid_key_pair.public_base58)
    assert issuer == key_issuer


def test_get_issuer_by_public_key_returns_none_if_not_found(valid_key_pair, other_key_pair):
    doc_did = make_identifier(valid_key_pair.public_bytes)
    key_issuer = Issuer.build(doc_did, '#AnIssuer')
    doc = RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey(key_issuer.name, valid_key_pair.public_base58, revoked=False)) \
        .build(key_issuer.did,
               DIDType.TWIN,
               proof='a proof, does not matter here',
               revoked=False)
    issuer = RegisterDocumentHelper.get_issuer_from_public_key(doc, other_key_pair.public_base58)
    assert not issuer
