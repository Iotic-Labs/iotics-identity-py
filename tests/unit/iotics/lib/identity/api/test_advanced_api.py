# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from typing import Dict

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.api.advanced_api import AdvancedIdentityLocalApi, AdvancedIdentityRegisterApi
from iotics.lib.identity.crypto.identity import make_identifier
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import DIDType
from iotics.lib.identity.error import IdentityRegisterIssuerNotFoundError, IdentityResolverError, \
    IdentityDependencyError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.keys import RegisterDelegationProof, RegisterPublicKey
from tests.unit.iotics.lib.identity.fake import ResolverClientTest
from tests.unit.iotics.lib.identity.helper import get_doc_with_keys
from tests.unit.iotics.lib.identity.validation.helper import get_delegation_proof, get_valid_document_from_secret


@pytest.fixture
def base_doc_issuer_name():
    return '#BaseDoc'


@pytest.fixture
def base_doc(valid_key_pair_secrets, base_doc_issuer_name):
    return get_valid_document_from_secret(valid_key_pair_secrets, base_doc_issuer_name)


@pytest.fixture
def base_doc_issuer(base_doc, base_doc_issuer_name):
    return Issuer.build(base_doc.did, base_doc_issuer_name)


@pytest.fixture
def other_doc_did(other_key_pair):
    return make_identifier(other_key_pair.public_bytes)


@pytest.fixture
def other_doc_issuer(other_doc_did):
    return Issuer.build(other_doc_did, '#DelegatedDoc')


def test_get_key_pair_from_hex_private_key():
    private_expo = 'a' * 64
    expected_base58 = 'PbNnn5VGAkos1X5gcduURAAj4J6e3Awe7Wy45TbKS1SNMTHTBsAG4pvJSfx7ui22zXKzdasQ3ym4idkD5b8YTwYh'
    keypair = AdvancedIdentityLocalApi.get_key_pair_from_hex_private_key(private_expo)
    assert keypair.public_base58 == expected_base58


def test_get_key_pair_from_hex_private_key_error():
    with pytest.raises(IdentityDependencyError):
        AdvancedIdentityLocalApi.get_key_pair_from_hex_private_key('')


def test_get_issuer_by_public_key_raises_not_found_error_if_not_found(base_doc, other_key_pair):
    with pytest.raises(IdentityRegisterIssuerNotFoundError):
        AdvancedIdentityLocalApi.get_issuer_by_public_key(base_doc, other_key_pair.public_base58)


def test_can_get_delegation_proof(base_doc_issuer, other_key_pair_secrets):
    subject_doc = get_valid_document_from_secret(other_key_pair_secrets, '#DelegatedDoc')
    subject_issuer, proof = AdvancedIdentityLocalApi. \
        create_delegation_proof(delegating_issuer=base_doc_issuer,
                                subject_doc=subject_doc,
                                subject_secrets=other_key_pair_secrets)
    assert subject_issuer.did == subject_doc.did
    assert subject_issuer.did == subject_doc.did
    assert proof.content == base_doc_issuer.did.encode()


def test_can_get_document_if_exists(base_doc):
    resolver_client = ResolverClientTest(docs={base_doc.did: base_doc})
    api = AdvancedIdentityRegisterApi(resolver_client)
    doc = api.get_document_if_exists(base_doc.did)
    assert doc.to_dict() == base_doc.to_dict()


def test_can_register_a_doc(valid_key_pair_secrets, valid_key_pair):
    resolver_client = ResolverClientTest(docs={})
    api = AdvancedIdentityRegisterApi(resolver_client)
    did = make_identifier(valid_key_pair.public_bytes)
    issuer = Issuer.build(did, '#NewIssuer')
    api.register_new_doc(valid_key_pair_secrets, issuer, DIDType.AGENT)
    registered_doc = resolver_client.docs.get(issuer.did)
    assert registered_doc
    owner_key = registered_doc.public_keys.get(issuer.name)
    assert owner_key.name == issuer.name
    assert owner_key.base58 == valid_key_pair.public_base58
    assert not owner_key.revoked


class ResolverClientTestWithError(ResolverClientTest):
    def __init__(self, register_err: Exception, docs: Dict[str, RegisterDocument] = None):
        super().__init__(docs)
        self.register_err = register_err

    def register_document(self, document: RegisterDocument, private_key: ec.EllipticCurvePrivateKey,
                          issuer: Issuer, audience: str = ''):
        raise self.register_err


def test_register_doc_raises_resolver_error_if_can_not_register(valid_key_pair_secrets, valid_key_pair):
    resolver_client = ResolverClientTestWithError(register_err=IdentityResolverError('an error'))
    api = AdvancedIdentityRegisterApi(resolver_client)
    issuer = Issuer.build(make_identifier(valid_key_pair.public_bytes), '#NewIssuer')
    with pytest.raises(IdentityResolverError):
        api.register_new_doc(valid_key_pair_secrets, issuer, DIDType.AGENT)


@pytest.mark.parametrize('purpose', list(DIDType))
def test_can_create_new_registered_identity(valid_key_pair_secrets, purpose):
    resolver_client = ResolverClientTest(docs={})
    api = AdvancedIdentityRegisterApi(resolver_client)
    registered_id = api.new_registered_identity(purpose, valid_key_pair_secrets, name='#NewId')
    assert registered_id.issuer
    assert registered_id.issuer.name == '#NewId'
    assert registered_id.key_pair_secrets == valid_key_pair_secrets
    registered_doc = resolver_client.docs.get(registered_id.issuer.did)
    assert registered_doc
    assert registered_doc.public_keys.get(registered_id.issuer.name)


@pytest.mark.parametrize('purpose,expected_default_name', [(DIDType.TWIN, '#twin-0'),
                                                           (DIDType.AGENT, '#agent-0'),
                                                           (DIDType.USER, '#user-0'),
                                                           (DIDType.HOST, '#host-0'), ])
def test_can_create_new_registered_identity_with_default_issuer_name(valid_key_pair_secrets, purpose,
                                                                     expected_default_name):
    resolver_client = ResolverClientTest(docs={})
    api = AdvancedIdentityRegisterApi(resolver_client)
    registered_id = api.new_registered_identity(purpose, valid_key_pair_secrets)
    assert registered_id.issuer.name == expected_default_name


def test_can_create_new_registered_identity_will_not_override_doc_if_exists(valid_key_pair_secrets, valid_key_pair):
    existing_doc_did = make_identifier(valid_key_pair.public_bytes)
    resolver_client = ResolverClientTest(docs={existing_doc_did: get_valid_document_from_secret(valid_key_pair_secrets,
                                                                                                '#ExistingDoc')})
    api = AdvancedIdentityRegisterApi(resolver_client)
    registered_id = api.new_registered_identity(DIDType.AGENT, valid_key_pair_secrets, name='#NewDoc')
    assert registered_id.issuer.name == '#ExistingDoc'
    registered_doc = resolver_client.get_document(registered_id.issuer.did)
    assert registered_doc
    assert registered_doc.public_keys.get('#ExistingDoc')
    assert '#NewDoc' not in registered_doc.public_keys


def test_can_create_new_registered_identity_will_override_doc_if_exists_and_override_true(valid_key_pair_secrets,
                                                                                          valid_key_pair):
    existing_doc_did = make_identifier(valid_key_pair.public_bytes)
    resolver_client = ResolverClientTest(docs={existing_doc_did: get_valid_document_from_secret(valid_key_pair_secrets,
                                                                                                '#ExistingDoc')})
    api = AdvancedIdentityRegisterApi(resolver_client)
    registered_id = api.new_registered_identity(DIDType.AGENT, valid_key_pair_secrets,
                                                name='#NewDoc', override_doc=True)
    assert registered_id.issuer.name == '#NewDoc'
    registered_doc = resolver_client.get_document(registered_id.issuer.did)
    assert registered_doc
    assert registered_doc.public_keys.get('#NewDoc')
    assert '#ExistingDoc' not in registered_doc.public_keys


def test_can_delegate_authentication(base_doc, valid_key_pair_secrets, other_key_pair_secrets):
    subject_doc = get_valid_document_from_secret(other_key_pair_secrets, '#DelegatedDoc')
    resolver_client = ResolverClientTest(docs={base_doc.did: base_doc,
                                               subject_doc.did: subject_doc})
    api = AdvancedIdentityRegisterApi(resolver_client)
    assert not resolver_client.docs[base_doc.did].auth_delegation_proof
    api.delegate_authentication(delegating_secrets=valid_key_pair_secrets,
                                delegating_did=base_doc.did,
                                subject_secrets=other_key_pair_secrets,
                                subject_did=subject_doc.did,
                                delegation_name='#NewAuthDeleg')
    auth_deleg = resolver_client.docs[base_doc.did].auth_delegation_proof.get('#NewAuthDeleg')
    assert auth_deleg
    assert auth_deleg.name == '#NewAuthDeleg'
    assert not auth_deleg.revoked
    assert auth_deleg.proof
    assert auth_deleg.controller == Issuer.build(subject_doc.did, '#DelegatedDoc')


def test_can_delegate_control(base_doc, valid_key_pair_secrets, other_key_pair_secrets):
    subject_doc = get_valid_document_from_secret(other_key_pair_secrets, '#DelegatedDoc')
    resolver_client = ResolverClientTest(docs={base_doc.did: base_doc,
                                               subject_doc.did: subject_doc})
    api = AdvancedIdentityRegisterApi(resolver_client)
    assert not resolver_client.docs[base_doc.did].control_delegation_proof
    api.delegate_control(delegating_secrets=valid_key_pair_secrets,
                         delegating_did=base_doc.did,
                         subject_secrets=other_key_pair_secrets,
                         subject_did=subject_doc.did,
                         delegation_name='#NewControlDeleg')
    control_deleg = resolver_client.docs[base_doc.did].control_delegation_proof.get('#NewControlDeleg')
    assert control_deleg
    assert control_deleg.name == '#NewControlDeleg'
    assert not control_deleg.revoked
    assert control_deleg.proof
    assert control_deleg.controller == Issuer.build(subject_doc.did, '#DelegatedDoc')


def test_can_add_public_key_to_a_document(base_doc, base_doc_issuer, valid_key_pair, other_key_pair):
    resolver_client = ResolverClientTest(docs={base_doc.did: base_doc})
    api = AdvancedIdentityRegisterApi(resolver_client)
    assert len(resolver_client.docs[base_doc.did].public_keys) == 1
    api.add_public_key_to_document(name='#NewOwner',
                                   new_public_key_base58=other_key_pair.public_base58,
                                   doc_owner_key_pair=valid_key_pair,
                                   doc_owner_issuer=base_doc_issuer)
    assert len(resolver_client.docs[base_doc.did].public_keys) == 2
    new_pub_key = resolver_client.docs[base_doc.did].public_keys.get('#NewOwner')
    assert new_pub_key
    assert new_pub_key.name == '#NewOwner'
    assert new_pub_key.base58 == other_key_pair.public_base58
    assert not new_pub_key.revoked


def test_can_add_auth_key_to_a_document(base_doc, base_doc_issuer, valid_key_pair, other_key_pair):
    resolver_client = ResolverClientTest(docs={base_doc.did: base_doc})
    api = AdvancedIdentityRegisterApi(resolver_client)
    assert len(resolver_client.docs[base_doc.did].auth_keys) == 0
    api.add_authentication_key_to_document(name='#NewKey',
                                           new_public_key_base58=other_key_pair.public_base58,
                                           doc_owner_key_pair=valid_key_pair,
                                           doc_owner_issuer=base_doc_issuer)
    assert len(resolver_client.docs[base_doc.did].public_keys) == 1
    new_pub_key = resolver_client.docs[base_doc.did].auth_keys.get('#NewKey')
    assert new_pub_key
    assert new_pub_key.name == '#NewKey'
    assert new_pub_key.base58 == other_key_pair.public_base58
    assert not new_pub_key.revoked


@pytest.mark.parametrize('get_api_call, doc_deleg_set', (
    (lambda api: api.add_control_delegation_proof_to_document, lambda doc: doc.control_delegation_proof),
    (lambda api: api.add_authentication_delegation_proof_to_document, lambda doc: doc.auth_delegation_proof)
))
def test_can_add_delegation_proof(base_doc, base_doc_issuer, valid_key_pair, other_key_pair_secrets, get_api_call,
                                  doc_deleg_set, other_doc_issuer):
    resolver_client = ResolverClientTest(docs={base_doc_issuer.did: base_doc})
    assert not doc_deleg_set(base_doc)
    api = AdvancedIdentityRegisterApi(resolver_client)
    proof = get_delegation_proof(other_doc_issuer, other_key_pair_secrets, base_doc.did)
    delegation_name = '#CtrlDeleg'
    get_api_call(api)(proof, other_doc_issuer, delegation_name, base_doc_issuer, valid_key_pair)
    updated_doc = resolver_client.docs[base_doc_issuer.did]
    deleg_proof = doc_deleg_set(updated_doc).get(delegation_name)
    assert deleg_proof
    assert deleg_proof.proof == proof.signature
    assert deleg_proof.controller == other_doc_issuer
    assert not deleg_proof.revoked


@pytest.mark.parametrize('get_api_call, doc_deleg_set, deleg_name', (
    (lambda api: api.remove_control_delegation_proof_from_document, lambda doc: doc.control_delegation_proof,
     '#Deleg1'),
    (lambda api: api.remove_authentication_delegation_proof_from_document, lambda doc: doc.auth_delegation_proof,
     '#Deleg2')
))
def test_can_remove_delegation_proof(base_doc_issuer, valid_key_pair, get_api_call, doc_deleg_set, deleg_doc_did,
                                     deleg_name):
    doc = get_doc_with_keys(deleg_control=[RegisterDelegationProof.build('#Deleg1',
                                                                         controller=Issuer(deleg_doc_did, '#plop2'),
                                                                         proof='proof',
                                                                         revoked=False)],
                            deleg_auth=[RegisterDelegationProof.build('#Deleg2',
                                                                      controller=Issuer(deleg_doc_did, '#plop2'),
                                                                      proof='proof',
                                                                      revoked=False)],
                            public_keys=[RegisterPublicKey.build('#MandatoryKey', 'base58Key1', revoked=False)],
                            did=base_doc_issuer.did)
    resolver_client = ResolverClientTest(docs={base_doc_issuer.did: doc})
    assert len(doc_deleg_set(doc)) == 1
    api = AdvancedIdentityRegisterApi(resolver_client)
    get_api_call(api)(deleg_name, base_doc_issuer, valid_key_pair)
    updated_doc = resolver_client.docs[base_doc_issuer.did]
    assert len(doc_deleg_set(updated_doc)) == 0


@pytest.mark.parametrize('get_api_call, doc_deleg_set, deleg_name', (
    (lambda api: api.revoke_control_delegation_proof_from_document, lambda doc: doc.control_delegation_proof,
     '#Deleg1'),
    (lambda api: api.revoke_authentication_delegation_proof_from_document, lambda doc: doc.auth_delegation_proof,
     '#Deleg2')
))
def test_can_revoke_delegation_proof(base_doc_issuer, valid_key_pair, get_api_call, doc_deleg_set, deleg_doc_did,
                                     deleg_name):
    doc = get_doc_with_keys(deleg_control=[RegisterDelegationProof.build('#Deleg1',
                                                                         controller=Issuer(deleg_doc_did, '#plop2'),
                                                                         proof='proof',
                                                                         revoked=False)],
                            deleg_auth=[RegisterDelegationProof.build('#Deleg2',
                                                                      controller=Issuer(deleg_doc_did, '#plop2'),
                                                                      proof='proof',
                                                                      revoked=False)],
                            public_keys=[RegisterPublicKey.build('#MandatoryKey', 'base58Key1', revoked=False)],
                            did=base_doc_issuer.did)
    resolver_client = ResolverClientTest(docs={base_doc_issuer.did: doc})
    assert not doc_deleg_set(doc)[deleg_name].revoked
    api = AdvancedIdentityRegisterApi(resolver_client)
    get_api_call(api)(deleg_name, revoked=True, doc_owner_issuer=base_doc_issuer, doc_owner_key_pair=valid_key_pair)
    updated_doc = resolver_client.docs[base_doc_issuer.did]
    assert doc_deleg_set(updated_doc)[deleg_name].revoked
