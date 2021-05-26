# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.crypto.identity import make_identifier
from iotics.lib.identity.crypto.key_pair_secrets import DIDType, KeyPairSecretsHelper
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.error import IdentityInvalidDocumentError, \
    IdentityInvalidProofError, IdentityResolverError
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.keys import RegisterPublicKey
from iotics.lib.identity.validation.document import DocumentValidation
from tests.unit.iotics.lib.identity.fake import ResolverClientTest
from tests.unit.iotics.lib.identity.helper import get_doc_with_keys
from tests.unit.iotics.lib.identity.validation.helper import get_valid_delegated_doc_and_deleg_proof, \
    get_valid_document_from_secret, is_validator_run_success, new_seed


@pytest.fixture
def doc_invalid_proof(valid_key_pair_secrets, valid_issuer):
    return Proof.build(valid_key_pair_secrets, valid_issuer, content='not the doc id'.encode())


@pytest.fixture
def valid_doc(valid_issuer, valid_key_pair_secrets):
    return get_valid_document_from_secret(valid_key_pair_secrets, valid_issuer.name)


@pytest.fixture
def invalid_doc_no_owner_key(valid_doc, valid_issuer, valid_key_pair_secrets, other_key_pair_secrets):
    public_base58 = KeyPairSecretsHelper.get_public_key_base58_from_key_pair_secrets(other_key_pair_secrets)
    doc_id = valid_doc.did
    return RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey('#KeyNotFromOwner', public_base58, revoked=False)) \
        .build(doc_id,
               DIDType.TWIN,
               proof=Proof.build(valid_key_pair_secrets, valid_issuer, content=doc_id.encode()).signature,
               revoked=False)


@pytest.fixture
def invalid_doc_invalid_proof(valid_doc, doc_invalid_proof, valid_key_pair_secrets):
    public_base58 = KeyPairSecretsHelper.get_public_key_base58_from_key_pair_secrets(valid_key_pair_secrets)
    doc_id = valid_doc.did
    return RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey('#Owner', public_base58, revoked=False)) \
        .build(doc_id,
               DIDType.TWIN,
               proof=doc_invalid_proof.signature,
               revoked=False)


@pytest.fixture
def invalid_doc(doc_did, valid_issuer_key):
    return get_doc_with_keys(
        did=doc_did,
        public_keys=[RegisterPublicKey.build('#Key1', valid_issuer_key.public_key_base58, revoked=False), ]
    )


def test_can_validate_document_proof(valid_doc):
    assert is_validator_run_success(DocumentValidation.validate_new_document_proof, valid_doc)


def test_validate_document_proof_fails_if_no_owner_key(invalid_doc_no_owner_key):
    with pytest.raises(IdentityInvalidDocumentError):
        is_validator_run_success(DocumentValidation.validate_new_document_proof, invalid_doc_no_owner_key)


def test_validate_document_proof_fails_if_invalid_proof(invalid_doc_invalid_proof):
    with pytest.raises(IdentityInvalidDocumentError) as err_wrapper:
        is_validator_run_success(DocumentValidation.validate_new_document_proof, invalid_doc_invalid_proof)
    assert isinstance(err_wrapper.value.__cause__, IdentityInvalidProofError)


def test_can_validate_document_without_delegation_against_resolver(valid_doc):
    resolver_client = ResolverClientTest(docs={})
    assert is_validator_run_success(DocumentValidation.validate_document_against_resolver,
                                    resolver_client, valid_doc)


def test_can_validate_document_with_delegation_against_resolver(valid_doc):
    delegated_doc1, deleg_key1 = get_valid_delegated_doc_and_deleg_proof(new_seed(), '#issuer1',
                                                                         delegating_doc_id=valid_doc.did,
                                                                         deleg_name='#DelegDoc1')
    delegated_doc2, deleg_key2 = get_valid_delegated_doc_and_deleg_proof(new_seed(), '#issuer2',
                                                                         delegating_doc_id=valid_doc.did,
                                                                         deleg_name='#DelegDoc2')

    valid_doc = RegisterDocumentBuilder() \
        .add_control_delegation_obj(deleg_key1) \
        .add_control_delegation_obj(deleg_key2) \
        .add_authentication_delegation(deleg_key1.name + 'auth', deleg_key1.controller, deleg_key1.proof,
                                       deleg_key1.revoked) \
        .add_authentication_delegation(deleg_key2.name + 'auth', deleg_key2.controller, deleg_key2.proof,
                                       deleg_key2.revoked) \
        .build_from_existing(valid_doc)
    resolver_client = ResolverClientTest(docs={valid_doc.did: valid_doc,
                                               delegated_doc1.did: delegated_doc1,
                                               delegated_doc2.did: delegated_doc2})
    assert is_validator_run_success(DocumentValidation.validate_document_against_resolver,
                                    resolver_client, valid_doc)


def test_can_validate_new_document_proof(valid_doc):
    assert is_validator_run_success(DocumentValidation.validate_new_document_proof, valid_doc)


def test_validate_document_proof_raises_validation_error_if_invalid_doc_proof(invalid_doc_invalid_proof):
    with pytest.raises(IdentityInvalidDocumentError) as err_wrapper:
        is_validator_run_success(DocumentValidation.validate_new_document_proof, invalid_doc_invalid_proof)
    assert isinstance(err_wrapper.value.__cause__, IdentityInvalidProofError)


@pytest.mark.parametrize('deleg_type', ('auth', 'control'))
def test_validate_document_against_resolver_raises_validation_error_if_invalid_delegation(valid_doc, other_key_pair,
                                                                                          deleg_type):
    wrong_deleg_id = make_identifier(other_key_pair.public_bytes)
    delegated_doc1, inconsistent_deleg_key = get_valid_delegated_doc_and_deleg_proof(new_seed(), '#issuer1',
                                                                                     delegating_doc_id=wrong_deleg_id,
                                                                                     deleg_name='#DelegDoc1')

    builder = RegisterDocumentBuilder()
    if deleg_type == 'auth':
        builder.add_authentication_delegation_obj(inconsistent_deleg_key)
    else:
        builder.add_control_delegation_obj(inconsistent_deleg_key)
    doc_with_invalid_delegation = builder.build_from_existing(valid_doc)
    resolver_client = ResolverClientTest(docs={valid_doc.did: valid_doc,
                                               delegated_doc1.did: delegated_doc1})
    with pytest.raises(IdentityInvalidDocumentError) as err_wrapper:
        is_validator_run_success(DocumentValidation.validate_document_against_resolver, resolver_client,
                                 doc_with_invalid_delegation)
    assert isinstance(err_wrapper.value.__cause__, IdentityInvalidProofError)


def test_validate_document_against_resolver_raises_validation_error_if_resolver_error(valid_doc):
    _, deleg_key = get_valid_delegated_doc_and_deleg_proof(new_seed(), '#issuer1',
                                                           delegating_doc_id=valid_doc.did,
                                                           deleg_name='#DelegDoc1')

    valid_doc = RegisterDocumentBuilder() \
        .add_control_delegation_obj(deleg_key) \
        .build_from_existing(valid_doc)

    # Initialised without the delegation doc so a not found will be raised
    resolver_client = ResolverClientTest(docs={valid_doc.did: valid_doc})
    with pytest.raises(IdentityInvalidDocumentError) as err_wrapper:
        is_validator_run_success(DocumentValidation.validate_document_against_resolver, resolver_client,
                                 valid_doc)
    assert isinstance(err_wrapper.value.__cause__, IdentityResolverError)
