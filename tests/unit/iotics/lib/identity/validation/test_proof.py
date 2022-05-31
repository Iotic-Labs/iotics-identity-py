# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.error import IdentityInvalidDocumentDelegationError, IdentityInvalidProofError, \
    IdentityResolverCommunicationError, IdentityResolverDocNotFoundError, IdentityResolverError, \
    IdentityResolverTimeoutError, IdentityValidationError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.keys import DelegationProofType, RegisterDelegationProof, RegisterPublicKey
from iotics.lib.identity.register.resolver import ResolverClient
from iotics.lib.identity.validation.proof import DelegationValidation, ProofValidation
from tests.unit.iotics.lib.identity.fake import ResolverClientTest
from tests.unit.iotics.lib.identity.helper import get_doc_with_keys
from tests.unit.iotics.lib.identity.validation.helper import get_delegation_register_proof, is_validator_run_success


@pytest.fixture
def valid_proof(valid_key_pair_secrets, valid_issuer):
    return Proof.build(valid_key_pair_secrets, valid_issuer, content=b'a content')


def test_can_validate_proof(valid_proof, valid_key_pair):
    assert is_validator_run_success(ProofValidation.validate_proof, valid_proof, valid_key_pair.public_base58)


def test_validate_proof_with_an_other_key_raises_validation_error(valid_proof, other_key_pair):
    with pytest.raises(IdentityInvalidProofError) as err_wrapper:
        is_validator_run_success(ProofValidation.validate_proof, valid_proof, other_key_pair.public_base58)
    assert isinstance(err_wrapper.value.__cause__, InvalidSignature)


def test_validate_proof_with_corrupted_content_raises_validation_error(valid_proof, other_key_pair):
    corrupted_proof = Proof(issuer=valid_proof.issuer,
                            signature=valid_proof.signature,
                            content=b'an other content')
    with pytest.raises(IdentityInvalidProofError) as err_wrapper:
        is_validator_run_success(ProofValidation.validate_proof, corrupted_proof, other_key_pair.public_base58)
    assert isinstance(err_wrapper.value.__cause__, InvalidSignature)


def test_validate_proof_with_corrupted_signature_raises_validation_error(other_key_pair):
    corrupted_proof = Proof(issuer=valid_proof, content=b'a content', signature='plop not a signature')
    with pytest.raises(IdentityInvalidProofError) as err_wrapper:
        is_validator_run_success(ProofValidation.validate_proof, corrupted_proof, other_key_pair.public_base58)
    assert isinstance(err_wrapper.value.__cause__, ValueError)


def get_delegation_doc_for(controller_name: str, doc_id: str, public_base58: str) -> RegisterDocument:
    return get_doc_with_keys(
        did=doc_id,
        public_keys=[
            RegisterPublicKey.build(controller_name, public_base58, revoked=False),
        ]

    )


@pytest.mark.parametrize('proof_type,get_content', ((DelegationProofType.DID, lambda did: did.encode()),
                                                    (DelegationProofType.GENERIC, lambda did: b'')))
def test_can_validate_delegation(doc_did,
                                 deleg_doc_did,
                                 valid_issuer_key,
                                 valid_key_pair_secrets,
                                 proof_type,
                                 get_content):
    controller_name = '#AController'
    deleg_proof = get_delegation_register_proof(subject_key_pair_secrets=valid_key_pair_secrets,
                                                content=get_content(doc_did),
                                                p_type=proof_type,
                                                subject_issuer=Issuer.build(deleg_doc_did, controller_name))
    deleg_doc = get_delegation_doc_for(controller_name=controller_name,
                                       doc_id=deleg_doc_did,
                                       public_base58=valid_issuer_key.public_key_base58)
    resolver_client = ResolverClientTest(docs={deleg_doc_did: deleg_doc})
    assert is_validator_run_success(DelegationValidation.validate_delegation, resolver_client,
                                    doc_id=doc_did, deleg_proof=deleg_proof)


def test_validate_delegation_raises_validation_error_if_delegation_to_self(deleg_doc_did, valid_key_pair_secrets):
    deleg_proof = get_delegation_register_proof(subject_key_pair_secrets=valid_key_pair_secrets,
                                                # parent and delegated doc are the same
                                                content=deleg_doc_did.encode(),
                                                p_type=DelegationProofType.DID,
                                                subject_issuer=Issuer.build(deleg_doc_did, '#AController'))
    resolver_client = ResolverClientTest()
    with pytest.raises(IdentityInvalidDocumentDelegationError):
        DelegationValidation.validate_delegation(resolver_client, doc_id=deleg_doc_did, deleg_proof=deleg_proof)


def test_validate_delegation_raises_validation_error_if_invalid_proof_type(doc_did, deleg_doc_did, valid_issuer_key):
    controller_name = '#AController'
    deleg_proof = RegisterDelegationProof(name='#DelegKey',
                                          controller=Issuer.build(deleg_doc_did, controller_name),
                                          proof='a signature',
                                          proof_type='not existing type',
                                          revoked=False)
    deleg_doc = get_delegation_doc_for(controller_name=controller_name,
                                       doc_id=deleg_doc_did,
                                       public_base58=valid_issuer_key.public_key_base58)
    resolver_client = ResolverClientTest(docs={deleg_doc_did: deleg_doc})
    with pytest.raises(IdentityInvalidDocumentDelegationError) as wrapper:
        DelegationValidation.validate_delegation(resolver_client, doc_id=doc_did, deleg_proof=deleg_proof)
    assert "Invalid proof: invalid type" in str(wrapper.value)


def test_validate_delegation_raises_validation_error_if_public_key_not_in_deleg_controller_doc(doc_did, deleg_doc_did,
                                                                                               valid_issuer_key,
                                                                                               valid_key_pair_secrets):
    controller_name = '#AController'
    deleg_proof = get_delegation_register_proof(subject_key_pair_secrets=valid_key_pair_secrets,
                                                content=doc_did.encode(),
                                                p_type=DelegationProofType.DID,
                                                subject_issuer=Issuer.build(deleg_doc_did, controller_name))
    deleg_doc = get_doc_with_keys(
        did=doc_did,
        public_keys=[
            RegisterPublicKey.build('#NotMatchingTheController', valid_issuer_key.public_key_base58,
                                    revoked=False),
        ]

    )
    resolver_client = ResolverClientTest({deleg_doc_did: deleg_doc})
    with pytest.raises(IdentityInvalidDocumentDelegationError) as err_wrapper:
        DelegationValidation.validate_delegation(resolver_client, doc_id=doc_did, deleg_proof=deleg_proof)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_validate_delegation_raises_validation_error_if_invalid_delegation_proof(doc_did, deleg_doc_did,
                                                                                 valid_issuer_key,
                                                                                 other_key_pair_secrets):
    controller_name = '#AController'
    corrupted_deleg_proof = get_delegation_register_proof(subject_key_pair_secrets=other_key_pair_secrets,
                                                          content=doc_did.encode(),
                                                          p_type=DelegationProofType.DID,
                                                          subject_issuer=Issuer.build(deleg_doc_did, controller_name))
    deleg_doc = get_delegation_doc_for(controller_name=controller_name,
                                       doc_id=deleg_doc_did,
                                       public_base58=valid_issuer_key.public_key_base58)
    resolver_client = ResolverClientTest(docs={deleg_doc_did: deleg_doc})
    with pytest.raises(IdentityInvalidDocumentDelegationError) as err_wrapper:
        DelegationValidation.validate_delegation(resolver_client, doc_id=doc_did, deleg_proof=corrupted_deleg_proof)
    assert isinstance(err_wrapper.value.__cause__, IdentityInvalidProofError)


@pytest.mark.parametrize('wrong_type,get_content', ((DelegationProofType.GENERIC, lambda did: did.encode()),
                                                    (DelegationProofType.DID, lambda did: b'')))
def test_validate_delegation_raises_validation_error_if_content_does_not_match_proof_type(doc_did,
                                                                                          deleg_doc_did,
                                                                                          valid_issuer_key,
                                                                                          valid_key_pair_secrets,
                                                                                          wrong_type,
                                                                                          get_content):
    controller_name = '#AController'
    deleg_proof = get_delegation_register_proof(subject_key_pair_secrets=valid_key_pair_secrets,
                                                content=get_content(doc_did),
                                                p_type=wrong_type,
                                                subject_issuer=Issuer.build(deleg_doc_did, controller_name))
    deleg_doc = get_delegation_doc_for(controller_name=controller_name,
                                       doc_id=deleg_doc_did,
                                       public_base58=valid_issuer_key.public_key_base58)
    resolver_client = ResolverClientTest(docs={deleg_doc_did: deleg_doc})

    with pytest.raises(IdentityInvalidDocumentDelegationError) as err_wrapper:
        DelegationValidation.validate_delegation(resolver_client, doc_id=doc_did, deleg_proof=deleg_proof)
    assert isinstance(err_wrapper.value.__cause__, IdentityInvalidProofError)


class ResolverClientWithError(ResolverClient):
    def __init__(self, error_to_raise: Exception):
        self.error_to_raise = error_to_raise

    def get_document(self, doc_id: str) -> RegisterDocument:
        raise self.error_to_raise

    def register_document(self, document: RegisterDocument, private_key: ec.EllipticCurvePrivateKey, issuer: Issuer,
                          audience: str = ''):
        pass


@pytest.mark.parametrize('resolver_err', (IdentityResolverError,
                                          IdentityResolverTimeoutError,
                                          IdentityResolverCommunicationError,
                                          IdentityResolverDocNotFoundError))
def test_validate_delegation_raises_validation_error_if_resolver_error(doc_did, deleg_doc_did,
                                                                       valid_key_pair_secrets,
                                                                       resolver_err):
    controller_name = '#AController'

    deleg_proof = get_delegation_register_proof(subject_key_pair_secrets=valid_key_pair_secrets,
                                                content=doc_did.encode(),
                                                p_type=DelegationProofType.DID,
                                                subject_issuer=Issuer.build(deleg_doc_did, controller_name))
    resolver_client = ResolverClientWithError(error_to_raise=resolver_err())
    with pytest.raises(IdentityInvalidDocumentDelegationError) as err_wrapper:
        DelegationValidation.validate_delegation(resolver_client,
                                                 doc_id=doc_did,
                                                 deleg_proof=deleg_proof)
    assert isinstance(err_wrapper.value.__cause__, resolver_err)
