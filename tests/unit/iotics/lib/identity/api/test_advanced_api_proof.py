# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from iotics.lib.identity import APIDidDelegationProof, APIGenericDelegationProof, APIProof, get_proof_type, Proof
from iotics.lib.identity.register.keys import DelegationProofType


def test_can_build_api_proof(valid_issuer, valid_key_pair_secrets):
    content = b"some content"
    proof = APIProof.build(
        valid_key_pair_secrets,
        valid_issuer,
        content
    )
    assert proof.signature, 'the proof should have a not empty signature'
    assert proof.issuer == valid_issuer
    assert proof.content == content
    assert proof.p_type == DelegationProofType.DID


def test_can_build_api_did_delegation_proof(doc_did, valid_issuer, valid_key_pair_secrets):
    proof = APIDidDelegationProof.build(
        valid_key_pair_secrets,
        valid_issuer,
        doc_did
    )
    assert proof.signature, 'the proof should have a not empty signature'
    assert proof.issuer == valid_issuer
    assert proof.content == doc_did.encode()
    assert proof.p_type == DelegationProofType.DID


def test_can_build_api_generic_delegation_proof(valid_issuer, valid_key_pair_secrets):
    proof = APIGenericDelegationProof.build(
        valid_key_pair_secrets,
        valid_issuer
    )
    assert proof.signature, 'the proof should have a not empty signature'
    assert proof.issuer == valid_issuer
    assert proof.content == b''
    assert proof.p_type == DelegationProofType.GENERIC


def test_get_proof_type_support_legacy_proof(valid_issuer, valid_key_pair_secrets):
    proof = Proof.build(valid_key_pair_secrets, valid_issuer, b'content')
    assert get_proof_type(proof) == DelegationProofType.DID


def test_can_get_proof_type_from_api_did_delegation_proof(doc_did, valid_issuer, valid_key_pair_secrets):
    proof = APIDidDelegationProof.build(valid_key_pair_secrets, valid_issuer, doc_did)
    assert get_proof_type(proof) == DelegationProofType.DID


def test_can_get_proof_type_from_api_generic_delegation_proof(valid_issuer, valid_key_pair_secrets):
    proof = APIGenericDelegationProof.build(valid_key_pair_secrets, valid_issuer)
    assert get_proof_type(proof) == DelegationProofType.GENERIC
