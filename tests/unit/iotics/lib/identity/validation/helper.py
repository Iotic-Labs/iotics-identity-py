# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from typing import Callable, Tuple

import base58

from iotics.lib.identity import DelegationProofType, RegisterDocument, APIProof
from iotics.lib.identity.api.advanced_api import AdvancedIdentityLocalApi
from iotics.lib.identity.crypto.identity import make_identifier
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import DIDType, KeyPairSecrets, KeyPairSecretsHelper
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.keys import RegisterDelegationProof, RegisterPublicKey


def new_seed(length: int = 128) -> bytes:
    return AdvancedIdentityLocalApi.create_seed(length)


def is_validator_run_success(validator: Callable, *args, **kwargs):
    """ Run a validation helper and ensure it has been run.
    By design the validators return nothing and they raise when something is invalid.
    For the valid case we want to highlight the fact the validator has been called returning True
    at the end of this helper."""
    validator(*args, **kwargs)
    return True


def get_delegation_proof(issuer: Issuer, key_pair_secrets: KeyPairSecrets, delegating_doc_id: str) -> APIProof:
    return APIProof.build(key_pair_secrets, issuer, content=delegating_doc_id.encode())


def get_delegation_register_proof(subject_key_pair_secrets: KeyPairSecrets,
                                  subject_issuer: Issuer,
                                  content: bytes,
                                  p_type: DelegationProofType,
                                  deleg_key_name='#DelegKey') -> RegisterDelegationProof:
    proof = Proof.build(subject_key_pair_secrets, subject_issuer, content=content)

    return RegisterDelegationProof.build(deleg_key_name,
                                         controller=subject_issuer,
                                         proof=proof.signature,
                                         p_type=p_type,
                                         revoked=False)


def get_valid_document(seed: bytes, issuer_name: str, controller: Issuer = None):
    secrets = KeyPairSecrets.build(seed, 'iotics/0/something/twin')
    return get_valid_document_from_secret(secrets, issuer_name, controller)


def get_new_document(issuer_name: str) -> Tuple[KeyPairSecrets, Issuer, RegisterDocument]:
    secrets = KeyPairSecrets.build(new_seed(), 'iotics/0/something')
    doc = get_valid_document_from_secret(secrets, issuer_name)
    return secrets, Issuer.build(doc.did, issuer_name), doc


def get_valid_document_from_secret(secrets: KeyPairSecrets, issuer_name: str, controller: Issuer = None):
    public_base58 = KeyPairSecretsHelper.get_public_key_base58_from_key_pair_secrets(secrets)
    public_bytes = base58.b58decode(public_base58)
    doc_id = make_identifier(public_bytes)
    proof = Proof.build(secrets, Issuer.build(doc_id, issuer_name), content=doc_id.encode())
    return RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey(issuer_name, public_base58, revoked=False)) \
        .build(doc_id,
               DIDType.TWIN,
               proof=proof.signature,
               revoked=False,
               controller=controller)


def get_valid_delegated_doc_and_deleg_proof(seed: bytes, issuer_name: str, delegating_doc_id: str, deleg_name: str):
    secrets = KeyPairSecrets.build(seed, 'iotics/0/something/twindeleg')
    public_base58 = KeyPairSecretsHelper.get_public_key_base58_from_key_pair_secrets(secrets)
    public_bytes = base58.b58decode(public_base58)
    doc_id = make_identifier(public_bytes)
    issuer = Issuer.build(doc_id, issuer_name)
    proof = Proof.build(secrets, issuer, content=doc_id.encode())

    deleg_key = get_delegation_register_proof(subject_key_pair_secrets=secrets,
                                              content=delegating_doc_id.encode(),
                                              p_type=DelegationProofType.DID,
                                              subject_issuer=Issuer.build(doc_id, issuer_name),
                                              deleg_key_name=deleg_name)
    delegated_doc = RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey(issuer_name, public_base58, revoked=False)) \
        .build(doc_id, DIDType.TWIN, proof=proof.signature, revoked=False)
    return delegated_doc, deleg_key
