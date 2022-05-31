# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
from dataclasses import dataclass
from typing import Union

from iotics.lib.identity.crypto.proof import Issuer, KeyPairSecrets, Proof
from iotics.lib.identity.register.keys import DelegationProofType


@dataclass(frozen=True)
class APIProof:
    issuer: Issuer
    content: bytes
    signature: str

    @property
    def p_type(self) -> DelegationProofType:
        return DelegationProofType.DID

    @staticmethod
    def build(key_pair: KeyPairSecrets, issuer: Issuer, content: bytes) -> 'APIProof':
        proof = Proof.build(key_pair, issuer, content)
        return APIProof(proof.issuer, proof.content, proof.signature)


@dataclass(frozen=True)
class APIDidDelegationProof(APIProof):

    @property
    def p_type(self) -> DelegationProofType:
        return DelegationProofType.DID

    # pylint: disable=arguments-differ
    @staticmethod
    def build(key_pair: KeyPairSecrets, issuer: Issuer, did: str) -> 'APIDidDelegationProof':
        proof = APIProof.build(key_pair, issuer, did.encode())
        return APIDidDelegationProof(proof.issuer, proof.content, proof.signature)


@dataclass(frozen=True)
class APIGenericDelegationProof(APIProof):

    @property
    def p_type(self) -> DelegationProofType:
        return DelegationProofType.GENERIC

    # pylint: disable=arguments-differ
    @staticmethod
    def build(key_pair: KeyPairSecrets, issuer: Issuer) -> 'APIGenericDelegationProof':
        proof = APIProof.build(key_pair, issuer, b'')
        return APIGenericDelegationProof(proof.issuer, proof.content, proof.signature)


def get_proof_type(proof: Union[Proof, APIProof]) -> DelegationProofType:
    """
    Backward compatibility function to allow legacy Proof usage and new API Delegation Proof usage
    :param proof: a Proof or an API Delegation Proof
    :return: the proof type or the default proof type if not present
    """
    return getattr(proof, 'p_type', DelegationProofType.DID)
