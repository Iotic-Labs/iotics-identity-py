# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import base64
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.const import TOKEN_ALGORITHM
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.crypto.key_pair_secrets import KeyPairSecrets, KeyPairSecretsHelper
from iotics.lib.identity.error import IdentityInvalidRegisterIssuerError, IdentityValidationError
from iotics.lib.identity.register.document_helper import RegisterDocumentHelper
from iotics.lib.identity.register.resolver import ResolverClient


@dataclass(frozen=True)
class Proof:
    issuer: Issuer
    content: bytes
    signature: str

    @staticmethod
    def from_challenge_token(resolver_client: ResolverClient, challenge_token: str) -> 'Proof':
        """
        Build proof from challenge token.
        :param resolver_client: resolver client to get the registered documents
        :param challenge_token: jwt challenge token
        :return: valid proof

        :raises:
            IdentityValidationError: if invalid challenge token
        """
        decoded_token = JwtTokenHelper.decode_token(challenge_token)
        iss = decoded_token.get('iss')
        aud = decoded_token.get('aud')
        if not iss or not aud:
            raise IdentityValidationError('Invalid challenge token, missing \'iss\' or \'aud\'')

        issuer = Issuer.from_string(iss)
        doc = resolver_client.get_document(issuer.did)
        get_controller_doc = resolver_client.get_document
        issuer_key = RegisterDocumentHelper.get_valid_issuer_key_for_control_only(doc, issuer.name, get_controller_doc)
        if not issuer_key:
            raise IdentityInvalidRegisterIssuerError(f'Invalid issuer {issuer}')
        verified_token = JwtTokenHelper.decode_and_verify_token(challenge_token, issuer_key.public_key_base58, aud)
        return Proof(issuer_key.issuer, aud.encode('ascii'), verified_token['proof'])

    @staticmethod
    def build(key_pair: KeyPairSecrets, issuer: Issuer, content: bytes) -> 'Proof':
        """
        Build a proof.
        :param key_pair: secrets used to build the proof signature
        :param issuer: proof issuer
        :param content:  proof content
        :return: proof

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityDependencyError: if incompatible library dependency
        """
        private_key = KeyPairSecretsHelper.get_private_key(key_pair)
        sig = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        proof = base64.b64encode(sig).decode('ascii')
        return Proof(issuer=issuer, content=content, signature=proof)


def build_new_challenge_token(proof: Proof, private_key: ec.EllipticCurvePrivateKey) -> str:
    """
    Build a new challenge token from a proof.
    :param proof: proof
    :param private_key: private key
    :return: jwt challenge token

    :raises:
        IdentityValidationError: if can not encode the token

    """
    try:
        return jwt.encode({'iss': str(proof.issuer), 'aud': proof.content.decode('ascii'), 'proof': proof.signature},
                          private_key, algorithm=TOKEN_ALGORITHM)  # type: ignore
    except (TypeError, ValueError) as err:
        raise IdentityValidationError(f'Can not create challenge token for {proof}: \'{err}\'') from err
