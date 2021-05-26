# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from datetime import datetime

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.const import DEFAULT_TOKEN_START_OFFSET_SECONDS, TOKEN_ALGORITHM
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.keys import KeysHelper
from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.register.document import RegisterDocument


class JwtTokenHelper:

    @staticmethod
    def decode_token(token: str) -> dict:
        """
        Decode a jwt token without verifying it.
        :param token: jwt token
        :return: decoded token

        :raises:
            IdentityValidationError: if invalid token
        """
        try:
            return jwt.decode(token, options={'verify_signature': False},
                              algorithms=[TOKEN_ALGORITHM], verify=False)
        except jwt.exceptions.DecodeError as err:
            raise IdentityValidationError(f'Can not decode invalid token: \'{err}\'') from err

    @staticmethod
    def decode_and_verify_token(token: str, public_base58: str, audience: str):
        """
        Decode a jwt token and verifying it.
        :param token: jwt token
        :param public_base58:  token public base58 key
        :param audience: token audience
        :return: decoded verified token

        :raises:
            IdentityValidationError: if invalid token
            IdentityValidationError: if invalid token signature
            IdentityValidationError: if expired token
        """
        try:
            key = KeysHelper.get_public_ECDSA_from_base58(public_base58)
            return jwt.decode(token, key, audience=audience, algorithms=[TOKEN_ALGORITHM],  # type: ignore
                              verify=True, options={'verify_signature': True})
        except jwt.exceptions.InvalidSignatureError as err:
            raise IdentityValidationError(f'Invalid token signature: \'{err}\'') from err
        except jwt.exceptions.ExpiredSignatureError as err:
            raise IdentityValidationError(f'Expired token: \'{err}\'') from err
        except jwt.exceptions.DecodeError as err:
            raise IdentityValidationError(f'Can not decode invalid token: \'{err}\'') from err

    @staticmethod
    def create_doc_token(issuer: Issuer, audience: str, doc: RegisterDocument,
                         private_key: ec.EllipticCurvePrivateKey) -> str:
        """
        Create a register document jwt token.
        :param issuer: document issuer
        :param audience: token audience
        :param doc: register document
        :param private_key: issuer private key
        :return: encoded jwt token

        :raises:
            IdentityValidationError: if can not encode the token
        """
        try:
            return jwt.encode({'iss': str(issuer), 'aud': audience, 'doc': doc.to_dict()}, private_key,  # type: ignore
                              algorithm=TOKEN_ALGORITHM)
        except (TypeError, ValueError) as err:
            raise IdentityValidationError(f'Can not create document token for {issuer}: \'{err}\'') from err

    @staticmethod
    def create_auth_token(iss: str, sub: str, aud: str, duration: int,
                          private_key: ec.EllipticCurvePrivateKey,
                          start_offset: int = DEFAULT_TOKEN_START_OFFSET_SECONDS) -> str:
        """
        Create an authentication jwt token.
        :param iss: issuer as string
        :param sub: subject document did
        :param aud: token audience
        :param duration: token duration (seconds)
        :param private_key: issuer private key
        :param start_offset: offset for token valid-from time used (default=DEFAULT_TOKEN_START_OFFSET_SECONDS)
        :return: encoded jwt token

        :raises:
            IdentityValidationError: if invalid duration (<=0)
            IdentityValidationError: if can not encode the token
        """
        now = int(datetime.now().timestamp())
        if duration < 0:
            raise IdentityValidationError(f'Can not create auth token with duration={duration}, must be >0')
        try:
            return jwt.encode({
                'iss': iss,
                'aud': aud,
                'sub': sub,
                'iat': now + start_offset,
                'exp': now + duration
            }, private_key, algorithm='ES256')  # type: ignore
        except (TypeError, ValueError) as err:
            raise IdentityValidationError(f'Can not create auth token for {iss}/{sub}: \'{err}\'') from err
