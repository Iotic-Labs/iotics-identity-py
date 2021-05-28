# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from dataclasses import dataclass
from typing import Tuple

import base58
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.error import IdentityDependencyError, IdentityValidationError


@dataclass(frozen=True)
class KeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_bytes: bytes
    public_base58: str


class KeysHelper:

    @staticmethod
    def get_private_ECDSA(private_expo: str) -> ec.EllipticCurvePrivateKey:
        """
        Get private key (ECDSA) from master and purpose
        :param private_expo: private exponent as hex string
        :return: private ECDSA key

        :raises:
            IdentityDependencyError: if incompatible EllipticCurve dependency
        """
        sbin = bytes.fromhex(private_expo)
        sint = int.from_bytes(sbin, 'big', signed=False)

        try:
            return ec.derive_private_key(sint, ec.SECP256K1(), default_backend())
        except Exception as err:
            raise IdentityDependencyError(f'Dependency cryptography failed to derive private key: {err}') from err

    @staticmethod
    def get_public_keys_from_private_ECDSA(private_key: ec.EllipticCurvePrivateKey) -> Tuple[bytes, str]:
        """
        Get public keys (bytes and base58) from private key (ECDSA)
        :param private_key: private key
        :return: public key bytes, public key base58
        """
        public_key = private_key.public_key()

        public_bytes = public_key.public_bytes(encoding=serialization.Encoding.X962,
                                               format=serialization.PublicFormat.UncompressedPoint)
        return public_bytes, base58.b58encode(public_bytes).decode('ascii')

    @staticmethod
    def get_public_ECDSA_from_base58(public_base58: str) -> ec.EllipticCurvePublicKey:
        """
        Get public key ECDSA from public key base58
        :param public_base58: public key base58
        :return: public key ECDSA

        :raises:
            IdentityValidationError: if invalid public base58 key
        """
        try:
            public_bytes = base58.b58decode(public_base58)
            public_ecdsa = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_bytes)
            return public_ecdsa
        except ValueError as err:
            raise IdentityValidationError(f'Can not convert public key base58 to ECDSA: \'{err}\'') from err
