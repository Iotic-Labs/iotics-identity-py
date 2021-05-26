# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from dataclasses import dataclass

from iotics.lib.identity.const import ISSUER_SEPARATOR
from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.validation.identity import IdentityValidation


@dataclass(frozen=True)
class Issuer:
    did: str
    name: str

    @staticmethod
    def build(did: str, name: str) -> 'Issuer':
        """
        Build a valid issuer.
        :param did: issuer decentralised identifier
        :param name: issuer name
        :return: valid issuer

        :raises:
            IdentityValidationError: if invalid name or did

        """
        IdentityValidation.validate_identifier(did)
        IdentityValidation.validate_key_name(name)
        return Issuer(did, name)

    @staticmethod
    def from_string(issuer_string: str) -> 'Issuer':
        """
        Build a valid issuer from issuer string.
        :param issuer_string: issuer string
        :return: valid issuer

        :raises:
            IdentityValidationError: if invalid issuer string
        """
        parts = issuer_string.split(ISSUER_SEPARATOR)
        if len(parts) != 2:
            raise IdentityValidationError(
                f'Invalid issuer string {issuer_string} should be of the form of [did]#[name]')
        return Issuer.build(parts[0], f'#{parts[1]}')

    def __str__(self) -> str:
        return f'{self.did}{self.name}'


@dataclass(frozen=True)
class IssuerKey:
    issuer: Issuer
    public_key_base58: str

    @staticmethod
    def build(did: str, name: str, public_key_base58: str) -> 'IssuerKey':
        """
        Build an issuer key from identifier, name and public key.
        :param did: issuer decentralised identifier
        :param name: issuer name
        :param public_key_base58: public key base58
        :return: issuer key with valid issuer

        :raises:
            IdentityValidationError: if invalid name or did
        """
        return IssuerKey(Issuer.build(did, name), public_key_base58)
