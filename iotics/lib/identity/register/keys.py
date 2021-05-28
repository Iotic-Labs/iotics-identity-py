# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from iotics.lib.identity.const import DOCUMENT_AUTHENTICATION_TYPE, DOCUMENT_PUBLIC_KEY_TYPE
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.validation.identity import IdentityValidation


@dataclass(frozen=True)  # type: ignore
class RegisterKeyBase(ABC):
    name: str

    @abstractmethod
    def get_new_key(self, revoked: bool) -> 'RegisterKeyBase':
        raise NotImplementedError

    @abstractmethod
    def is_equal(self, other: 'RegisterKeyBase') -> bool:
        raise NotImplementedError


@dataclass(frozen=True)  # type: ignore
class RegisterKey(RegisterKeyBase, ABC):
    base58: str
    revoked: bool

    @abstractmethod
    def get_new_key(self, revoked: bool) -> 'RegisterKeyBase':
        raise NotImplementedError

    def is_equal(self, other: 'RegisterKey') -> bool:  # type: ignore
        """
        Check if register key is equal by name, public key base58 and revoked
        This is not overriding the default __eq__ because we still need to fully compare the objects

        :param other: Other register key to compare
        :return: True if equal
        """
        return self.name == other.name and self.base58 == other.base58 and self.revoked == other.revoked


@dataclass(frozen=True)
class RegisterPublicKey(RegisterKey):

    def to_dict(self) -> dict:
        ret = {
            'id': self.name,
            'type': DOCUMENT_PUBLIC_KEY_TYPE,
            'publicKeyBase58': self.base58,
            'revoked': self.revoked,
        }
        return ret

    def get_new_key(self, revoked: bool) -> 'RegisterPublicKey':
        """
        Get a new register public key from the current setting revoke field.
        :param revoked: is revoked
        :return: register public key

        :raises:
            IdentityValidationError: if invalid register public key
        """
        return RegisterPublicKey.build(self.name, self.base58, revoked)

    @staticmethod
    def from_dict(data: dict):
        """
        Build a register public key from dict.
        :param data: register public key as dict
        :return: valid register public key

        :raises:
            IdentityValidationError: if invalid register public key as dict
        """
        try:
            return RegisterPublicKey.build(data['id'], data['publicKeyBase58'],
                                           data.get('revoked', False))

        except (TypeError, KeyError, ValueError) as err:
            raise IdentityValidationError(f'Can not parse invalid register public key: \'{err}\'') from err

    @staticmethod
    def build(name: str, public_base58: str, revoked: Optional[bool] = False) -> 'RegisterPublicKey':
        """
        Build a register public key.
        :param name: key name
        :param public_base58: public key base58
        :param revoked: is revoked key (default=False)
        :return: valid register public key

        :raises:
            IdentityValidationError: if invalid key name
        """
        IdentityValidation.validate_key_name(name)
        return RegisterPublicKey(name=name, base58=public_base58, revoked=revoked)  # type: ignore


@dataclass(frozen=True)
class RegisterAuthenticationPublicKey(RegisterKey):

    def to_dict(self) -> dict:
        ret = {
            'id': self.name,
            'type': DOCUMENT_AUTHENTICATION_TYPE,
            'publicKeyBase58': self.base58,
            'revoked': self.revoked,
        }
        return ret

    def get_new_key(self, revoked: bool) -> 'RegisterAuthenticationPublicKey':
        """
        Get a new register authentication public key from the current setting revoke field.
        :param revoked: is revoked
        :return: register authentication public key

        :raises:
            IdentityValidationError: if invalid register authentication public key
        """
        return RegisterAuthenticationPublicKey.build(self.name, self.base58, revoked)

    @staticmethod
    def from_dict(data: dict):
        """
        Build a register authentication public key from dict.
        :param data: register authentication public key as dict
        :return: valid register authentication public key

        :raises:
            IdentityValidationError: if invalid register authentication public key as dict
        """
        try:
            return RegisterAuthenticationPublicKey.build(data['id'], data['publicKeyBase58'],
                                                         data.get('revoked', False))
        except (TypeError, KeyError, ValueError) as err:
            raise IdentityValidationError(
                f'Can not parse invalid register authentication public key: \'{err}\'') from err

    @staticmethod
    def build(name: str, public_base58: str, revoked: Optional[bool] = False) -> 'RegisterAuthenticationPublicKey':
        """
         Build a register authentication public key.
         :param name: key name
         :param public_base58: authentication public key base58
         :param revoked: is revoked key (default=False)
         :return: valid register authentication public key

         :raises:
             IdentityValidationError: if invalid key name
         """
        IdentityValidation.validate_key_name(name)
        return RegisterAuthenticationPublicKey(name=name, base58=public_base58, revoked=revoked)  # type: ignore


@dataclass(frozen=True)
class RegisterDelegationProof(RegisterKeyBase):
    controller: Issuer
    proof: str
    revoked: bool

    def is_equal(self, other: 'RegisterDelegationProof') -> bool:  # type: ignore
        """
        Check if register delegation proof is equal by name, controller and revoked
        Cannot check proof as this changes every time
        This is not overriding the default __eq__ because we still need to fully compare the objects

        :param other: Other register delegation proof to compare
        :return: True if equal
        """
        return self.name == other.name and self.controller == other.controller and self.revoked == other.revoked

    def to_dict(self):
        return {'id': self.name,
                'controller': str(self.controller),
                'proof': self.proof,
                'revoked': self.revoked}

    def get_new_key(self, revoked: bool) -> 'RegisterDelegationProof':
        """
        Get a new register delegation proof from the current setting revoke field.
        :param revoked: is revoked
        :return: register delegation proof

        :raises:
            IdentityValidationError: if invalid register delegation proof
        """
        return RegisterDelegationProof.build(self.name, self.controller, self.proof, revoked)

    @staticmethod
    def from_dict(data: dict):
        """
        Build a register delegation public key from dict.
        :param data: register delegation public key as dict
        :return: valid register delegation key

        :raises:
            IdentityValidationError: if invalid register delegation public key as dict
        """
        try:
            controller = Issuer.from_string(data['controller'])
            return RegisterDelegationProof.build(data['id'], controller, data['proof'],
                                                 data.get('revoked', False))
        except (TypeError, KeyError, ValueError) as err:
            raise IdentityValidationError(f'Can not parse invalid register delegation proof: \'{err}\'') from err

    @staticmethod
    def build(name: str, controller: Issuer, proof: str, revoked: Optional[bool] = False) -> 'RegisterDelegationProof':
        """
        Build a register delegation public key.
        :param name: key name
        :param controller: delegation controller
        :param proof: delegation proof
        :param revoked: is revoked key (default=False)
        :return: valid register delegation public key

         :raises:
             IdentityValidationError: if invalid key name
             IdentityValidationError: if invalid delegation controller
        """
        IdentityValidation.validate_key_name(name)
        return RegisterDelegationProof(name, controller, proof, revoked)  # type: ignore
