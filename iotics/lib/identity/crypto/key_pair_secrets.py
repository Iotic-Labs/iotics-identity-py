# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import hmac
from dataclasses import dataclass
from enum import Enum, unique
from hashlib import sha256, sha512

from cryptography.hazmat.primitives.asymmetric import ec
from mnemonic import Mnemonic  # type: ignore
from mnemonic.mnemonic import ConfigurationError  # type: ignore

from iotics.lib.identity.const import KEY_PAIR_PATH_PREFIX, MIN_SEED_METHOD_NONE_LEN
from iotics.lib.identity.crypto.keys import KeyPair, KeysHelper
from iotics.lib.identity.error import IdentityDependencyError, IdentityValidationError


@unique
class DIDType(Enum):
    HOST = 'host'  # Not used in Iotics ecosystem
    USER = 'user'
    AGENT = 'agent'
    TWIN = 'twin'

    def __str__(self) -> str:
        return str(self.value)


@unique
class SeedMethod(Enum):
    SEED_METHOD_NONE = 0
    SEED_METHOD_BIP39 = 1


@dataclass(frozen=True)
class KeyPairSecrets:
    seed: bytes
    path: str
    seed_method: SeedMethod
    password: str

    @staticmethod
    def build(seed: bytes, path: str, seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
              password: str = '') -> 'KeyPairSecrets':
        """
        Build a valid key pair secrets.
        :param seed: key seed
        :param path: key path
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :param password: key password (secrets) (Optional: can be empty string)
        :return: valid key pair secrets

        :raises:
            IdentityValidationError: if invalid key seed
            IdentityValidationError: if invalid key path
        """
        if seed_method == SeedMethod.SEED_METHOD_NONE:
            if len(seed) < MIN_SEED_METHOD_NONE_LEN:
                raise IdentityValidationError(f'Invalid seed length for method \'SEED_METHOD_NONE\', '
                                              f'must be at least {MIN_SEED_METHOD_NONE_LEN} bytes')
        elif seed_method == SeedMethod.SEED_METHOD_BIP39:
            KeyPairSecretsHelper.validate_bip39_seed(seed)
        else:
            raise IdentityValidationError(f'Invalid seed method \'{seed_method}\', '
                                          f'must be in {[m.name for m in SeedMethod]}')
        if not path.startswith(KEY_PAIR_PATH_PREFIX):
            raise IdentityValidationError(f'Invalid key pair path \'{path}\', '
                                          f'must start with {KEY_PAIR_PATH_PREFIX}')

        return KeyPairSecrets(seed, path, seed_method, password)


def build_user_secrets(seed: bytes, name: str,
                       seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                       password: str = '') -> KeyPairSecrets:
    """
    Build a valid key pair secrets for User.
    :param seed: User key seed
    :param name: User key name
    :param seed_method: User seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
    :param password: User key password (secrets) (Optional: can be empty string)
    :return: valid User key pair secrets

    :raises:
        IdentityValidationError: if invalid User key seed
        IdentityValidationError: if invalid User key name
    """
    user_path = f'{KEY_PAIR_PATH_PREFIX}/{DIDType.USER}/{name}'
    return KeyPairSecrets.build(seed, user_path, seed_method, password)


def build_agent_secrets(seed: bytes, name: str,
                        seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                        password: str = '') -> KeyPairSecrets:
    """
    Build a valid key pair secrets for Agent.
    :param seed: Agent key seed
    :param name: Agent key name
    :param seed_method: Agent seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
    :param password: Agent key password (secrets) (Optional: can be empty string)
    :return: valid Agent key pair secrets

    :raises:
        IdentityValidationError: if invalid Agent key seed
        IdentityValidationError: if invalid Agent key name
    """
    agent_path = f'{KEY_PAIR_PATH_PREFIX}/{DIDType.AGENT}/{name}'
    return KeyPairSecrets.build(seed, agent_path, seed_method, password)


def build_twin_secrets(seed: bytes, name: str,
                       seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                       password: str = '') -> KeyPairSecrets:
    """
    Build a valid key pair secrets for Twin.
    :param seed: Twin key seed
    :param name: Twin key name
    :param seed_method: Twin seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
    :param password: Twin key password (secrets) (Optional: can be empty string)
    :return: valid Twin key pair secrets

    :raises:
        IdentityValidationError: if invalid Twin key seed
        IdentityValidationError: if invalid Twin key name
    """
    twin_path = f'{KEY_PAIR_PATH_PREFIX}/{DIDType.TWIN}/{name}'
    return KeyPairSecrets.build(seed, twin_path, seed_method, password)


class KeyPairSecretsHelper:

    @staticmethod
    def mnemonic_bip39_to_seed(mnemonic: str, lang: str = 'english') -> bytes:
        """mnemonic_bip39_to_seed: Take mnemonic string and return seed string hex"""
        men = Mnemonic(lang)
        return men.to_entropy(mnemonic)

    @staticmethod
    def seed_bip39_to_mnemonic(seed: bytes, lang: str = 'english') -> str:
        """
        Convert a BIP39 seed to mnemonic.
        :param seed: BIP39 seed
        :param lang: a mnemonic language
        :return: a mnemonic

        :raises:
            IdentityValidationError: if invalid seed
            IdentityValidationError: if invalid lang
            IdentityDependencyError: if incompatible Mnemonic dependency
        """
        try:
            men = Mnemonic(lang)
            return men.to_mnemonic(seed)
        except ConfigurationError as err:
            raise IdentityDependencyError(f'Dependency Mnemonic Internal Error: {err}') from err
        except TypeError as err:
            raise IdentityValidationError(f'Invalid seed format for method \'SEED_METHOD_BIP39_LEN\': {err}') from err
        except ValueError as err:
            raise IdentityValidationError(f'Invalid seed length for method \'SEED_METHOD_BIP39_LEN\': {err}') from err
        except OSError as err:
            raise IdentityValidationError(f'Invalid language for mnemonic: {err}') from err

    @staticmethod
    def validate_bip39_seed(seed: bytes):
        """
        Valid BIP39 seed
        :param seed: BIP39 seed

        :raises:
            IdentityValidationError: if invalid seed
            IdentityValidationError: if invalid lang
            IdentityDependencyError: if incompatible Mnemonic dependency

        """
        KeyPairSecretsHelper.seed_bip39_to_mnemonic(seed)

    @staticmethod
    def get_private_key(key_pair_secrets: KeyPairSecrets) -> ec.EllipticCurvePrivateKey:
        """
        Get private key from key pair secrets
        :param key_pair_secrets: key pair secrets
        :return: private key

        :raise:
            IdentityValidationError: if invalid seed method
            IdentityValidationError: if invalid lang
            IdentityDependencyError: if incompatible Mnemonic dependency
            IdentityDependencyError: if incompatible EllipticCurve dependency
        """
        if key_pair_secrets.seed_method == SeedMethod.SEED_METHOD_NONE:
            result = hmac.new(key_pair_secrets.seed, key_pair_secrets.password.encode(), sha512).digest()
        elif key_pair_secrets.seed_method == SeedMethod.SEED_METHOD_BIP39:
            men = KeyPairSecretsHelper.seed_bip39_to_mnemonic(key_pair_secrets.seed)
            result = Mnemonic.to_seed(men, key_pair_secrets.password)
        else:
            raise IdentityValidationError(f'Invalid seed method \'{key_pair_secrets.seed_method}\', '
                                          f'must be in {[m.name for m in SeedMethod]}')

        private_expo = hmac.new(result, key_pair_secrets.path.encode(), sha256).hexdigest()
        return KeysHelper.get_private_ECDSA(private_expo)

    @staticmethod
    def get_public_key_base58_from_key_pair_secrets(key_pair_secrets: KeyPairSecrets) -> str:
        """
        Get public key base58 fron key pair secrets
        :param key_pair_secrets: key pair secrets
        :return: public key base58

        :raise:
            IdentityValidationError: if invalid key_pair_secrets
            IdentityDependencyError: if incompatible EllipticCurve dependency
        """
        private_key = KeyPairSecretsHelper.get_private_key(key_pair_secrets)
        _, base58 = KeysHelper.get_public_keys_from_private_ECDSA(private_key)
        return base58

    @staticmethod
    def get_key_pair(key_pair_secrets: KeyPairSecrets) -> KeyPair:
        """
        Get key pair from key pair secrets
        :param key_pair_secrets: key pair secrets
        :return: key pair

        :raises:
            IdentityValidationError: if invalid key_pair_secrets
        """
        private_key = KeyPairSecretsHelper.get_private_key(key_pair_secrets)
        public_bytes, public_base58 = KeysHelper.get_public_keys_from_private_ECDSA(private_key)
        return KeyPair(private_key=private_key,
                       public_bytes=public_bytes,
                       public_base58=public_base58)
