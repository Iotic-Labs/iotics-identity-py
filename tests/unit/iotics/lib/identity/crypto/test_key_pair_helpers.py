# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.crypto.key_pair_secrets import KeyPairSecrets, KeyPairSecretsHelper
from iotics.lib.identity.error import IdentityValidationError


def test_can_convert_seed_to_mnemonic(valid_bip39_seed):
    mnemonic = KeyPairSecretsHelper.seed_bip39_to_mnemonic(valid_bip39_seed)
    assert mnemonic == ('goddess muscle soft human fatal country this hockey great perfect evidence '
                        'gather industry rack silver small cousin another flee silver casino country '
                        'sugar purse')


def test_can_convert_seed_to_mnemonic_with_spanish(valid_bip39_seed):
    mnemonic = KeyPairSecretsHelper.seed_bip39_to_mnemonic(valid_bip39_seed, lang='spanish')
    assert mnemonic == ('glaciar mojar rueda hueso exponer chupar tanque hijo grano olvido ensayo '
                        'gaita inmune percha retrato rojo cielo alivio fiel retrato brusco chupar '
                        'sirena peine')


@pytest.mark.parametrize('invalid_seed,error_val', (('a' * 16, 'Invalid seed format'),
                                                    (b'too long' * 945, 'Invalid seed length'),
                                                    (b'', 'Invalid seed length'),
                                                    (12345, 'Invalid seed format')))
def test_convert_seed_to_mnemonic_raises_validation_error_if_invalid_seed(invalid_seed, error_val):
    with pytest.raises(IdentityValidationError) as err_wrp:
        KeyPairSecretsHelper.seed_bip39_to_mnemonic(invalid_seed)
    assert error_val in str(err_wrp.value)


def test_convert_seed_to_mnemonic_raises_validation_error_if_invalid_language(valid_bip39_seed):
    with pytest.raises(IdentityValidationError) as err_wrp:
        KeyPairSecretsHelper.seed_bip39_to_mnemonic(valid_bip39_seed, lang='invalid_lang')
    assert 'Invalid language for mnemonic:' in str(err_wrp.value)


def test_validate_bip39_seed_should_not_raise_if_valid_seed(valid_bip39_seed):
    KeyPairSecretsHelper.validate_bip39_seed(valid_bip39_seed)


def test_validate_bip39_seed_should_raise_if_invalid_seed():
    with pytest.raises(IdentityValidationError):
        KeyPairSecretsHelper.validate_bip39_seed(seed=b'invalid')


def test_can_get_private_key_from_key_pair_secrets(valid_key_pair_secrets):
    private_key = KeyPairSecretsHelper.get_private_key(valid_key_pair_secrets)
    assert private_key.key_size == ec.SECP256K1().key_size
    assert private_key.curve.name == ec.SECP256K1().name


def test_get_private_key_from_key_pair_secrets_raises_validation_error_if_invalid_method(valid_key_pair_secrets):
    key_pair_secret = KeyPairSecrets(valid_key_pair_secrets.seed, valid_key_pair_secrets.path,
                                     seed_method='plop', password='')
    with pytest.raises(IdentityValidationError):
        KeyPairSecretsHelper.get_private_key(key_pair_secret)


def test_can_get_public_base58_key(valid_key_pair_secrets, valid_public_base58):
    public_base58_key = KeyPairSecretsHelper.get_public_key_base58_from_key_pair_secrets(valid_key_pair_secrets)
    assert public_base58_key == valid_public_base58
