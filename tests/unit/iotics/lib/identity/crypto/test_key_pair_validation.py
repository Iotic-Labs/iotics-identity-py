# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.crypto.key_pair_secrets import build_agent_secrets, build_twin_secrets, build_user_secrets, \
    DIDType, KEY_PAIR_PATH_PREFIX, KeyPairSecrets, SeedMethod
from iotics.lib.identity.error import IdentityValidationError


def test_can_create_key_pair_secrets_with_none_seed_method(valid_seed_16_bytes,
                                                           valid_key_pair_path):
    password = 'a password'
    key_pair = KeyPairSecrets.build(seed=valid_seed_16_bytes,
                                    path=valid_key_pair_path,
                                    password=password,
                                    seed_method=SeedMethod.SEED_METHOD_NONE)

    assert key_pair.seed == valid_seed_16_bytes
    assert key_pair.path == valid_key_pair_path
    assert key_pair.seed_method == SeedMethod.SEED_METHOD_NONE
    assert key_pair.password == password


def test_can_create_key_pair_secrets_with_default_bip39_seed_method(valid_bip39_seed_32_bytes,
                                                                    valid_key_pair_path):
    password = 'a password'
    key_pair = KeyPairSecrets.build(seed=valid_bip39_seed_32_bytes,
                                    path=valid_key_pair_path,
                                    password=password)

    assert key_pair.seed == valid_bip39_seed_32_bytes
    assert key_pair.path == valid_key_pair_path
    assert key_pair.seed_method == SeedMethod.SEED_METHOD_BIP39
    assert key_pair.password == password


@pytest.mark.parametrize('invalid_seed,error_val', (('a' * 16, 'Invalid seed format'),
                                                    (b'too long' * 945, 'Invalid seed length'),
                                                    (b'', 'Invalid seed length'),
                                                    (12345, 'Invalid seed format')))
def test_create_key_pair_raises_validation_error_if_invalid_seed_with_bip39_method(invalid_seed, error_val,
                                                                                   valid_key_pair_path):
    with pytest.raises(IdentityValidationError) as err_wpr:
        KeyPairSecrets.build(seed=invalid_seed,
                             path=valid_key_pair_path)
    assert error_val in str(err_wpr.value)


@pytest.mark.parametrize('invalid_seed,error_val', (('a' * 16, 'Invalid seed format'),
                                                    (b'not long enough'[0:3], 'Invalid seed length'),
                                                    (b'', 'Invalid seed length'),
                                                    (12345, 'Invalid seed format')))
def test_create_key_pair_raises_validation_error_if_invalid_seed_with_none_method(invalid_seed, error_val,
                                                                                  valid_key_pair_path):
    with pytest.raises(IdentityValidationError) as err_wpr:
        KeyPairSecrets.build(seed=invalid_seed,
                             path=valid_key_pair_path,
                             seed_method=SeedMethod.SEED_METHOD_BIP39)
    assert error_val in str(err_wpr.value)


def test_create_key_pair_raises_validation_error_if_invalid_path(valid_bip39_seed_32_bytes):
    with pytest.raises(IdentityValidationError) as err_wpr:
        KeyPairSecrets.build(seed=valid_bip39_seed_32_bytes,
                             path='invalid path (no starting with Iotics prefix)')
    assert 'Invalid key pair path' in str(err_wpr.value)


@pytest.mark.parametrize('create_key_pair_with_purpose, expected_path', (
    (build_user_secrets, f'{KEY_PAIR_PATH_PREFIX}/{DIDType.USER}/a_name'),
    (build_agent_secrets, f'{KEY_PAIR_PATH_PREFIX}/{DIDType.AGENT}/a_name'),
    (build_twin_secrets, f'{KEY_PAIR_PATH_PREFIX}/{DIDType.TWIN}/a_name')
))
def test_create_key_pair_with_purpose(create_key_pair_with_purpose, expected_path,
                                      valid_bip39_seed_32_bytes):
    password = 'a passwd'
    name = 'a_name'
    key_pair = create_key_pair_with_purpose(seed=valid_bip39_seed_32_bytes,
                                            name=name,
                                            seed_method=SeedMethod.SEED_METHOD_NONE,
                                            password=password)
    assert key_pair.seed == valid_bip39_seed_32_bytes
    assert key_pair.path == expected_path
    assert key_pair.seed_method == SeedMethod.SEED_METHOD_NONE
    assert key_pair.password == password
