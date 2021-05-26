# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.crypto.key_pair_secrets import KEY_PAIR_PATH_PREFIX


@pytest.fixture
def valid_seed_16_bytes():
    return b'a' * 16


@pytest.fixture
def valid_bip39_seed_32_bytes():
    return b'a' * 32


@pytest.fixture
def valid_key_pair_path():
    return f'{KEY_PAIR_PATH_PREFIX}plop'


@pytest.fixture
def valid_public_base58():
    return 'Q9F3CfJDDkfdp5s81tReuhaew12Y56askT1RJCdXcbiHcLvBLz2HHmGPxS6XrrkujxLRCHJ6CkkTKfU3izDgMqLa'
