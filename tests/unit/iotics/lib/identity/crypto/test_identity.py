# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.const import IDENTIFIER_PREFIX
from iotics.lib.identity.crypto.identity import is_same_identifier, make_identifier


def test_can_make_identifier(valid_key_pair):
    new_id = make_identifier(valid_key_pair.public_bytes)
    assert new_id.startswith(IDENTIFIER_PREFIX)


def test_make_identifier_is_idempotent(valid_key_pair):
    assert make_identifier(valid_key_pair.public_bytes) == make_identifier(valid_key_pair.public_bytes)


A_DID = 'did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEgY'


@pytest.mark.parametrize('id_a,id_b', ((A_DID, A_DID),
                                       (A_DID, f'{A_DID}#Plop'),
                                       (f'{A_DID}#Plop', A_DID),
                                       (f'{A_DID}#AAA', f'{A_DID}#BBB')))
def test_is_same_identifier_return_true_for_the_same_identifier_ignoring_names(id_a, id_b):
    assert is_same_identifier(id_a, id_b)


@pytest.mark.parametrize('id_a,id_b', ((A_DID, f'{A_DID[:-1]}K'),
                                       (f'{A_DID}#Plop', f'{A_DID[-1]}K#Plop')))
def test_is_same_identifier_return_false_for_different_identifier_ignoring_names(id_a, id_b):
    assert not is_same_identifier(id_a, id_b)
