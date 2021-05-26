# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.crypto.issuer import Issuer, IssuerKey
from iotics.lib.identity.error import IdentityValidationError


@pytest.fixture
def did():
    return 'did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEgY'


@pytest.fixture
def name():
    return '#aName'


def test_can_build_issuer(did, name):
    issuer = Issuer.build(did, name)
    assert issuer.did == did
    assert issuer.name == name


def test_can_build_issuer_from_string(did, name):
    issuer_string = f'{did}{name}'
    issuer = Issuer.from_string(issuer_string)
    assert issuer.did == did
    assert issuer.name == name


def test_building_issuer_with_invalid_name_raises_validation_error(did):
    with pytest.raises(IdentityValidationError):
        Issuer.build(did, 'invalidName')


def test_building_issuer_from_string_with_invalid_name_raises_validation_error(did):
    with pytest.raises(IdentityValidationError):
        Issuer.from_string(f'{did}#invalid name')


def test_building_issuer_with_invalid_did_raises_validation_error(name):
    with pytest.raises(IdentityValidationError):
        Issuer.build('invalidDID', name)


def test_building_issuer_from_string_with_invalid_did_raises_validation_error(name):
    with pytest.raises(IdentityValidationError):
        Issuer.from_string(f'invalidDID{name}')


def test_can_build_issuer_from_string_with_invalid_string_raises_validation_error(did):
    with pytest.raises(IdentityValidationError):
        Issuer.from_string(f'{did}aNameWithoutSep')


def test_can_build_issuer_key(did, name, valid_public_base58):
    issuer_key = IssuerKey.build(did, name, valid_public_base58)
    assert issuer_key.issuer == Issuer(did, name)
    assert issuer_key.public_key_base58 == valid_public_base58


def test_building_issuer_key_with_invalid_issuer_data_raises_validation_error(name, valid_public_base58):
    with pytest.raises(IdentityValidationError):
        IssuerKey.build('invalid did', name, valid_public_base58)
