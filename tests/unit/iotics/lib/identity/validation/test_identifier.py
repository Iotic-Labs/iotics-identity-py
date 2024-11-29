# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.validation.identity import IdentityValidation
from tests.unit.iotics.lib.identity.validation.helper import is_validator_run_success


@pytest.fixture
def an_identifier():
    return 'did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7'


def test_validate_identifier_do_not_raises_if_valid_identifier(an_identifier):
    assert is_validator_run_success(IdentityValidation.validate_identifier, an_identifier)


@pytest.mark.parametrize('invalid_identifier', (
    'ddi:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEgY',  # Invalid prefix
    'did:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEI',  # Invalid 'I' character
    'did:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEg',  # Invalid size
))
def test_validate_identifier_raises_validation_error_if_invalid_identifier(invalid_identifier):
    with pytest.raises(IdentityValidationError):
        is_validator_run_success(IdentityValidation.validate_identifier, invalid_identifier)


@pytest.mark.parametrize('key_name', ('#AName',
                                      '#a',
                                      '#b-C-8'))
def test_validate_key_name_do_not_raises_if_valid_identifier(key_name):
    assert is_validator_run_success(IdentityValidation.validate_key_name, key_name)


@pytest.mark.parametrize('invalid_key_name', ('AName',  # Invalid prefix
                                              '#' + 'a' * 50,  # Too long
                                              '#a+plop',  # Invalid char
                                              ))
def test_validate_key_name_raises_validation_error_if_invalid_identifier(invalid_key_name):
    with pytest.raises(IdentityValidationError):
        is_validator_run_success(IdentityValidation.validate_key_name, invalid_key_name)


def test_validate_issuer_string_do_not_raises_if_valid_issuer(an_identifier):
    assert is_validator_run_success(IdentityValidation.validate_issuer_string, f'{an_identifier}#AName')


@pytest.mark.parametrize('invalid_issuer',
                         ('ddi:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEgY#AName',  # Invalid identifier
                          'did:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEY#++A++',  # Invalid Name
                          ))
def test_validate_issuer_string_raises_validation_error_if_invalid_identifier(invalid_issuer):
    with pytest.raises(IdentityValidationError):
        is_validator_run_success(IdentityValidation.validate_identifier, invalid_issuer)
