# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from datetime import datetime

import pytest

from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.crypto.keys import KeysHelper
from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder


def compare_doc(register_doc, decoded_doc):
    register_doc_as_dict = register_doc.to_dict()
    register_doc_as_dict.pop('updateTime')
    decoded_doc_as_dict = decoded_doc.to_dict()
    decoded_doc_as_dict.pop('updateTime')
    assert register_doc_as_dict == decoded_doc_as_dict


def test_can_create_doc_token(valid_issuer, valid_private_key, register_doc):
    token = JwtTokenHelper.create_doc_token(issuer=valid_issuer,
                                            audience='http://somehting',
                                            doc=register_doc,
                                            private_key=valid_private_key)
    assert token


def test_create_doc_token_raises_validation_error_if_can_not_create_token(valid_issuer, register_doc):
    with pytest.raises(IdentityValidationError):
        JwtTokenHelper.create_doc_token(issuer=valid_issuer,
                                        audience='http://somehting',
                                        doc=register_doc,
                                        private_key='no a private key')


def test_can_decode_doc_token(valid_issuer, valid_private_key, register_doc):
    audience = 'http://somehting'
    token = JwtTokenHelper.create_doc_token(issuer=valid_issuer,
                                            audience=audience,
                                            doc=register_doc,
                                            private_key=valid_private_key)
    decoded = JwtTokenHelper.decode_token(token)
    assert decoded['iss'] == str(valid_issuer)
    assert decoded['aud'] == audience
    decoded_doc = RegisterDocumentBuilder().build_from_dict(decoded['doc'])
    compare_doc(register_doc, decoded_doc)


def test_can_decode_and_verify_doc_token(valid_issuer_key, valid_private_key, register_doc):
    audience = 'http://somehting'
    token = JwtTokenHelper.create_doc_token(issuer=valid_issuer_key.issuer,
                                            audience=audience,
                                            doc=register_doc,
                                            private_key=valid_private_key)
    decoded = JwtTokenHelper.decode_and_verify_token(token, valid_issuer_key.public_key_base58, audience)
    assert decoded['iss'] == str(valid_issuer_key.issuer)
    assert decoded['aud'] == audience
    decoded_doc = RegisterDocumentBuilder().build_from_dict(decoded['doc'])
    compare_doc(register_doc, decoded_doc)


def test_can_create_auth_token(valid_issuer, valid_private_key):
    token = JwtTokenHelper.create_auth_token(iss=str(valid_issuer),
                                             sub='did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEEE',
                                             aud='http://somehting',
                                             duration=12,
                                             private_key=valid_private_key)
    assert token


def test_create_auth_token_raises_validation_error_if_can_not_create_token(valid_issuer):
    with pytest.raises(IdentityValidationError):
        JwtTokenHelper.create_auth_token(iss=str(valid_issuer),
                                         sub='did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEEE',
                                         aud='http://somehting',
                                         duration=12,
                                         private_key='no a private key')


def test_create_auth_token_raises_validation_error_if_negative_duration(valid_issuer, valid_private_key):
    with pytest.raises(IdentityValidationError):
        JwtTokenHelper.create_auth_token(iss=str(valid_issuer),
                                         sub='did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEEE',
                                         aud='http://somehting',
                                         duration=-12,
                                         private_key=valid_private_key)


def test_can_decode_auth_token(valid_issuer, valid_private_key):
    audience = 'http://somehting'
    subject = 'did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEEE'
    start_offset = -20
    duration = 12
    now = int(datetime.now().timestamp())
    token = JwtTokenHelper.create_auth_token(iss=str(valid_issuer),
                                             sub=subject,
                                             aud='http://somehting',
                                             duration=duration,
                                             private_key=valid_private_key,
                                             start_offset=start_offset)
    decoded = JwtTokenHelper.decode_token(token)
    assert decoded['iss'] == str(valid_issuer)
    assert decoded['aud'] == audience
    assert decoded['sub'] == subject
    assert decoded['iat'] >= now + start_offset
    assert decoded['exp'] >= (now + start_offset) + duration


def test_can_decode_and_verify_auth_token(valid_issuer_key, valid_private_key):
    audience = 'http://somehting'
    subject = 'did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEEE'
    start_offset = -20
    duration = 12
    now = int(datetime.now().timestamp())
    token = JwtTokenHelper.create_auth_token(iss=str(valid_issuer_key.issuer),
                                             sub=subject,
                                             aud='http://somehting',
                                             duration=duration,
                                             private_key=valid_private_key,
                                             start_offset=start_offset)
    decoded = JwtTokenHelper.decode_and_verify_token(token, valid_issuer_key.public_key_base58, audience)
    assert decoded['iss'] == str(valid_issuer_key.issuer)
    assert decoded['aud'] == audience
    assert decoded['sub'] == subject
    assert decoded['iat'] >= now + start_offset
    assert decoded['exp'] >= (now + start_offset) + duration


def test_decode_token_raises_validation_error_if_invalid_token():
    with pytest.raises(IdentityValidationError):
        JwtTokenHelper.decode_token('not a real token')


def test_decode_and_verify_token_raises_validation_error_if_invalid_token(valid_issuer_key):
    with pytest.raises(IdentityValidationError):
        JwtTokenHelper.decode_and_verify_token('not a real token', valid_issuer_key.public_key_base58,
                                               'http://audience')


def test_decode_and_verify_token_raises_validation_error_if_invalid_issuer_key(valid_issuer_key, register_doc,
                                                                               valid_private_key,
                                                                               other_private_key):
    audience = 'http://something'
    token = JwtTokenHelper.create_doc_token(issuer=valid_issuer_key.issuer,
                                            audience=audience,
                                            doc=register_doc,
                                            private_key=valid_private_key)

    with pytest.raises(IdentityValidationError):
        _, public_base58 = KeysHelper.get_public_keys_from_private_ECDSA(other_private_key)
        JwtTokenHelper.decode_and_verify_token(token, public_base58, audience)
