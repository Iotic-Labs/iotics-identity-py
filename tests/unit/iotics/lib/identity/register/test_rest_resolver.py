# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import jwt
import pytest
from requests import ConnectTimeout, HTTPError, RequestException

from iotics.lib.identity.const import TOKEN_ALGORITHM
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.error import IdentityInvalidRegisterIssuerError, IdentityResolverDocNotFoundError, \
    IdentityResolverError, IdentityResolverTimeoutError, IdentityValidationError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.keys import RegisterDelegationProof, RegisterPublicKey
from iotics.lib.identity.register.rest_resolver import ResolverSerializer, RESTResolverRequester
from tests.unit.iotics.lib.identity.helper import get_doc_with_keys


@pytest.fixture
def simple_doc(doc_did, valid_issuer_key):
    return get_doc_with_keys(
        did=doc_did,
        public_keys=[
            RegisterPublicKey.build(valid_issuer_key.issuer.name, valid_issuer_key.public_key_base58, revoked=False)],
    )


@pytest.fixture
def doc_with_doc_deleg(valid_issuer_key, doc_did, deleg_doc_did):
    doc = get_doc_with_keys(
        did=doc_did,
        public_keys=[RegisterPublicKey.build('#Key1', 'base58Key1', revoked=False)],
        deleg_control=[
            RegisterDelegationProof.build(valid_issuer_key.issuer.name,
                                          controller=Issuer.build(deleg_doc_did, '#plop1'), proof='aproof',
                                          revoked=False),
        ],
    )

    deleg_doc = get_doc_with_keys(
        did=deleg_doc_did,
        public_keys=[
            RegisterPublicKey.build(valid_issuer_key.issuer.name, valid_issuer_key.public_key_base58, revoked=False),
        ]

    )
    return doc, deleg_doc


def test_can_serialize_doc_to_token(simple_doc, valid_private_key, valid_issuer):
    token = ResolverSerializer.serialize_to_token(simple_doc, valid_private_key, valid_issuer,
                                                  audience='http://audience/')
    assert token


def raise_if_called(did: str) -> RegisterDocument:  # pylint: disable=unused-argument
    assert False, 'should not be called'


def test_can_get_valid_doc_from_token(simple_doc, valid_private_key, valid_issuer):
    token = ResolverSerializer.serialize_to_token(simple_doc, valid_private_key, valid_issuer,
                                                  audience='http://audience/')
    doc = ResolverSerializer.get_valid_doc_from_token(token, get_controller_doc=raise_if_called)
    assert doc.to_dict() == simple_doc.to_dict()


def test_can_get_valid_doc_from_token_using_delegation(doc_with_doc_deleg, valid_private_key, valid_issuer):
    doc, deleg_doc = doc_with_doc_deleg
    token = ResolverSerializer.serialize_to_token(doc, valid_private_key, valid_issuer, audience='http://audience/')
    doc = ResolverSerializer.get_valid_doc_from_token(token, get_controller_doc=lambda x: deleg_doc)
    assert doc.to_dict() == doc.to_dict()


def get_inconsistent_token(issuer: str, doc_data, private_key):
    data = {'aud': 'http://audience/', 'doc': doc_data}
    if issuer:
        data['iss'] = issuer
    return jwt.encode(data, private_key, algorithm=TOKEN_ALGORITHM)


def test_get_valid_doc_from_token_raises_resolver_error_if_not_a_token():
    with pytest.raises(IdentityResolverError) as err_wrapper:
        ResolverSerializer.get_valid_doc_from_token('not a token', get_controller_doc=raise_if_called)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_get_valid_doc_from_token_raises_resolver_error_if_invalid_token_format(simple_doc, valid_private_key):
    token_without_issuer = get_inconsistent_token(issuer=None, doc_data=simple_doc.to_dict(),
                                                  private_key=valid_private_key)
    with pytest.raises(IdentityResolverError) as err_wrapper:
        ResolverSerializer.get_valid_doc_from_token(token_without_issuer, get_controller_doc=raise_if_called)
    assert isinstance(err_wrapper.value.__cause__, KeyError)


def test_get_valid_doc_from_token_raises_resolver_error_if_invalid_doc_format(valid_private_key, valid_issuer):
    token_with_invalid_doc_format = get_inconsistent_token(str(valid_issuer), doc_data={'plop': 'not a doc'},
                                                           private_key=valid_private_key)
    with pytest.raises(IdentityResolverError) as err_wrapper:
        ResolverSerializer.get_valid_doc_from_token(token_with_invalid_doc_format, get_controller_doc=raise_if_called)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_get_valid_doc_from_token_raises_resolver_error_if_invalid_doc_data(simple_doc, valid_private_key,
                                                                            valid_issuer):
    invalid_doc_data = simple_doc.to_dict()
    invalid_doc_data['id'] = 'InvalidDID'
    token_with_invalid_doc_did = get_inconsistent_token(str(valid_issuer), doc_data=invalid_doc_data,
                                                        private_key=valid_private_key)
    with pytest.raises(IdentityResolverError) as err_wrapper:
        ResolverSerializer.get_valid_doc_from_token(token_with_invalid_doc_did, get_controller_doc=raise_if_called)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_get_valid_doc_from_token_raises_resolver_error_if_invalid_issuer(simple_doc, valid_private_key):
    token_with_invalid_doc_did = get_inconsistent_token('invalid_issuer', doc_data=simple_doc.to_dict(),
                                                        private_key=valid_private_key)
    with pytest.raises(IdentityResolverError) as err_wrapper:
        ResolverSerializer.get_valid_doc_from_token(token_with_invalid_doc_did, get_controller_doc=raise_if_called)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_get_valid_doc_from_token_raises_invalid_issuer_if_can_not_find_issuer(simple_doc, valid_private_key):
    not_in_doc_issuer = Issuer.build(simple_doc.did, '#NotInDoc')
    token = get_inconsistent_token(str(not_in_doc_issuer), simple_doc.to_dict(), valid_private_key)
    with pytest.raises(IdentityResolverError) as err_wrapper:
        ResolverSerializer.get_valid_doc_from_token(token, get_controller_doc=raise_if_called)
    assert isinstance(err_wrapper.value.__cause__, IdentityInvalidRegisterIssuerError)


def test_get_valid_doc_from_token_raises_resolver_error_if_corrupted_token(simple_doc, valid_issuer, other_private_key):
    private_key_not_associated_to_doc = other_private_key
    token = ResolverSerializer.serialize_to_token(simple_doc, private_key_not_associated_to_doc, valid_issuer,
                                                  audience='http://audience/')
    with pytest.raises(IdentityResolverError) as err_wrapper:
        ResolverSerializer.get_valid_doc_from_token(token, get_controller_doc=raise_if_called)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_can_get_token_from_resolver(requests_mock, doc_did):
    a_token = 'the value doesn\'t matter here'
    requests_mock.get(
        f'/1.0/discover/{doc_did}', json={'token': a_token}
    )
    requester = RESTResolverRequester(address='http://ploptest')
    token = requester.get_token(doc_did)
    assert token == a_token


def test_get_token_from_resolver_raises_resolver_error_if_inconsistent_response(requests_mock, doc_did):
    requests_mock.get(
        f'/1.0/discover/{doc_did}', json={'plop': 12}
    )
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverError):
        requester.get_token(doc_did)


def test_get_token_from_resolver_raises_resolver_error_if_http_error(requests_mock, doc_did):
    requests_mock.get(
        f'/1.0/discover/{doc_did}', json={}, status_code=400,
    )
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverError) as err_wrapper:
        requester.get_token(doc_did)
    assert isinstance(err_wrapper.value.__cause__, HTTPError)


def test_get_token_from_resolver_raises_not_found_error_if_http_not_found(requests_mock, doc_did):
    requests_mock.get(
        f'/1.0/discover/{doc_did}', json={}, status_code=404,
    )
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverDocNotFoundError) as err_wrapper:
        requester.get_token(doc_did)
    assert isinstance(err_wrapper.value.__cause__, HTTPError)


def test_get_token_from_resolver_raises_timeout_error_if_connection_timeout(requests_mock, doc_did):
    requests_mock.get(url=f'/1.0/discover/{doc_did}', exc=ConnectTimeout)
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverTimeoutError) as err_wrapper:
        requester.get_token(doc_did)
    assert isinstance(err_wrapper.value.__cause__, ConnectTimeout)


def test_get_token_from_resolver_raises_resolver_error_if_request_error(requests_mock, doc_did):
    requests_mock.get(url=f'/1.0/discover/{doc_did}', exc=RequestException)
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverError) as err_wrapper:
        requester.get_token(doc_did)
    assert isinstance(err_wrapper.value.__cause__, RequestException)


def test_can_register_token_to_resolver(requests_mock):
    a_token = 'the value doesn\'t matter here'

    requests_mock.post('/1.0/register', headers={'Content-type': 'text/plain'}, )
    requester = RESTResolverRequester(address='http://ploptest')
    requester.register_token(a_token)

    assert requests_mock.request_history[0].body == a_token


def test_register_token_to_resolver_raises_resolver_error_if_http_error(requests_mock):
    requests_mock.post(
        '/1.0/register', headers={'Content-type': 'text/plain'}, json={}, status_code=400,
    )
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverError) as err_wrapper:
        requester.register_token('a token')
    assert isinstance(err_wrapper.value.__cause__, HTTPError)


def test_register_token_to_resolver_raises_timeout_error_if_connection_timeout(requests_mock):
    requests_mock.post(url='/1.0/register', exc=ConnectTimeout)
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverTimeoutError) as err_wrapper:
        requester.register_token('a token')
    assert isinstance(err_wrapper.value.__cause__, ConnectTimeout)


def test_register_token_to_resolver_raises_resolver_error_if_request_error(requests_mock):
    requests_mock.post(url='/1.0/register', exc=RequestException)
    requester = RESTResolverRequester(address='http://ploptest')
    with pytest.raises(IdentityResolverError) as err_wrapper:
        requester.register_token('a token')
    assert isinstance(err_wrapper.value.__cause__, RequestException)
