# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import jwt
import pytest

from iotics.lib.identity.const import TOKEN_ALGORITHM
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.error import IdentityAuthenticationFailed, IdentityInvalidRegisterIssuerError, \
    IdentityNotAllowed, IdentityResolverError, IdentityValidationError
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.keys import RegisterDelegationProof, RegisterPublicKey
from iotics.lib.identity.validation.authentication import IdentityAuthValidation
from tests.unit.iotics.lib.identity.fake import ResolverClientTest
from tests.unit.iotics.lib.identity.validation.helper import get_valid_document, \
    get_valid_document_from_secret, is_validator_run_success, new_seed


@pytest.fixture
def delegating_secrets(valid_key_pair_secrets):
    return valid_key_pair_secrets


@pytest.fixture
def allowed_issuer_secrets(other_key_pair_secrets):
    return other_key_pair_secrets


@pytest.fixture
def delegating_issuer_name():
    return '#DelegatingIssuer'


@pytest.fixture
def allowed_issuer_name():
    return '#AllowedIsssuer'


@pytest.fixture
def allowed_issuer_doc(allowed_issuer_name, allowed_issuer_secrets):
    return get_valid_document_from_secret(allowed_issuer_secrets, allowed_issuer_name)


@pytest.fixture
def allowed_issuer(allowed_issuer_doc, allowed_issuer_name):
    return Issuer.build(allowed_issuer_doc.did, allowed_issuer_name)


@pytest.fixture
def doc_delegating_control(delegating_issuer_name, delegating_secrets, allowed_issuer_secrets, allowed_issuer):
    doc = get_valid_document_from_secret(delegating_secrets, delegating_issuer_name)
    delegating_issuer = Issuer.build(doc.did, delegating_issuer_name)
    proof = Proof.build(allowed_issuer_secrets, allowed_issuer, content=delegating_issuer.did.encode())
    return RegisterDocumentBuilder() \
        .add_control_delegation_obj(RegisterDelegationProof.build('#ADeleg',
                                                                  controller=allowed_issuer,
                                                                  proof=proof.signature)) \
        .build_from_existing(doc)


@pytest.fixture
def doc_delegating_authentication(delegating_issuer_name, delegating_secrets, allowed_issuer_secrets, allowed_issuer):
    doc = get_valid_document_from_secret(delegating_secrets, delegating_issuer_name)
    delegating_issuer = Issuer.build(doc.did, delegating_issuer_name)
    proof = Proof.build(allowed_issuer_secrets, allowed_issuer, content=delegating_issuer.did.encode())
    return RegisterDocumentBuilder() \
        .add_authentication_delegation_obj(RegisterDelegationProof.build('#ADeleg',
                                                                         controller=allowed_issuer,
                                                                         proof=proof.signature)) \
        .build_from_existing(doc)


@pytest.fixture
def not_allowed_issuer(allowed_issuer_doc):
    return Issuer.build(allowed_issuer_doc.did, '#NotAllowed')


def test_validate_allowed_for_control_raises_not_allowed_if_not_allowed_for_control(not_allowed_issuer,
                                                                                    doc_delegating_control,
                                                                                    allowed_issuer_doc):
    resolver_client = ResolverClientTest(docs={doc_delegating_control.did: doc_delegating_control,
                                               allowed_issuer_doc.did: allowed_issuer_doc})
    with pytest.raises(IdentityNotAllowed):
        is_validator_run_success(IdentityAuthValidation.validate_allowed_for_control,
                                 resolver_client,
                                 issuer=not_allowed_issuer,
                                 subject_id=doc_delegating_control.did)


def test_validate_allowed_for_control_raises_not_allowed_if_not_allowed_for_auth(not_allowed_issuer,
                                                                                 doc_delegating_authentication,
                                                                                 allowed_issuer_doc):
    resolver_client = ResolverClientTest(docs={doc_delegating_authentication.did: doc_delegating_authentication,
                                               allowed_issuer_doc.did: allowed_issuer_doc})
    with pytest.raises(IdentityNotAllowed):
        is_validator_run_success(IdentityAuthValidation.validate_allowed_for_auth,
                                 resolver_client,
                                 issuer=not_allowed_issuer,
                                 subject_id=doc_delegating_authentication.did)


def test_can_validate_allowed_for_control_on_owned_doc(allowed_issuer, allowed_issuer_doc):
    resolver_client = ResolverClientTest(docs={allowed_issuer_doc.did: allowed_issuer_doc})
    assert is_validator_run_success(IdentityAuthValidation.validate_allowed_for_control,
                                    resolver_client,
                                    issuer=allowed_issuer,
                                    subject_id=allowed_issuer_doc.did)


def test_can_validate_allowed_for_authentication_on_owned_doc(allowed_issuer, allowed_issuer_doc):
    resolver_client = ResolverClientTest(docs={allowed_issuer_doc.did: allowed_issuer_doc})
    assert is_validator_run_success(IdentityAuthValidation.validate_allowed_for_auth,
                                    resolver_client,
                                    issuer=allowed_issuer,
                                    subject_id=allowed_issuer_doc.did)


def test_can_validate_allowed_for_control_with_allowed_by_control_delegation(allowed_issuer,
                                                                             doc_delegating_control,
                                                                             allowed_issuer_doc):
    resolver_client = ResolverClientTest(docs={doc_delegating_control.did: doc_delegating_control,
                                               allowed_issuer_doc.did: allowed_issuer_doc})
    assert is_validator_run_success(IdentityAuthValidation.validate_allowed_for_control,
                                    resolver_client, allowed_issuer,
                                    subject_id=doc_delegating_control.did)


def test_can_validate_allowed_for_control_with_allowed_by_auth_delegation(allowed_issuer,
                                                                          doc_delegating_authentication,
                                                                          allowed_issuer_doc):
    resolver_client = ResolverClientTest(docs={doc_delegating_authentication.did: doc_delegating_authentication,
                                               allowed_issuer_doc.did: allowed_issuer_doc})
    assert is_validator_run_success(IdentityAuthValidation.validate_allowed_for_auth,
                                    resolver_client, allowed_issuer,
                                    subject_id=doc_delegating_authentication.did)


def test_can_validate_allowed_for_control_with_controller_doc(allowed_issuer,
                                                              allowed_issuer_doc):
    controller_issuer_doc = allowed_issuer_doc
    controller_issuer = Issuer.build(controller_issuer_doc.did, '#Plop')
    a_doc_with_controller_allowed_for_ctrl = get_valid_document(new_seed(), '#ASubject',
                                                                controller=controller_issuer)
    resolver_docs = {controller_issuer.did: controller_issuer_doc,
                     a_doc_with_controller_allowed_for_ctrl.did: a_doc_with_controller_allowed_for_ctrl}
    resolver_client = ResolverClientTest(docs=resolver_docs)

    assert is_validator_run_success(IdentityAuthValidation.validate_allowed_for_control,
                                    resolver_client, allowed_issuer,
                                    subject_id=a_doc_with_controller_allowed_for_ctrl.did)


def test_can_validate_allowed_for_auth_with_controller_doc(allowed_issuer,
                                                           allowed_issuer_doc):
    controller_issuer_doc = allowed_issuer_doc
    controller_issuer = Issuer.build(controller_issuer_doc.did, '#Plop')
    a_doc_with_controller_allowed_for_auth = get_valid_document(new_seed(), '#ASubject',
                                                                controller=controller_issuer)
    resolver_docs = {controller_issuer.did: controller_issuer_doc,
                     a_doc_with_controller_allowed_for_auth.did: a_doc_with_controller_allowed_for_auth}
    resolver_client = ResolverClientTest(docs=resolver_docs)

    assert is_validator_run_success(IdentityAuthValidation.validate_allowed_for_auth,
                                    resolver_client, allowed_issuer,
                                    subject_id=a_doc_with_controller_allowed_for_auth.did)


def test_validate_allowed_for_control_raises_not_allowed_if_resolver_error(allowed_issuer,
                                                                           allowed_issuer_doc):
    # Initialised without the docs so a not found will be raised
    resolver_client = ResolverClientTest(docs={})
    with pytest.raises(IdentityNotAllowed) as err_wrapper:
        is_validator_run_success(IdentityAuthValidation.validate_allowed_for_control,
                                 resolver_client,
                                 issuer=allowed_issuer,
                                 subject_id=allowed_issuer_doc.did)
    assert isinstance(err_wrapper.value.__cause__, IdentityResolverError)


def test_validate_allowed_for_auth_raises_not_allowed_if_resolver_error(allowed_issuer,
                                                                        allowed_issuer_doc):
    # Initialised without the docs so a not found will be raised
    resolver_client = ResolverClientTest(docs={})
    with pytest.raises(IdentityNotAllowed) as err_wrapper:
        is_validator_run_success(IdentityAuthValidation.validate_allowed_for_auth,
                                 resolver_client, issuer=allowed_issuer,
                                 subject_id=allowed_issuer_doc.did)
    assert isinstance(err_wrapper.value.__cause__, IdentityResolverError)


@pytest.fixture
def authentication_subject_doc(other_key_pair_secrets, valid_key_pair, allowed_issuer_name):
    return RegisterDocumentBuilder() \
        .add_public_key_obj(RegisterPublicKey(allowed_issuer_name, valid_key_pair.public_base58, revoked=False)) \
        .build_from_existing(get_valid_document_from_secret(other_key_pair_secrets, '#Adoc'))


@pytest.fixture
def valid_auth_token(allowed_issuer, valid_private_key, authentication_subject_doc):
    return JwtTokenHelper.create_auth_token(iss=str(allowed_issuer),
                                            sub=authentication_subject_doc.did,
                                            aud='http://audience/',
                                            duration=360,
                                            private_key=valid_private_key)


def test_can_verify_authentication(allowed_issuer, valid_auth_token, authentication_subject_doc):
    resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
    claim = IdentityAuthValidation.verify_authentication(resolver_client, valid_auth_token)
    assert claim['iss'] == str(allowed_issuer)
    assert claim['aud'] == 'http://audience/'
    assert claim['sub'] == authentication_subject_doc.did
    assert claim['iat']
    assert claim['exp']


def test_verify_authentication_raises_auth_error_if_invalid_token(authentication_subject_doc):
    resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
    with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
        IdentityAuthValidation.verify_authentication(resolver_client, token='not a token')
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_verify_authentication_raises_auth_error_if_token_with_missing_data(authentication_subject_doc,
                                                                            valid_private_key):
    token_with_missing_data = jwt.encode({'plop': 'data'}, valid_private_key, algorithm=TOKEN_ALGORITHM)
    resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
    with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
        IdentityAuthValidation.verify_authentication(resolver_client, token=token_with_missing_data)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_verify_authentication_raises_auth_error_if_invalid_issuer(authentication_subject_doc,
                                                                   valid_private_key):
    token_with_invalid_iss = JwtTokenHelper.create_auth_token(iss='invalid issuer',
                                                              sub=authentication_subject_doc.did,
                                                              aud='http://audience/',
                                                              duration=360,
                                                              private_key=valid_private_key)

    resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
    with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
        IdentityAuthValidation.verify_authentication(resolver_client, token=token_with_invalid_iss)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_verify_authentication_raises_auth_error_if_resolver_error(valid_auth_token):
    # doc not provided so will raise not found
    resolver_client = ResolverClientTest(docs={})
    with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
        IdentityAuthValidation.verify_authentication(resolver_client, token=valid_auth_token)
    assert isinstance(err_wrapper.value.__cause__, IdentityResolverError)


def test_verify_authentication_raises_auth_error_if_issuer_not_in_doc_keys_or_deleg(authentication_subject_doc,
                                                                                    valid_private_key):
    not_auth_issuer = Issuer.build(authentication_subject_doc.did, '#OtherIssuer')
    token_from_not_auth_issuer = JwtTokenHelper.create_auth_token(
        iss=str(not_auth_issuer),
        sub=authentication_subject_doc.did,
        aud='http://audience/',
        duration=360,
        private_key=valid_private_key
    )
    resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
    with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
        IdentityAuthValidation.verify_authentication(resolver_client, token=token_from_not_auth_issuer)
    assert isinstance(err_wrapper.value.__cause__, IdentityInvalidRegisterIssuerError)


def test_verify_authentication_raises_auth_error_if_token_invalid_signature(authentication_subject_doc,
                                                                            allowed_issuer,
                                                                            other_private_key):
    token_signed_with_an_other_private_key = JwtTokenHelper.create_auth_token(
        iss=str(allowed_issuer),
        sub=authentication_subject_doc.did,
        aud='http://audience/',
        duration=360,
        private_key=other_private_key
    )
    resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
    with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
        IdentityAuthValidation.verify_authentication(resolver_client, token=token_signed_with_an_other_private_key)
    assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)


def test_verify_authentication_raises_auth_error_if_token_not_allowed(authentication_subject_doc,
                                                                      allowed_issuer,
                                                                      valid_private_key):
    other_doc_with_auth_or_delegation_link = get_valid_document(new_seed(), '#OtherDoc')
    token_signed_with_an_other_private_key = JwtTokenHelper.create_auth_token(
        iss=str(allowed_issuer),
        sub=other_doc_with_auth_or_delegation_link.did,
        aud='http://audience/',
        duration=360,
        private_key=valid_private_key
    )
    resolver_docs = {authentication_subject_doc.did: authentication_subject_doc,
                     other_doc_with_auth_or_delegation_link.did: other_doc_with_auth_or_delegation_link}
    resolver_client = ResolverClientTest(docs=resolver_docs)
    with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
        IdentityAuthValidation.verify_authentication(resolver_client, token=token_signed_with_an_other_private_key)
    assert isinstance(err_wrapper.value.__cause__, IdentityNotAllowed)
