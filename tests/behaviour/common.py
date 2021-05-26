from typing import Dict, Optional

import pytest

from iotics.lib.identity.api.advanced_api import AdvancedIdentityLocalApi
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.crypto.key_pair_secrets import build_agent_secrets, build_twin_secrets, build_user_secrets, \
    DIDType, KeyPairSecrets, KeyPairSecretsHelper, SeedMethod
from iotics.lib.identity.error import IdentityNotAllowed, IdentityResolverHttpDocNotFoundError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.key_pair import RegisteredIdentity
from iotics.lib.identity.register.resolver import ResolverClient
from iotics.lib.identity.register.rest_resolver import RESTResolverRequester
# Globals
from iotics.lib.identity.validation.authentication import IdentityAuthValidation


class RESTRequesterTest(RESTResolverRequester):
    def __init__(self, doc_tokens: Dict[str, str] = None):
        self.doc_tokens = doc_tokens or {}

    def get_token(self, doc_id: str) -> str:
        token = self.doc_tokens.get(doc_id.split('#')[0])
        if not token:
            raise IdentityResolverHttpDocNotFoundError(doc_id)
        return token

    def register_token(self, token: str):
        decoded_token = JwtTokenHelper.decode_token(token)
        self.doc_tokens[decoded_token['doc']['id']] = token


def get_secrets_by_type(seed: bytes, key_name: str, purpose: DIDType,
                        seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39) -> KeyPairSecrets:
    if purpose == DIDType.TWIN:
        return build_twin_secrets(seed, key_name, seed_method)
    if purpose == DIDType.AGENT:
        return build_agent_secrets(seed, key_name, seed_method)
    return build_user_secrets(seed, key_name, seed_method)


class SetupError(Exception):
    def __init__(self, msg):
        super().__init__(f'Tests setup error: {msg}')


def assert_owner_pub_key_exist(doc: RegisterDocument, owner_name: str, pub_key_base58: str):
    owner_key = doc.public_keys.get(owner_name)
    assert owner_key, f'Doc {doc.purpose} owner key {owner_name} not found in the register document'
    assert not owner_key.revoked, f'Doc {doc.purpose} owner key should not be revoked'
    assert owner_key.base58 == pub_key_base58, f'Doc {doc.purpose} invalid owner public key base58'


def assert_owner_key(doc: RegisterDocument, owner_name: str, registered_identity: RegisteredIdentity):
    key_pair = KeyPairSecretsHelper.get_key_pair(registered_identity.key_pair_secrets)
    assert_owner_pub_key_exist(doc, owner_name, key_pair.public_base58)


def get_allowed_for_control_error(resolver_client: ResolverClient, issuer: Issuer,
                                  doc_id: str) -> Optional[Exception]:
    try:
        IdentityAuthValidation.validate_allowed_for_control(resolver_client, issuer, doc_id)
    except IdentityNotAllowed as err:
        return err
    return None


def get_allowed_for_auth_error(resolver_client: ResolverClient, issuer: Issuer,
                               doc_id: str) -> Optional[Exception]:
    try:
        IdentityAuthValidation.validate_allowed_for_auth(resolver_client, issuer, doc_id)
    except IdentityNotAllowed as err:
        return err
    return None


def get_allowed_for_auth_and_control_error(resolver_client: ResolverClient, owner_issuer: Issuer,
                                           doc_id: str) -> Optional[Exception]:
    return get_allowed_for_auth_error(resolver_client, owner_issuer, doc_id) or \
        get_allowed_for_control_error(resolver_client, owner_issuer, doc_id)


def assert_owner_is_allowed(resolver_client: ResolverClient, owner_issuer: Issuer, doc_id: str):
    try:
        IdentityAuthValidation.validate_allowed_for_auth(resolver_client, owner_issuer, doc_id)
        IdentityAuthValidation.validate_allowed_for_control(resolver_client, owner_issuer, doc_id)
    except IdentityNotAllowed as err:
        assert False, f'Owner should be allowed for control and authentication on the document: {err}'


def assert_owner_not_allowed_anymore(resolver_client: ResolverClient, owner_issuer: Issuer, doc_id: str):
    with pytest.raises(IdentityNotAllowed):
        IdentityAuthValidation.validate_allowed_for_auth(resolver_client, owner_issuer, doc_id)
    with pytest.raises(IdentityNotAllowed):
        IdentityAuthValidation.validate_allowed_for_control(resolver_client, owner_issuer, doc_id)


def assert_newly_created_registered_identity(seed: bytes, key_name: str, identity_name: str, seed_method: SeedMethod,
                                             registered_identity: RegisteredIdentity, purpose: DIDType):
    expected_secrets = get_secrets_by_type(seed, key_name, purpose, seed_method)
    assert registered_identity.key_pair_secrets == expected_secrets, f'{purpose}: Invalid registered identity secrets'
    key_pair = KeyPairSecretsHelper.get_key_pair(expected_secrets)
    assert registered_identity.issuer.did == AdvancedIdentityLocalApi.create_identifier(key_pair.public_bytes), \
        f'{purpose}: Invalid registered identity issuer did'
    assert registered_identity.name == identity_name, \
        f'{purpose}: Invalid registered identity issuer name'
