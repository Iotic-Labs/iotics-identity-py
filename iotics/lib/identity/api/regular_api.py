# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from typing import Optional, Union

from iotics.lib.identity.api.advanced_api import AdvancedIdentityLocalApi, AdvancedIdentityRegisterApi
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import build_agent_secrets, build_twin_secrets, build_user_secrets, \
    KeyPairSecrets, KeyPairSecretsHelper, SeedMethod
from iotics.lib.identity.crypto.keys import KeyPair
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.key_pair import RegisteredIdentity
from iotics.lib.identity.register.rest_resolver import get_rest_resolver_client


class IdentityApi:
    def __init__(self, advanced_api: AdvancedIdentityRegisterApi):
        self.advanced_api = advanced_api

    def create_user_identity(self, user_seed: bytes, user_key_name: str, user_name: str,
                             seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                             password: str = '', override_doc: bool = False) -> RegisteredIdentity:
        """
        Create and register a user identity.
        :param user_seed: user seed (secrets)
        :param user_key_name: user key name (secrets)
        :param password: Optional user password (secrets)
        :param user_name: Optional user name (default #user-0) following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :param override_doc: override registered identity document if already exist (default False)
        :return: user registered identity

        :raises:
            IdentityValidationError: if invalid secrets or name
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        key_pair_secrets = build_user_secrets(user_seed, user_key_name, seed_method, password)
        return self.advanced_api.new_registered_user_identity(key_pair_secrets, user_name, override_doc)

    def create_agent_identity(self, agent_seed: bytes, agent_key_name: str, agent_name: str,
                              seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                              password: str = '', override_doc: bool = False) -> RegisteredIdentity:
        """
        Create and register a agent identity.
        :param agent_seed: agent seed (secrets)
        :param agent_key_name: agent key name (secrets)
        :param password: Optional agent password (secrets)
        :param agent_name: Optional agent name (default #agent-0) following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :param override_doc: override registered identity document if already exist (default False)
        :return: agent registered identity

        :raises:
            IdentityValidationError: if invalid secrets or name
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        key_pair_secrets = build_agent_secrets(agent_seed, agent_key_name, seed_method, password)
        return self.advanced_api.new_registered_agent_identity(key_pair_secrets, agent_name, override_doc)

    def create_twin_identity(self, twin_seed: bytes, twin_key_name: str, twin_name: str,
                             seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                             password: str = '', override_doc: bool = False) -> RegisteredIdentity:
        """
        Create and register a twin identity.
        :param twin_seed: twin seed (secrets)
        :param twin_key_name: twin key name (secrets)
        :param password: Optional twin password (secrets)
        :param twin_name: Optional twin name (default #twin-0) following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :param override_doc: override registered identity document if already exist (default False)
        :return: twin registered identity

        :raises:
            IdentityValidationError: if invalid secrets or name
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        key_pair_secrets = build_twin_secrets(twin_seed, twin_key_name, seed_method, password)
        return self.advanced_api.new_registered_twin_identity(key_pair_secrets, twin_name, override_doc)

    @staticmethod
    def _get_identity(key_pair_secrets: KeyPairSecrets, did: str, name: str) -> RegisteredIdentity:
        return RegisteredIdentity(key_pair_secrets=key_pair_secrets,
                                  issuer=Issuer.build(did, name))

    def get_user_identity(self, key_seed: bytes, key_name: str, user_did: str, user_name: str,
                          seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                          password: str = '') -> RegisteredIdentity:
        """
        Get user registered identity from secrets.
        :param key_seed: user secrets
        :param key_name: user key name
        :param user_did: user decentralised identifier
        :param user_name: user name
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :param password: Optional user password (secrets)
        :return: user registered identity

        :raises:
            IdentityValidationError: if invalid user name
        """
        key_pair_secrets = build_user_secrets(key_seed, key_name, seed_method, password)
        return self._get_identity(key_pair_secrets, user_did, user_name)

    def get_agent_identity(self, key_seed: bytes, key_name: str, agent_did: str, agent_name: str,
                           seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                           password: str = '') -> RegisteredIdentity:
        """
        Get agent registered identity from secrets.
        :param key_seed: agent secrets
        :param key_name: agent key name
        :param agent_did: agent decentralised identifier
        :param agent_name: agent name
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :param password: Optional agent password (secrets)
        :return: agent registered identity

        :raises:
            IdentityValidationError: if invalid agent name
        """
        key_pair_secrets = build_agent_secrets(key_seed, key_name, seed_method, password)
        return self._get_identity(key_pair_secrets, agent_did, agent_name)

    def get_twin_identity(self, key_seed: bytes, key_name: str, twin_did: str, twin_name: str,
                          seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                          password: str = '') -> RegisteredIdentity:
        """
        Get twin registered identity from secrets.
        :param key_seed: twin secrets
        :param key_name: twin key name
        :param twin_did: twin decentralised identifier
        :param twin_name: twin name
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :param password: Optional twin password (secrets)
        :return: twin registered identity

        :raises:
            IdentityValidationError: if invalid twin name
        """
        key_pair_secrets = build_twin_secrets(key_seed, key_name, seed_method, password)
        return self._get_identity(key_pair_secrets, twin_did, twin_name)

    def user_delegates_authentication_to_agent(self, user_registered_identity: RegisteredIdentity,
                                               agent_registered_identity: RegisteredIdentity,
                                               delegation_name: str):
        """
        User delegates authentication to agent.
        The agent can authenticate on behalf of the user.
        :param user_registered_identity: user registered identity
        :param agent_registered_identity: agent registered identity
        :param delegation_name: register authentication delegation proof name

        :raises:
            IdentityValidationError: if registered identities
            IdentityRegisterDocumentKeyConflictError: if authentication delegation proof name is not unique within
                                                      the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
            IdentityDependencyError: if incompatible library dependency
        """
        self.advanced_api.delegate_authentication(user_registered_identity.key_pair_secrets,
                                                  user_registered_identity.issuer.did,
                                                  agent_registered_identity.key_pair_secrets,
                                                  agent_registered_identity.issuer.did,
                                                  delegation_name)

    def twin_delegates_control_to_agent(self, twin_registered_identity: RegisteredIdentity,
                                        agent_registered_identity: RegisteredIdentity,
                                        delegation_name: str):
        """
        Twin delegates control to the agent. The agent can control the twin.
        :param twin_registered_identity: twin registered identity
        :param agent_registered_identity: agent registered identity
        :param delegation_name: register authentication delegation proof name

        :raises:
           IdentityValidationError: if registered identities
           IdentityRegisterDocumentKeyConflictError: if control delegation proof name is not unique within
                                                     the register document
           IdentityInvalidDocumentError: if invalid register document
           IdentityResolverError: if resolver error
           IdentityDependencyError: if incompatible library dependency
       """
        self.advanced_api.delegate_control(twin_registered_identity.key_pair_secrets,
                                           twin_registered_identity.issuer.did,
                                           agent_registered_identity.key_pair_secrets,
                                           agent_registered_identity.issuer.did,
                                           delegation_name)

    def set_document_controller(self, identity: RegisteredIdentity,
                                controller: Issuer):
        """
        Set controller issuer to the register document associated to the provided registered identity.
        :param identity: registered identity
        :param controller: register document controller issuer

        :raises:
            IdentityValidationError: if invalid registered identity
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        key_pair = KeyPairSecretsHelper.get_key_pair(identity.key_pair_secrets)
        self.advanced_api.set_document_controller(key_pair,
                                                  identity.issuer,
                                                  controller)

    def set_document_creator(self, identity: RegisteredIdentity,
                             creator: str):
        """
        Set creator to the register document associated to the provided registered identity.
        :param identity: registered identity
        :param creator: register document creator decentralised identifier

        :raises:
            IdentityValidationError: if invalid registered identity
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        key_pair = KeyPairSecretsHelper.get_key_pair(identity.key_pair_secrets)
        self.advanced_api.set_document_creator(key_pair,
                                               identity.issuer,
                                               creator)

    def set_document_revoked(self, identity: RegisteredIdentity,
                             revoked: bool):
        """
        Set register document associated to the provided registered identity revoke field.
        :param identity: registered identity
        :param revoked:  is register document revoked

        :raises:
            IdentityValidationError: if invalid registered identity
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        key_pair = KeyPairSecretsHelper.get_key_pair(identity.key_pair_secrets)
        self.advanced_api.set_document_revoked(key_pair,
                                               identity.issuer,
                                               revoked)

    def get_register_document(self, doc_did: str) -> RegisterDocument:
        """
        Get a register document from the resolver.
        :param doc_did: register document decentralised identifier
        :return: associated register document

        :raises:
            IdentityResolverError: if invalid resolver response
            IdentityResolverDocNotFoundError: if document not found
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error
        """
        return self.advanced_api.get_register_document(doc_did)

    def validate_register_document(self, doc: RegisterDocument) -> RegisterDocument:
        """
        Validate a register document against the resolver.
        :param doc: register document

        :raises:
            IdentityInvalidDocumentDelegationError: if one of the register document delegation proof is invalid
        """
        return self.advanced_api.validate_register_document(doc)

    @staticmethod
    def validate_document_proof(doc: RegisterDocument) -> RegisterDocument:
        """
        Verify a register document proof.
        :param doc: register document

        :raises:
            IdentityInvalidDocumentError: if register document proof is invalid
        """
        return AdvancedIdentityLocalApi.validate_document_proof(doc)

    @staticmethod
    def create_agent_auth_token(agent_registered_identity: RegisteredIdentity,
                                user_did: str, duration: int, audience: str = 'default') -> str:
        """
        Create an agent authentication token.
        :param agent_registered_identity: agent registered identity
        :param user_did: user register document decentralised identifier
        :param duration: token duration in seconds
        :param audience: Optional token audience
        :return: encoded jwt token

        :raises:
            IdentityValidationError: if invalid agent registered identity
            IdentityValidationError: if invalid token data
            IdentityDependencyError: if incompatible library dependency
        """
        agent_key_pair = KeyPairSecretsHelper.get_key_pair(agent_registered_identity.key_pair_secrets)
        return AdvancedIdentityLocalApi.create_agent_auth_token(agent_key_pair,
                                                                agent_registered_identity.issuer,
                                                                user_did,
                                                                duration,
                                                                audience)

    @staticmethod
    def get_key_pair_from_user(user_seed: bytes, user_key_name: str,
                               seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                               password: str = '') -> KeyPair:
        """
        Get key pair from user secrets
        :param user_seed: user seed (secrets)
        :param user_key_name: user key name (secrets)
        :param password: Optional user password (secrets)
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :return: user key pair

        :raises:
                IdentityValidationError: if invalid user key seed
                IdentityValidationError: if invalid user key name
        """
        key_pair_secrets = build_user_secrets(user_seed, user_key_name, seed_method, password)
        return KeyPairSecretsHelper.get_key_pair(key_pair_secrets)

    @staticmethod
    def get_key_pair_from_agent(agent_seed: bytes, agent_key_name: str,
                                seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                                password: str = '') -> KeyPair:
        """
        Get key pair from agent secrets
        :param agent_seed: agent seed (secrets)
        :param agent_key_name: agent key name (secrets)
        :param password: Optional agent password (secrets)
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :return: agent key pair

        :raises:
                IdentityValidationError: if invalid agent key seed
                IdentityValidationError: if invalid agent key name
        """
        key_pair_secrets = build_agent_secrets(agent_seed, agent_key_name, seed_method, password)
        return KeyPairSecretsHelper.get_key_pair(key_pair_secrets)

    @staticmethod
    def get_key_pair_from_twin(twin_seed: bytes, twin_key_name: str,
                               seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39,
                               password: str = '') -> KeyPair:
        """
        Get key pair from twin secrets
        :param twin_seed: twin seed (secrets)
        :param twin_key_name: twin key name (secrets)
        :param password: Optional twin password (secrets)
        :param seed_method: seed method (SEED_METHOD_NONE or SEED_METHOD_BIP39) default=SEED_METHOD_BIP39
        :return: twin key pair

        :raises:
                IdentityValidationError: if invalid twin key seed
                IdentityValidationError: if invalid twin key name
        """
        key_pair_secrets = build_twin_secrets(twin_seed, twin_key_name, seed_method, password)
        return KeyPairSecretsHelper.get_key_pair(key_pair_secrets)

    def add_new_owner(self, new_owner_name: str, new_owner_public_key_base58: str,
                      doc_registered_identity: RegisteredIdentity) -> Issuer:
        """
        Add new register document owner.
        :param new_owner_name: new owner name
        :param new_owner_public_key_base58: new owner public base 58 key
        :param doc_registered_identity: doc owner registered identity
        :return: new register document owner issuer

        :raises:
            IdentityValidationError: if invalid new owner name
            IdentityValidationError: if invalid doc owner registered identity
            IdentityRegisterDocumentKeyConflictError: if new owner name is not unique within the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        key_pair = KeyPairSecretsHelper.get_key_pair(doc_registered_identity.key_pair_secrets)
        return self.advanced_api.add_public_key_to_document(new_owner_name, new_owner_public_key_base58,
                                                            key_pair, doc_registered_identity.issuer)

    def remove_ownership(self, removed_owner_issuer: Issuer,
                         existing_owner_registered_identity: RegisteredIdentity):
        """
        Remove owner from a register document.
        :param removed_owner_issuer: register document owner issuer to remove
        :param existing_owner_registered_identity: other existing doc owner registered identity
        :return: removed register document owner issuer

        :raises:
            IdentityValidationError: if invalid owner
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        existing_owner_key_pair = KeyPairSecretsHelper.get_key_pair(existing_owner_registered_identity.key_pair_secrets)
        return self.advanced_api.remove_public_key_from_document(removed_owner_issuer,
                                                                 existing_owner_key_pair,
                                                                 existing_owner_registered_identity.issuer)

    @staticmethod
    def create_seed(length: Optional[int] = 256) -> bytes:
        """
        Create a new seed (secrets).
        :param length: seed length
        :return: seed

        :raises:
            IdentityValidationError: if invalid seed length
        """
        return AdvancedIdentityLocalApi.create_seed(length)


def get_rest_identity_api(resolver_url, timeout: Optional[Union[int, float]] = None) -> IdentityApi:
    """
    Get a REST identity api.
    :param resolver_url: resolver url
    :param timeout: optional timeout seconds. Default=60s. If set to 0, requests will have no timeout.
    :return: identity api
    """
    resolver_client = get_rest_resolver_client(resolver_url, timeout)
    return IdentityApi(AdvancedIdentityRegisterApi(resolver_client))
