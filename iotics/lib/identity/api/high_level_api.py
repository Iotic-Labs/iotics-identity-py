# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from typing import Optional, Tuple, Union

from iotics.lib.identity.api.advanced_api import AdvancedIdentityLocalApi, AdvancedIdentityRegisterApi
from iotics.lib.identity.crypto.key_pair_secrets import build_agent_secrets, build_twin_secrets, build_user_secrets, \
    KeyPairSecretsHelper, SeedMethod
from iotics.lib.identity.register.key_pair import RegisteredIdentity
from iotics.lib.identity.register.rest_resolver import get_rest_resolver_client


class HighLevelIdentityApi:
    def __init__(self, advanced_api: AdvancedIdentityRegisterApi):
        self.advanced_api = advanced_api

    def create_user_and_agent_with_auth_delegation(self, user_seed: bytes, user_key_name: str,
                                                   agent_seed: bytes, agent_key_name: str,
                                                   delegation_name: str,
                                                   user_name: str = None, agent_name: str = None,
                                                   user_password: str = '', agent_password: str = '',
                                                   override_docs: bool = False, ) -> Tuple[RegisteredIdentity,
                                                                                           RegisteredIdentity]:
        """
        Create and register a user and an agent identities with user delegating authentication to the agent.
        The agent can authenticate on behalf of the user.
        :param user_seed: user seed (secrets)
        :param user_key_name: user key name (secrets)
        :param user_password: Optional user password (secrets)
        :param user_name: Optional user name (default #user-0) following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param agent_seed: agent seed (secrets)
        :param agent_key_name: agent key name (secrets)
        :param agent_password: Optional agent password (secrets)
        :param agent_name: Optional agent name (default #agent-0) following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param delegation_name: user/agent authentication delegation name
        :param override_docs: override registered identity documents if already exist (default False)
        :return: user registered identity, agent registered identity

        :raises:
            IdentityValidationError: if invalid secrets or names
            IdentityValidationError: if invalid names
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        user_key_pair_secrets = build_user_secrets(user_seed, user_key_name, SeedMethod.SEED_METHOD_BIP39,
                                                   user_password)
        user_registered_identity = self.advanced_api.new_registered_user_identity(user_key_pair_secrets, user_name,
                                                                                  override_docs)
        agent_key_pair_secrets = build_agent_secrets(agent_seed, agent_key_name, SeedMethod.SEED_METHOD_BIP39,
                                                     agent_password)
        agent_registered_identity = self.advanced_api.new_registered_agent_identity(agent_key_pair_secrets,
                                                                                    agent_name,
                                                                                    override_docs)
        self.advanced_api.delegate_authentication(user_registered_identity.key_pair_secrets,
                                                  user_registered_identity.issuer.did,
                                                  agent_registered_identity.key_pair_secrets,
                                                  agent_registered_identity.issuer.did,
                                                  delegation_name)
        return user_registered_identity, agent_registered_identity

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
            IdentityValidationError: if invalid agent identity
            IdentityValidationError: if invalid token data
            IdentityDependencyError: if incompatible library dependency
        """
        agent_key_pair = KeyPairSecretsHelper.get_key_pair(agent_registered_identity.key_pair_secrets)
        return AdvancedIdentityLocalApi.create_agent_auth_token(agent_key_pair,
                                                                agent_registered_identity.issuer,
                                                                user_did,
                                                                duration,
                                                                audience)

    def create_twin(self, twin_seed: bytes, twin_key_name: str, twin_name: str = None,
                    password: str = '', override_doc: bool = False) -> RegisteredIdentity:
        """
        Create and register a twin identity.
        :param twin_seed: twin seed (secrets)
        :param twin_key_name: twin key name (secrets)
        :param password: Optional twin password (secrets)
        :param twin_name: Optional twin name (default #twin-0) following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param override_doc: override registered identity document if already exist (default False)
        :return: twin registered identity

        :raises:
            IdentityValidationError: if invalid secrets or name
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        key_pair_secrets = build_twin_secrets(twin_seed, twin_key_name, SeedMethod.SEED_METHOD_BIP39, password)
        return self.advanced_api.new_registered_twin_identity(key_pair_secrets, twin_name, override_doc)

    def create_twin_with_control_delegation(self, twin_seed: bytes, twin_key_name: str,
                                            agent_registered_identity: RegisteredIdentity,
                                            delegation_name: str,
                                            twin_name: str = None,
                                            password: str = '',
                                            override_doc: bool = False) -> RegisteredIdentity:
        """
        Create and register a twin identity with twin delegating control to the agent.
        The agent can control the twin.
        :param twin_seed: twin seed (secrets)
        :param twin_key_name: twin key name (secrets)
        :param password: Optional twin password (secrets)
        :param twin_name: Optional twin name (default #twin-0) following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param override_doc: override registered identity document if already exist (default False)
        :return: twin registered identity

        :raises:
            IdentityValidationError: if invalid secret or name
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        twin_registered_identity = self.create_twin(twin_seed, twin_key_name, twin_name, password, override_doc)
        self.advanced_api.delegate_control(twin_registered_identity.key_pair_secrets,
                                           twin_registered_identity.issuer.did,
                                           agent_registered_identity.key_pair_secrets,
                                           agent_registered_identity.issuer.did,
                                           delegation_name)

        return twin_registered_identity

    def get_ownership_of_twin_from_registered_identity(self, twin_registered_identity: RegisteredIdentity,
                                                       new_owner_registered_identity: RegisteredIdentity,
                                                       new_owner_key_name: str):
        """
        Get Ownership of a twin using a registered identity you owned.
        :param twin_registered_identity: twin registered identity
        :param new_owner_registered_identity: new owner registered identity
        :param new_owner_key_name: new owner key name

        :raises:
            IdentityValidationError: if invalid registered identities or name
            IdentityRegisterDocumentKeyConflictError: if new owner key name is not unique within the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        new_owner_key_pair = KeyPairSecretsHelper.get_key_pair(new_owner_registered_identity.key_pair_secrets)
        current_owner_key_pair = KeyPairSecretsHelper.get_key_pair(twin_registered_identity.key_pair_secrets)
        self.advanced_api.add_public_key_to_document(new_owner_key_name, new_owner_key_pair.public_base58,
                                                     current_owner_key_pair, twin_registered_identity.issuer)

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


def get_rest_high_level_identity_api(resolver_url, timeout: Optional[Union[int, float]] = None) -> HighLevelIdentityApi:
    """
    Get a REST high level identity api.
    :param resolver_url: resolver url
    :param timeout: optional timeout seconds. Default=60s. If set to 0, requests will have no timeout.
    :return: high level identity api
    """
    resolver_client = get_rest_resolver_client(resolver_url, timeout)
    return HighLevelIdentityApi(AdvancedIdentityRegisterApi(resolver_client))
