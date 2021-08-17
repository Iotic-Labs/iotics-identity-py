# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import pytest

from iotics.lib.identity.error import IdentityRegisterDocumentKeyConflictError
from iotics.lib.identity import HighLevelIdentityApi, AdvancedIdentityRegisterApi
from tests.unit.iotics.lib.identity.fake import ResolverClientTest


def test_create_user_and_agent_with_auth_delegation_duplicate_name_different_controller(valid_bip39_seed):
    resolver_client = ResolverClientTest(docs={})
    api = HighLevelIdentityApi(AdvancedIdentityRegisterApi(resolver_client))

    user_name = '#user'
    agent_name = '#agent'
    agent_name2 = '#agent2'
    deleg_name = '#AuthDeleg'

    api.create_user_and_agent_with_auth_delegation(
        user_seed=valid_bip39_seed, user_key_name=user_name, user_name=user_name,
        agent_seed=valid_bip39_seed, agent_key_name=agent_name, agent_name=agent_name,
        delegation_name=deleg_name
    )

    with pytest.raises(IdentityRegisterDocumentKeyConflictError) as exc:
        api.create_user_and_agent_with_auth_delegation(
            user_seed=valid_bip39_seed, user_key_name=user_name, user_name=user_name,
            agent_seed=valid_bip39_seed, agent_key_name=agent_name2, agent_name=agent_name2,
            delegation_name=deleg_name
        )
    assert "Authentication delegation name '#AuthDeleg' already in use" in str(exc.value)


def test_create_user_and_agent_with_auth_delegation_unspecified_name_different_controller(valid_bip39_seed):
    resolver_client = ResolverClientTest(docs={})
    api = HighLevelIdentityApi(AdvancedIdentityRegisterApi(resolver_client))

    user_name = '#user'
    agent_name = '#agent'
    agent_name2 = '#agent2'

    user_did, _ = api.create_user_and_agent_with_auth_delegation(
        user_seed=valid_bip39_seed, user_key_name=user_name, user_name=user_name,
        agent_seed=valid_bip39_seed, agent_key_name=agent_name, agent_name=agent_name
    )

    api.create_user_and_agent_with_auth_delegation(
        user_seed=valid_bip39_seed, user_key_name=user_name, user_name=user_name,
        agent_seed=valid_bip39_seed, agent_key_name=agent_name2, agent_name=agent_name2
    )

    user_doc = resolver_client.docs.get(user_did.did)
    assert len(user_doc.auth_delegation_proof) == 2

    api.create_user_and_agent_with_auth_delegation(
        user_seed=valid_bip39_seed, user_key_name=user_name, user_name=user_name,
        agent_seed=valid_bip39_seed, agent_key_name=agent_name2, agent_name=agent_name2
    )

    user_doc = resolver_client.docs.get(user_did.did)
    assert len(user_doc.auth_delegation_proof) == 2
