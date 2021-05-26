# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
from dataclasses import dataclass
from os.path import dirname, join

import pytest
from pytest_bdd import given, scenario, then, when

from iotics.lib.identity import AdvancedIdentityRegisterApi, HighLevelIdentityApi, IdentityApi, Issuer, \
    KeyPairSecretsHelper, RegisterDocument, RegisteredIdentity, ResolverSerializer, RESTResolverClient, \
    SeedMethod
from iotics.lib.identity.api.advanced_api import AdvancedIdentityLocalApi
from iotics.lib.identity.validation.authentication import IdentityAuthValidation
from tests.behaviour.common import assert_newly_created_registered_identity, assert_owner_is_allowed, \
    assert_owner_key, get_secrets_by_type, RESTRequesterTest

FEATURES = join(dirname(__file__), 'features')

RESOLVER_CLIENT = RESTResolverClient(RESTRequesterTest(), ResolverSerializer())
HIGH_LEVEL_API = HighLevelIdentityApi(AdvancedIdentityRegisterApi(RESOLVER_CLIENT))
REGULAR_API = IdentityApi(AdvancedIdentityRegisterApi(RESOLVER_CLIENT))


@pytest.fixture()
def context():
    """context: Overwritten by tests."""
    return None


@dataclass(frozen=True)
class IdentityContext:
    seed: bytes
    key_name: str
    issuer_name: str


@dataclass(frozen=True)
class GivenContext:
    user: IdentityContext
    agent: IdentityContext
    twin: IdentityContext
    registered_user: RegisteredIdentity
    registered_agent: RegisteredIdentity
    registered_twin: RegisteredIdentity
    auth_delegation_name: str
    control_delegation_name: str
    new_owner_name: str
    token_duration: int


@dataclass
class Context:
    given: GivenContext
    when_ret_values = None


def get_new_given_context() -> Context:
    RESOLVER_CLIENT.requester.doc_tokens.clear()
    given_ctx = GivenContext(
        user=IdentityContext(seed=HIGH_LEVEL_API.create_seed(),
                             key_name='#keyUser1',
                             issuer_name='#User1'),
        agent=IdentityContext(seed=HIGH_LEVEL_API.create_seed(),
                              key_name='#keyAgent1',
                              issuer_name='#Agent1'),
        twin=IdentityContext(seed=HIGH_LEVEL_API.create_seed(),
                             key_name='#keyTwin1',
                             issuer_name='#Twin1'),
        registered_user=REGULAR_API.create_user_identity(HIGH_LEVEL_API.create_seed(), '#RegUserKey1', '#RegUser1'),
        registered_agent=REGULAR_API.create_agent_identity(HIGH_LEVEL_API.create_seed(), '#RegAgentKey1', '#RegAgent1'),
        registered_twin=REGULAR_API.create_twin_identity(HIGH_LEVEL_API.create_seed(), '#RegTwinKey1', '#RegTwin1'),
        new_owner_name='#NewOwner',
        auth_delegation_name='#AuthDelegation',
        control_delegation_name='#CtrlDelegation',
        token_duration=500,
    )
    return Context(given=given_ctx)


@given('a user seed, a user key name, an agent seed, and agent key name and a delegation name',
       target_fixture='context')
def given_user_and_agent_seeds_and_key_names_and_delegation_name():
    ctx = get_new_given_context()
    return ctx


@given('a twin seed and twin a key name', target_fixture='context')
def given_twin_seed_and_key_name():
    ctx = get_new_given_context()
    return ctx


@given('a twin seed, a twin key name and a registered agent identity', target_fixture='context')
def given_twin_seed_and_key_name_and_a_registered_agent():
    ctx = get_new_given_context()
    return ctx


@given('a registered agent identity with auth delegation for a user_did and a duration', target_fixture='context')
def given_a_registered_agent_a_user_and_a_duration():
    ctx = get_new_given_context()
    return ctx


@given('a registered twin identity, a registered user identity and a new owner name', target_fixture='context')
def given_a_new_owner_name_and_a_registered_twin_and_user():
    ctx = get_new_given_context()
    return ctx


@when('I create user and agent with authentication delegation')
def when_i_create_user_and_agent_with_delegation(context: Context):
    context.when_ret_values = HIGH_LEVEL_API.create_user_and_agent_with_auth_delegation(
        user_seed=context.given.user.seed,
        user_key_name=context.given.user.key_name,
        user_name=context.given.user.issuer_name,
        agent_seed=context.given.agent.seed,
        agent_key_name=context.given.agent.key_name,
        agent_name=context.given.agent.issuer_name,
        delegation_name=context.given.auth_delegation_name)


@when('I create a twin')
def when_i_create_a_twin(context: Context):
    ret = HIGH_LEVEL_API.create_twin(twin_seed=context.given.twin.seed,
                                     twin_key_name=context.given.twin.key_name,
                                     twin_name=context.given.twin.issuer_name)
    context.when_ret_values = ret


@when('I create a twin with control delegation')
def when_i_create_a_twin_with_control_delegation(context: Context):
    ret = HIGH_LEVEL_API.create_twin_with_control_delegation(twin_seed=context.given.twin.seed,
                                                             twin_key_name=context.given.twin.key_name,
                                                             twin_name=context.given.twin.issuer_name,
                                                             agent_registered_identity=context.given.registered_agent,
                                                             delegation_name=context.given.control_delegation_name)
    context.when_ret_values = ret


@when('I create an agent auth token')
def when_i_create_an_agent_token(context: Context):
    when_i_create_user_and_agent_with_delegation(context)
    user_registered_identity, agent_registered_identity = context.when_ret_values
    ret = HIGH_LEVEL_API.create_agent_auth_token(agent_registered_identity=agent_registered_identity,
                                                 user_did=user_registered_identity.did,
                                                 duration=context.given.token_duration)
    context.when_ret_values = ret


@when('the user takes ownership of the registered twin')
def when_user_takes_ownership_of_the_twin(context: Context):
    HIGH_LEVEL_API.get_ownership_of_twin_from_registered_identity(
        twin_registered_identity=context.given.registered_twin,
        new_owner_registered_identity=context.given.registered_user,
        new_owner_key_name=context.given.new_owner_name
    )


def assert_new_doc_and_identity(doc: RegisterDocument, registered_identity: RegisteredIdentity,
                                identity_ctx: IdentityContext):
    REGULAR_API.validate_register_document(doc)
    assert_newly_created_registered_identity(identity_ctx.seed, identity_ctx.key_name, identity_ctx.issuer_name,
                                             SeedMethod.SEED_METHOD_BIP39, registered_identity, doc.purpose)
    assert_owner_key(doc, identity_ctx.issuer_name, registered_identity)
    expected_secrets = get_secrets_by_type(identity_ctx.seed, identity_ctx.key_name, doc.purpose)
    expected_key_pair = KeyPairSecretsHelper.get_key_pair(expected_secrets)
    expected_issuer = Issuer.build(AdvancedIdentityLocalApi.create_identifier(expected_key_pair.public_bytes),
                                   identity_ctx.issuer_name)

    assert_owner_key(doc, identity_ctx.issuer_name, registered_identity)
    assert registered_identity.key_pair_secrets == expected_secrets, 'User corrupted secrets'
    assert registered_identity.issuer == expected_issuer, 'User invalid issuer'
    owner_issuer = Issuer.build(registered_identity.did, identity_ctx.issuer_name)
    assert_owner_is_allowed(RESOLVER_CLIENT, owner_issuer, registered_identity.did)


@then('the user and agent documents are created and registered with authentication delegation')
def then_user_and_agent_are_created_and_registered_with_delegation(context: Context):
    user_registered_identity, agent_registered_identity = context.when_ret_values

    user_doc = REGULAR_API.get_register_document(user_registered_identity.did)
    assert_new_doc_and_identity(user_doc, user_registered_identity, context.given.user)

    agent_doc = REGULAR_API.get_register_document(agent_registered_identity.did)
    assert_new_doc_and_identity(agent_doc, agent_registered_identity, context.given.agent)

    auth_delegation_proof = user_doc.auth_delegation_proof.get(context.given.auth_delegation_name)
    assert auth_delegation_proof, f'Auth delegation proof {auth_delegation_proof} should be added to the user document'
    assert not auth_delegation_proof.revoked, f'Auth delegation proof {auth_delegation_proof} should not be revoked'
    assert auth_delegation_proof.controller == agent_registered_identity.issuer, \
        f'Auth delegation proof {auth_delegation_proof} controller should be equal to the agent issuer'


@then('the twin document is created and registered')
def then_the_twin_is_created_and_registered(context: Context):
    twin_registered_identity = context.when_ret_values

    twin_doc = REGULAR_API.get_register_document(twin_registered_identity.did)
    assert_new_doc_and_identity(twin_doc, twin_registered_identity, context.given.twin)


@then('the twin document is created and registered with control delegation')
def then_the_twin_is_created_and_registered_with_delegation(context: Context):
    twin_registered_identity = context.when_ret_values

    twin_doc = REGULAR_API.get_register_document(twin_registered_identity.did)
    assert_new_doc_and_identity(twin_doc, twin_registered_identity, context.given.twin)

    control_delegation_proof = twin_doc.control_delegation_proof.get(context.given.control_delegation_name)
    assert control_delegation_proof, f'control delegation proof {control_delegation_proof} ' \
                                     f'should be added to the twin document'
    assert not control_delegation_proof.revoked, \
        f'Control delegation proof {control_delegation_proof} should not be revoked'
    assert control_delegation_proof.controller == context.given.registered_agent.issuer, \
        f'Control delegation proof {control_delegation_proof} controller should be equal to the agent issuer'
    IdentityAuthValidation.validate_allowed_for_control(RESOLVER_CLIENT, context.given.registered_agent.issuer,
                                                        twin_doc.did)


@then('an authorized token is created')
def then_an_authorized_token_is_created(context: Context):
    token = context.when_ret_values
    IdentityAuthValidation.verify_authentication(RESOLVER_CLIENT, token)


@then('the twin document is updated with the new owner')
def then_the_twin_doc_has_a_new_owner(context: Context):
    twin_doc = REGULAR_API.get_register_document(context.given.registered_twin.did)
    REGULAR_API.validate_register_document(twin_doc)
    expected_key_pair = KeyPairSecretsHelper.get_key_pair(context.given.registered_user.key_pair_secrets)
    owner_issuer = context.given.registered_twin.issuer
    owner_key = twin_doc.public_keys.get(owner_issuer.name)
    assert owner_key, 'Twin owner key should still belong to the document'
    additional_owner_issuer = Issuer.build(owner_issuer.did, context.given.new_owner_name)
    additional_owner_key = twin_doc.public_keys.get(additional_owner_issuer.name)
    assert additional_owner_key, 'Twin additional owner key not found in the register document'

    assert not additional_owner_key.revoked, 'Twin additional owner key should not be revoked'
    assert additional_owner_key.base58 == expected_key_pair.public_base58, \
        'Twin invalid additional owner public key base58'
    assert_owner_is_allowed(RESOLVER_CLIENT, additional_owner_issuer, twin_doc.did)
    assert_owner_is_allowed(RESOLVER_CLIENT, owner_issuer, twin_doc.did)


@scenario('high_level_identity_api.feature',
          'Create user and agent with authentication delegation',
          features_base_dir=FEATURES)
def test_create_user_and_agent_with_auth_deleg():
    pass


@scenario('high_level_identity_api.feature',
          'Create a Twin',
          features_base_dir=FEATURES)
def test_create_twin():
    pass


@scenario('high_level_identity_api.feature',
          'Create a Twin with control delegation',
          features_base_dir=FEATURES)
def test_create_twin_with_ctrl_deleg():
    pass


@scenario('high_level_identity_api.feature',
          'Create an agent token',
          features_base_dir=FEATURES)
def test_create_agent_token():
    pass


@scenario('high_level_identity_api.feature',
          'Get ownership of a twin',
          features_base_dir=FEATURES)
def test_get_ownership_of_a_twin():
    pass
