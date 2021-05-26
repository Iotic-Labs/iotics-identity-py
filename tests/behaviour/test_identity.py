# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
from dataclasses import dataclass
from os.path import dirname, join

import pytest
from pytest_bdd import given, parsers, scenario, then, when

from iotics.lib.identity import AdvancedIdentityLocalApi, AdvancedIdentityRegisterApi, build_twin_secrets, DIDType, \
    DocumentValidation, IdentityApi, IdentityAuthenticationFailed, IdentityInvalidDocumentError, IdentityNotAllowed, \
    Issuer, KeyPairSecretsHelper, Proof, RegisterDocument, RegisteredIdentity, ResolverSerializer, RESTResolverClient, \
    SeedMethod
from iotics.lib.identity.validation.authentication import IdentityAuthValidation
from tests.behaviour.common import assert_newly_created_registered_identity, assert_owner_is_allowed, \
    assert_owner_key, assert_owner_not_allowed_anymore, get_secrets_by_type, RESTRequesterTest, SetupError

FEATURES = join(dirname(__file__), 'features')

RESOLVER_CLIENT = RESTResolverClient(RESTRequesterTest(), ResolverSerializer())
ADVANCED_API = AdvancedIdentityRegisterApi(RESOLVER_CLIENT)
REGULAR_API = IdentityApi(ADVANCED_API)


@pytest.fixture()
def context():
    """context: Overwritten by tests."""
    return None


@pytest.fixture(autouse=True)
def clear_resolver():
    """Auto use fixture to clear the resolver before each test"""
    RESOLVER_CLIENT.requester.doc_tokens.clear()


@dataclass(frozen=True)
class BaseGivenContext:
    pass


@dataclass(frozen=True)
class CreateContext(BaseGivenContext):
    seed: bytes
    key_name: str
    identity_name: str
    seed_method: SeedMethod = SeedMethod.SEED_METHOD_BIP39


@dataclass(frozen=True)
class SecretsFromRegisteredIDCtx(BaseGivenContext):
    seed: bytes
    key_name: str
    registered_identity: RegisteredIdentity
    identity_name: str
    doc_did: str


@dataclass(frozen=True)
class RegisteredIdentityCtx(BaseGivenContext):
    registered_identity: RegisteredIdentity
    key_name: str


@dataclass(frozen=True)
class OverridingIdentityCtx(BaseGivenContext):
    initial: RegisteredIdentityCtx
    new_identity_name: str


@dataclass(frozen=True)
class RegUserAndAgentAndDelegNameCtx(BaseGivenContext):
    user: RegisteredIdentityCtx
    agent: RegisteredIdentityCtx
    delegation_name: str


@dataclass(frozen=True)
class RegTwinAndAgentAndDelegNameCtx(BaseGivenContext):
    twin: RegisteredIdentityCtx
    agent: RegisteredIdentityCtx
    delegation_name: str


@dataclass(frozen=True)
class RegUserAndAgentNoAuthDelegCtx(BaseGivenContext):
    user: RegisteredIdentityCtx
    agent: RegisteredIdentityCtx


@dataclass(frozen=True)
class RegUserAndAgentWithAuthDelegCtx(BaseGivenContext):
    user: RegisteredIdentityCtx
    agent: RegisteredIdentityCtx


@dataclass(frozen=True)
class RegIDAndControllerIssuer(BaseGivenContext):
    identity: RegisteredIdentityCtx
    controller_issuer: Issuer


@dataclass(frozen=True)
class RegIDAndCreatorID(BaseGivenContext):
    identity: RegisteredIdentityCtx
    creator_id: str


@dataclass(frozen=True)
class NewOwnerCtx(BaseGivenContext):
    new_owner_name: str
    new_owner_public_key_base58: str
    identity_ctx: RegisteredIdentityCtx


@dataclass(frozen=True)
class RemoveOwnerCtx(BaseGivenContext):
    initial_owner_identity: RegisteredIdentityCtx
    additional_owner_issuer: Issuer


@dataclass(frozen=True)
class NotRevokedRegIDCtx(BaseGivenContext):
    identity: RegisteredIdentityCtx


@dataclass(frozen=True)
class DocCtx(BaseGivenContext):
    doc: RegisterDocument


@dataclass(frozen=True)
class ValidDocCtx(DocCtx):
    pass


@dataclass(frozen=True)
class CorruptedDocCtx(DocCtx):
    pass


@dataclass
class Context:
    given: BaseGivenContext
    when_ret_values = None


def get_new_context(given_ctx) -> Context:
    return Context(given=given_ctx)


@given(parsers.parse('a {identity_type} seed and a {identity_type} key name'), target_fixture='context')
@given(parsers.parse('an {identity_type} seed and an {identity_type} key name'), target_fixture='context')
def given_an_identity_seed_and_key_name(identity_type):
    return get_new_context(CreateContext(seed=REGULAR_API.create_seed(), key_name=f'#Key{identity_type}1',
                                         identity_name=f'#{identity_type}1'))


@given(parsers.parse('a {identity_type} seed, a {identity_type} key name and the legacy seed method'),
       target_fixture='context')
@given(parsers.parse('an {identity_type} seed, an {identity_type} key name and the legacy seed method'),
       target_fixture='context')
def given_an_identity_seed_and_key_name_witt_legacy_method(identity_type):
    return get_new_context(CreateContext(seed=REGULAR_API.create_seed(), key_name=f'#Key{identity_type}1',
                                         identity_name=f'#{identity_type}1', seed_method=SeedMethod.SEED_METHOD_NONE))


def get_registered_identity(name: str, purpose: DIDType = DIDType.TWIN) -> RegisteredIdentityCtx:
    key_name = f'{name}Key'
    identity_secrets = get_secrets_by_type(REGULAR_API.create_seed(), key_name, purpose)
    if purpose == DIDType.TWIN:
        registered_twin = ADVANCED_API.new_registered_twin_identity(identity_secrets, name)
    elif purpose == DIDType.AGENT:
        registered_twin = ADVANCED_API.new_registered_agent_identity(identity_secrets, name)
    else:
        registered_twin = ADVANCED_API.new_registered_user_identity(identity_secrets, name)
    identity_ctx = RegisteredIdentityCtx(registered_identity=registered_twin, key_name=key_name)
    return identity_ctx


def get_purpose(identity_type: str) -> DIDType:
    try:
        return DIDType(identity_type.lower())
    except ValueError:
        raise SetupError(f'Invalid identity type: {identity_type}. Must be in: {list(DIDType)}')


@given(parsers.parse('an existing registered {identity_type} identity'), target_fixture='context')
def given_an_existing_registered_type_identity(identity_type):
    purpose = get_purpose(identity_type)
    reg_user = get_registered_identity(name=f'#RegExisting{identity_type}1', purpose=purpose)
    return get_new_context(OverridingIdentityCtx(
        initial=reg_user,
        new_identity_name=f'#Reg{identity_type}Overriden'
    ))


@given(parsers.parse('a {identity_type} seed and a {identity_type} key name from a registered identity'),
       target_fixture='context')
@given(parsers.parse('an {identity_type} seed and an {identity_type} key name from a registered identity'),
       target_fixture='context')
def given_secrets_from_registered_identity(identity_type):
    purpose = DIDType(identity_type)
    identity_name = f'#GetRegID{identity_type}1'
    identity_cxt = get_registered_identity(name=identity_name, purpose=purpose)
    return get_new_context(SecretsFromRegisteredIDCtx(
        seed=identity_cxt.registered_identity.key_pair_secrets.seed,
        key_name=identity_cxt.key_name,
        registered_identity=identity_cxt.registered_identity,
        identity_name=identity_name,
        doc_did=identity_cxt.registered_identity.did
    ))


@given('a registered user, a registered agent and a delegation name', target_fixture='context')
def given_a_registered_user_a_registered_agent_and_a_delegation_name():
    return get_new_context(RegUserAndAgentAndDelegNameCtx(
        user=get_registered_identity(name='#RegUser2', purpose=DIDType.USER),
        agent=get_registered_identity(name='#RegAgent2', purpose=DIDType.AGENT),
        delegation_name='#AuthRegU2A2'
    ))


@given('a registered twin, a registered agent and a delegation name', target_fixture='context')
def given_a_registered_twin_a_registered_agent_and_a_delegation_name():
    return get_new_context(RegTwinAndAgentAndDelegNameCtx(
        twin=get_registered_identity(name='#RegTwin3', purpose=DIDType.TWIN),
        agent=get_registered_identity(name='#RegAgent3', purpose=DIDType.AGENT),
        delegation_name='#AuthRegU2A2'
    ))


@given('a registered identity and a controller issuer', target_fixture='context')
def given_a_registered_identity_and_a_controller_issuer():
    identity_ctx = get_registered_identity(name='#RegID1')

    controller_secrets = build_twin_secrets(REGULAR_API.create_seed(), '#ControllerKey')
    controller_key_pair = KeyPairSecretsHelper.get_key_pair(controller_secrets)
    controller_id = AdvancedIdentityLocalApi.create_identifier(controller_key_pair.public_bytes)
    return get_new_context(RegIDAndControllerIssuer(
        identity=identity_ctx,
        controller_issuer=Issuer.build(controller_id, '#Controller1')
    ))


@given('a registered identity and a creator', target_fixture='context')
def given_a_registered_identity_and_a_creator():
    identity_ctx = get_registered_identity(name='#RegID2')

    creator_secrets = build_twin_secrets(REGULAR_API.create_seed(), '#CreatorKey')
    creator_key_pair = KeyPairSecretsHelper.get_key_pair(creator_secrets)
    creator_id = AdvancedIdentityLocalApi.create_identifier(creator_key_pair.public_bytes)
    return get_new_context(RegIDAndCreatorID(
        identity=identity_ctx,
        creator_id=creator_id,
    ))


@given('a not revoked registered identity', target_fixture='context')
def given_a_not_revoked_registered_identity():
    identity_ctx = get_registered_identity(name='#NotRevokedRegID')
    return get_new_context(NotRevokedRegIDCtx(
        identity=identity_ctx,
    ))


@given('an existing registered identity', target_fixture='context')
def given_an_existing_registered_identity():
    return get_new_context(get_registered_identity(name='#ExistingRegID1'))


@given('an existing registered document', target_fixture='context')
def given_an_existing_registered_document():
    identity_ctx = get_registered_identity(name='#ValidDocID1')
    doc = RESOLVER_CLIENT.get_document(identity_ctx.registered_identity.did)
    return get_new_context(ValidDocCtx(doc=doc))


@given('a corrupted registered document', target_fixture='context')
def given_a_corrupted_registered_document():
    identity_ctx = get_registered_identity('#CorruptedDoc')
    subject_ctx = get_registered_identity('#ASubject')
    # add invalid delegation
    invalid_delegation_proof = Proof(issuer=subject_ctx.registered_identity.issuer,
                                     content=b'invalid deleagtion content',
                                     signature='invalid delegation proof signature')
    ADVANCED_API.add_control_delegation_proof_to_document(invalid_delegation_proof,
                                                          subject_ctx.registered_identity.issuer,
                                                          '#NewInvalidDelegation',
                                                          identity_ctx.registered_identity.issuer,
                                                          KeyPairSecretsHelper.get_key_pair(
                                                              identity_ctx.registered_identity.key_pair_secrets))
    doc_with_invalid_delegation = RESOLVER_CLIENT.get_document(identity_ctx.registered_identity.did)
    return get_new_context(CorruptedDocCtx(doc=doc_with_invalid_delegation))


@given('a register user document and a register agent document without authentication delegation',
       target_fixture='context')
def given_a_register_user_document_and_a_register_agent_document_without_authentication_delegation():
    return get_new_context(RegUserAndAgentNoAuthDelegCtx(
        user=get_registered_identity(name='#RegUserNotAuthDeleg', purpose=DIDType.USER),
        agent=get_registered_identity(name='#RegAgentNotAuthDeleg', purpose=DIDType.AGENT)
    ))


@given('a register user document and a register agent document with authentication delegation',
       target_fixture='context')
def given_a_register_user_document_and_a_register_agent_document_with_authentication_delegation():
    ctx = RegUserAndAgentWithAuthDelegCtx(
        user=get_registered_identity(name='#RegUserWithAuthDeleg', purpose=DIDType.USER),
        agent=get_registered_identity(name='#RegAgentwithAuthDeleg', purpose=DIDType.AGENT))
    ADVANCED_API.delegate_authentication(ctx.user.registered_identity.key_pair_secrets,
                                         ctx.user.registered_identity.did,
                                         ctx.agent.registered_identity.key_pair_secrets,
                                         ctx.agent.registered_identity.did,
                                         delegation_name='#UserAgentAuthDeleg')
    return get_new_context(ctx)


@given('a new owner key name an registered identity register', target_fixture='context')
def given_a_new_owner_key_name_an_registered_identity_register():
    identity_ctx = get_registered_identity('#ADocForNewOwner')
    new_owner_secrets = get_secrets_by_type(REGULAR_API.create_seed(), 'NewOwner1Key', DIDType.USER)
    new_owner_key_pair = KeyPairSecretsHelper.get_key_pair(new_owner_secrets)
    return get_new_context(NewOwnerCtx(
        new_owner_name='#NewOwner1',
        new_owner_public_key_base58=new_owner_key_pair.public_base58,
        identity_ctx=identity_ctx
    ))


@given('a owner key name an registered identity register', target_fixture='context')
def given_a_owner_key_name_an_registered_identity_register():
    identity_ctx = get_registered_identity('#ADocForRemoveOwner')

    new_owner_name = '#NewOwner2'
    new_owner_secrets = get_secrets_by_type(REGULAR_API.create_seed(), 'NewOwner2Key', DIDType.USER)
    new_owner_key_pair = KeyPairSecretsHelper.get_key_pair(new_owner_secrets)
    REGULAR_API.add_new_owner(new_owner_name, new_owner_key_pair.public_base58, identity_ctx.registered_identity)

    return get_new_context(RemoveOwnerCtx(
        initial_owner_identity=identity_ctx,
        additional_owner_issuer=Issuer.build(identity_ctx.registered_identity.did, new_owner_name),
    ))


@when('I create a user')
def when_i_create_a_user(context: Context):
    given_ctx: CreateContext = context.given
    ret = REGULAR_API.create_user_identity(given_ctx.seed, given_ctx.key_name, given_ctx.identity_name,
                                           seed_method=given_ctx.seed_method)
    context.when_ret_values = ret


@when('I create an agent')
def when_i_create_an_agent(context: Context):
    given_ctx: CreateContext = context.given
    ret = REGULAR_API.create_agent_identity(given_ctx.seed, given_ctx.key_name, given_ctx.identity_name,
                                            seed_method=given_ctx.seed_method)
    context.when_ret_values = ret


@when('I create a twin')
def when_i_create_a_twin(context: Context):
    given_ctx: CreateContext = context.given
    ret = REGULAR_API.create_twin_identity(given_ctx.seed, given_ctx.key_name, given_ctx.identity_name,
                                           seed_method=given_ctx.seed_method)
    context.when_ret_values = ret


@when('I create the user overriding the document with a new user name')
def when_i_create_the_user_overriding_the_document_with_a_new_user_name(context: Context):
    given_ctx: OverridingIdentityCtx = context.given
    ret = REGULAR_API.create_user_identity(given_ctx.initial.registered_identity.key_pair_secrets.seed,
                                           given_ctx.initial.key_name,
                                           given_ctx.new_identity_name,
                                           override_doc=True)
    context.when_ret_values = ret


@when('I create the agent overriding the document with a new agent name')
def when_i_create_the_agent_overriding_the_document_with_a_new_agent_name(context: Context):
    given_ctx: OverridingIdentityCtx = context.given
    ret = REGULAR_API.create_agent_identity(given_ctx.initial.registered_identity.key_pair_secrets.seed,
                                            given_ctx.initial.key_name,
                                            given_ctx.new_identity_name,
                                            override_doc=True)
    context.when_ret_values = ret


@when('I create the twin overriding the document with a new twin name')
def when_i_create_the_twin_overriding_the_document_with_a_new_twin_name(context: Context):
    given_ctx: OverridingIdentityCtx = context.given
    ret = REGULAR_API.create_twin_identity(given_ctx.initial.registered_identity.key_pair_secrets.seed,
                                           given_ctx.initial.key_name,
                                           given_ctx.new_identity_name,
                                           override_doc=True)
    context.when_ret_values = ret


@when('I get the user identity')
def when_i_get_the_user_identity(context: Context):
    given_ctx: SecretsFromRegisteredIDCtx = context.given
    registered_identity = REGULAR_API.get_user_identity(given_ctx.seed, given_ctx.key_name,
                                                        given_ctx.doc_did,
                                                        given_ctx.identity_name)
    context.when_ret_values = registered_identity


@when('I get the agent identity')
def when_i_get_the_agent_identity(context: Context):
    given_ctx: SecretsFromRegisteredIDCtx = context.given
    registered_identity = REGULAR_API.get_agent_identity(given_ctx.seed, given_ctx.key_name,
                                                         given_ctx.doc_did,
                                                         given_ctx.identity_name)
    context.when_ret_values = registered_identity


@when('I get the twin identity')
def when_i_get_the_twin_identity(context: Context):
    given_ctx: SecretsFromRegisteredIDCtx = context.given
    registered_identity = REGULAR_API.get_twin_identity(given_ctx.seed, given_ctx.key_name,
                                                        given_ctx.doc_did,
                                                        given_ctx.identity_name)
    context.when_ret_values = registered_identity


@when('User delegates authentication to agent')
def when_user_delegates_authentication_to_agent(context: Context):
    given_ctx: RegUserAndAgentAndDelegNameCtx = context.given
    REGULAR_API.user_delegates_authentication_to_agent(given_ctx.user.registered_identity,
                                                       given_ctx.agent.registered_identity,
                                                       given_ctx.delegation_name)


@when('Twin delegates control to agent')
def when_twin_delegates_control_to_agent(context: Context):
    given_ctx: RegTwinAndAgentAndDelegNameCtx = context.given
    REGULAR_API.twin_delegates_control_to_agent(given_ctx.twin.registered_identity,
                                                given_ctx.agent.registered_identity,
                                                given_ctx.delegation_name)


@when('I set the identity register document controller')
def when_i_set_the_identity_register_document_controller(context: Context):
    given_ctx: RegIDAndControllerIssuer = context.given
    REGULAR_API.set_document_controller(given_ctx.identity.registered_identity,
                                        given_ctx.controller_issuer)


@when('I set the identity register document creator')
def when_i_set_the_identity_register_document_creator(context: Context):
    given_ctx: RegIDAndCreatorID = context.given
    REGULAR_API.set_document_creator(given_ctx.identity.registered_identity,
                                     given_ctx.creator_id)


@when('I revoke the identity register document')
def when_i_revoke_the_identity_register_document(context: Context):
    given_ctx: NotRevokedRegIDCtx = context.given
    REGULAR_API.set_document_revoked(given_ctx.identity.registered_identity,
                                     revoked=True)


@when('I get the registered document')
def when_i_get_the_registered_document(context: Context):
    given_ctx: RegisteredIdentityCtx = context.given
    ret = REGULAR_API.get_register_document(given_ctx.registered_identity.did)
    context.when_ret_values = ret


@when('I verify the document')
def when_i_verify_the_document(context: Context):
    given_ctx: DocCtx = context.given
    try:
        REGULAR_API.validate_register_document(given_ctx.doc)
    except IdentityInvalidDocumentError as err:
        context.when_ret_values = err


@when('I create an authentication token from the agent without delegation')
def when_i_create_an_authentication_token_from_the_agent_without_deleg(context: Context):
    given_ctx: RegUserAndAgentNoAuthDelegCtx = context.given
    token = REGULAR_API.create_agent_auth_token(given_ctx.agent.registered_identity,
                                                given_ctx.user.registered_identity.did,
                                                duration=5000)
    context.when_ret_values = token


@when('I create an authentication token from the agent with delegation')
def when_i_create_an_authentication_token_from_the_agent_with_deleg(context: Context):
    given_ctx: RegUserAndAgentWithAuthDelegCtx = context.given
    token = REGULAR_API.create_agent_auth_token(given_ctx.agent.registered_identity,
                                                given_ctx.user.registered_identity.did,
                                                duration=5000)
    context.when_ret_values = token


@when('I add a new owner')
def when_i_add_a_new_owner(context: Context):
    given_ctx: NewOwnerCtx = context.given
    REGULAR_API.add_new_owner(given_ctx.new_owner_name, given_ctx.new_owner_public_key_base58,
                              given_ctx.identity_ctx.registered_identity)


@when('I remove a owner')
def when_i_remove_a_owner(context: Context):
    ctx: RemoveOwnerCtx = context.given
    REGULAR_API.remove_ownership(removed_owner_issuer=ctx.additional_owner_issuer,
                                 existing_owner_registered_identity=ctx.initial_owner_identity.registered_identity)


def assert_single_owner_doc_is_valid(registered_identity: RegisteredIdentity, purpose: DIDType, owner_name: str):
    doc = REGULAR_API.get_register_document(registered_identity.did)
    assert doc.purpose == purpose
    DocumentValidation.validate_document_against_resolver(RESOLVER_CLIENT, doc)
    assert len(doc.public_keys) >= 1
    assert_owner_key(doc, owner_name, registered_identity)


@then(parsers.parse('the {identity_type} register document is created, the associated {identity_type} identity '
                    'is returned and the {identity_type} owns the document'))
def then_the_identity_is_created_and_registered(identity_type, context: Context):
    given_ctx: CreateContext = context.given
    created_registered_identity = context.when_ret_values
    purpose = get_purpose(identity_type)

    assert_newly_created_registered_identity(given_ctx.seed, given_ctx.key_name, given_ctx.identity_name,
                                             given_ctx.seed_method, created_registered_identity, purpose)
    assert_single_owner_doc_is_valid(created_registered_identity, purpose, given_ctx.identity_name)
    assert_owner_is_allowed(RESOLVER_CLIENT, Issuer.build(created_registered_identity.did, given_ctx.identity_name),
                            created_registered_identity.did)


@then(parsers.parse('the {identity_type} document is updated with the new name'))
def then_the_identity_document_is_updated_with_the_new_name(identity_type, context: Context):
    given_ctx: OverridingIdentityCtx = context.given
    updated_registered_identity = context.when_ret_values
    purpose = get_purpose(identity_type)

    assert given_ctx.initial.registered_identity.key_pair_secrets == updated_registered_identity.key_pair_secrets
    assert given_ctx.initial.registered_identity.issuer != updated_registered_identity.issuer
    assert given_ctx.initial.registered_identity.issuer.did == updated_registered_identity.issuer.did
    assert given_ctx.initial.registered_identity.name != updated_registered_identity.name
    assert updated_registered_identity.name == given_ctx.new_identity_name

    assert_single_owner_doc_is_valid(updated_registered_identity, purpose, given_ctx.new_identity_name)
    owner_issuer = Issuer.build(updated_registered_identity.did, given_ctx.new_identity_name)
    assert_owner_is_allowed(RESOLVER_CLIENT, owner_issuer, updated_registered_identity.did)


@then('the identity is valid')
def then_the_identity_is_valid(context: Context):
    given_ctx: SecretsFromRegisteredIDCtx = context.given
    retrieved_registered_identity = context.when_ret_values
    assert retrieved_registered_identity == given_ctx.registered_identity


@then('the user document is updated with the agent authentication delegation')
def then_the_user_document_is_updated_with_the_agent_authentication_delegation(context: Context):
    given_ctx: RegUserAndAgentAndDelegNameCtx = context.given
    assert_single_owner_doc_is_valid(given_ctx.user.registered_identity, DIDType.USER,
                                     given_ctx.user.registered_identity.name)
    assert_single_owner_doc_is_valid(given_ctx.agent.registered_identity, DIDType.AGENT,
                                     given_ctx.agent.registered_identity.name)
    user_doc = REGULAR_API.get_register_document(given_ctx.user.registered_identity.did)
    auth_delegation_proof = user_doc.auth_delegation_proof.get(given_ctx.delegation_name)
    assert auth_delegation_proof, f'Auth delegation proof {auth_delegation_proof} should be added to the user document'
    assert not auth_delegation_proof.revoked, f'Auth delegation proof {auth_delegation_proof} should not be revoked'
    assert auth_delegation_proof.controller == given_ctx.agent.registered_identity.issuer, \
        f'Auth delegation proof {auth_delegation_proof} controller should be equal to the agent issuer'
    try:
        IdentityAuthValidation.validate_allowed_for_auth(RESOLVER_CLIENT,
                                                         issuer=given_ctx.agent.registered_identity.issuer,
                                                         subject_id=given_ctx.user.registered_identity.did)
    except IdentityNotAllowed as err:
        assert False, f'Agent should be allowed for authentication in behalf of the user: {err}'


@then('the twin document is updated with the agent authentication delegation')
def then_the_twin_document_is_updated_with_the_agent_authentication_delegation(context: Context):
    given_ctx: RegTwinAndAgentAndDelegNameCtx = context.given
    assert_single_owner_doc_is_valid(given_ctx.twin.registered_identity, DIDType.TWIN,
                                     given_ctx.twin.registered_identity.name)
    assert_single_owner_doc_is_valid(given_ctx.agent.registered_identity, DIDType.AGENT,
                                     given_ctx.agent.registered_identity.name)
    twin_doc = REGULAR_API.get_register_document(given_ctx.twin.registered_identity.did)
    ctrl_delegation_proof = twin_doc.control_delegation_proof.get(given_ctx.delegation_name)
    assert ctrl_delegation_proof, f'Control delegation proof {ctrl_delegation_proof} ' \
                                  f'should be added to the twin document'
    assert not ctrl_delegation_proof.revoked, f'Control delegation proof {ctrl_delegation_proof} should not be revoked'
    assert ctrl_delegation_proof.controller == given_ctx.agent.registered_identity.issuer, \
        f'Control delegation proof {ctrl_delegation_proof} controller should be equal to the agent issuer'
    try:
        IdentityAuthValidation.validate_allowed_for_control(RESOLVER_CLIENT,
                                                            issuer=given_ctx.agent.registered_identity.issuer,
                                                            subject_id=given_ctx.twin.registered_identity.did)
    except IdentityNotAllowed as err:
        assert False, f'Agent should be allowed for control in behalf of the twin: {err}'


@then('the document is updated with the new controller')
def then_the_document_is_updated_with_the_new_controller(context: Context):
    given_ctx: RegIDAndControllerIssuer = context.given
    assert_single_owner_doc_is_valid(given_ctx.identity.registered_identity, DIDType.TWIN,
                                     given_ctx.identity.registered_identity.name)
    identity_doc = REGULAR_API.get_register_document(given_ctx.identity.registered_identity.did)
    assert identity_doc.controller == given_ctx.controller_issuer, 'Register Document should be updated with ' \
                                                                   'the new controller'


@then('the document is updated with the new creator')
def then_the_document_is_updated_with_the_new_creator(context: Context):
    given_ctx: RegIDAndCreatorID = context.given
    assert_single_owner_doc_is_valid(given_ctx.identity.registered_identity, DIDType.TWIN,
                                     given_ctx.identity.registered_identity.name)
    identity_doc = REGULAR_API.get_register_document(given_ctx.identity.registered_identity.did)
    assert identity_doc.creator == given_ctx.creator_id, 'Register Document should be updated with ' \
                                                         'the new creator id'


@then('the document is revoked')
def then_the_document_is_revoked(context: Context):
    given_ctx: NotRevokedRegIDCtx = context.given
    assert_single_owner_doc_is_valid(given_ctx.identity.registered_identity, DIDType.TWIN,
                                     given_ctx.identity.registered_identity.name)
    identity_doc = REGULAR_API.get_register_document(given_ctx.identity.registered_identity.did)
    assert identity_doc.revoked, 'Register Document should be revoked now'


@then('the corresponding document is returned')
def then_the_corresponding_document_is_returned(context: Context):
    given_ctx: RegisteredIdentityCtx = context.given
    returned_doc = context.when_ret_values
    assert returned_doc.did == given_ctx.registered_identity.did
    assert returned_doc.public_keys.get(given_ctx.registered_identity.name)


@then('the document is valid')
def then_the_document_is_valid(context: Context):
    verify_error = context.when_ret_values
    assert verify_error is None, 'Valid document verification should not raise an error'


@then('a validation error is raised')
def then_a_validation_error_is_raised(context: Context):
    verify_error = context.when_ret_values
    assert verify_error, 'Corrupted document verification should raise an error'


@then('the token is not authorized for authentication')
def then_the_token_is_not_authorized_for_authentication(context: Context):
    token = context.when_ret_values
    assert token, 'The authentication token should be created'
    with pytest.raises(IdentityAuthenticationFailed):
        IdentityAuthValidation.verify_authentication(RESOLVER_CLIENT, token)


@then('the token is authorized for authentication')
def then_the_token_is_authorized_for_authentication(context: Context):
    token = context.when_ret_values
    assert token, 'The authentication token should be created'
    try:
        IdentityAuthValidation.verify_authentication(RESOLVER_CLIENT, token)
    except IdentityAuthenticationFailed as err:
        assert False, f'The authentication should be valid for authentication: {err}'


@then('the new owner key has been added to the document')
def then_the_new_owner_key_has_been_added_to_the_document(context: Context):
    given_ctx: NewOwnerCtx = context.given
    initial_owner_issuer = given_ctx.identity_ctx.registered_identity.issuer
    doc_with_additional_owner = REGULAR_API.get_register_document(initial_owner_issuer.did)
    initial_owner_key = doc_with_additional_owner.public_keys.get(initial_owner_issuer.name)
    assert initial_owner_key, 'Initial owner key should still belongs to the doc public keys'
    assert not initial_owner_key.revoked, 'Initial owner key should not be revoked'

    additional_owner_key = doc_with_additional_owner.public_keys.get(given_ctx.new_owner_name)
    assert additional_owner_key, 'New owner key should belongs to the doc public keys'
    assert not additional_owner_key.revoked, 'New owner key should not be revoked'
    assert additional_owner_key.base58 == given_ctx.new_owner_public_key_base58, 'New owner key base58 is invalid'
    new_owner_issuer = Issuer.build(doc_with_additional_owner.did, given_ctx.new_owner_name)
    assert_owner_is_allowed(RESOLVER_CLIENT, new_owner_issuer, doc_with_additional_owner.did)
    assert_owner_is_allowed(RESOLVER_CLIENT, initial_owner_issuer, doc_with_additional_owner.did)


@then('the key has been removed from the document')
def then_the_key_has_been_removed_from_the_document(context: Context):
    given_ctx: RemoveOwnerCtx = context.given
    initial_owner_issuer = given_ctx.initial_owner_identity.registered_identity.issuer
    doc_with_owner_removed = REGULAR_API.get_register_document(initial_owner_issuer.did)
    initial_owner_key = doc_with_owner_removed.public_keys.get(initial_owner_issuer.name)
    assert initial_owner_key, 'Initial owner key should still belongs to the doc public keys'
    assert not initial_owner_key.revoked, 'Initial owner key should not be revoked'

    additional_owner_key = doc_with_owner_removed.public_keys.get(given_ctx.additional_owner_issuer.name)
    assert not additional_owner_key, 'Additional owner key should not belong to the doc anymore'
    assert_owner_not_allowed_anymore(RESOLVER_CLIENT, given_ctx.additional_owner_issuer, doc_with_owner_removed.did)
    assert_owner_is_allowed(RESOLVER_CLIENT, initial_owner_issuer, doc_with_owner_removed.did)


@scenario('identity_api.feature', 'Create user identity with default seed method', features_base_dir=FEATURES)
def test_create_user_identity_with_default_seed_method():
    pass


@scenario('identity_api.feature', 'Create user identity with legacy seed method',
          features_base_dir=FEATURES)
def test_create_user_identity_with_default_legacy_seed_method():
    pass


@scenario('identity_api.feature', 'Create agent identity with default seed method', features_base_dir=FEATURES)
def test_create_agent_identity_with_default_seed_method():
    pass


@scenario('identity_api.feature', 'Create agent identity with legacy seed method',
          features_base_dir=FEATURES)
def test_create_agent_identity_with_default_legacy_seed_method():
    pass


@scenario('identity_api.feature', 'Create twin identity with default seed method', features_base_dir=FEATURES)
def test_create_twin_identity_with_default_seed_method():
    pass


@scenario('identity_api.feature', 'Create twin identity with legacy seed method',
          features_base_dir=FEATURES)
def test_create_twin_identity_with_default_legacy_seed_method():
    pass


@scenario('identity_api.feature', 'Create user identity overriding previously created identity',
          features_base_dir=FEATURES)
def test_create_user_identity_overriding_previously_created_identity():
    pass


@scenario('identity_api.feature', 'Create agent identity overriding previously created identity',
          features_base_dir=FEATURES)
def test_create_agent_identity_overriding_previously_created_identity():
    pass


@scenario('identity_api.feature', 'Create twin identity overriding previously created identity',
          features_base_dir=FEATURES)
def test_create_twin_identity_overriding_previously_created_identity():
    pass


@scenario('identity_api.feature', 'Get existing user identity from secrets', features_base_dir=FEATURES)
def test_get_existing_user_identity_from_secrets():
    pass


@scenario('identity_api.feature', 'Get existing agent identity from secrets', features_base_dir=FEATURES)
def test_get_existing_agent_identity_from_secrets():
    pass


@scenario('identity_api.feature', 'Get existing twin identity from secrets', features_base_dir=FEATURES)
def test_get_existing_twin_identity_from_secrets():
    pass


@scenario('identity_api.feature', 'User delegates authentication to agent', features_base_dir=FEATURES)
def test_user_delegates_authentication_to_agent():
    pass


@scenario('identity_api.feature', 'Twin delegates control to agent', features_base_dir=FEATURES)
def test_twin_delegates_control_to_agent():
    pass


@scenario('identity_api.feature', 'Set document controller', features_base_dir=FEATURES)
def test_set_document_controller():
    pass


@scenario('identity_api.feature', 'Set document creator', features_base_dir=FEATURES)
def test_set_document_creator():
    pass


@scenario('identity_api.feature', 'Revoke a document', features_base_dir=FEATURES)
def test_revoke_a_document():
    pass


@scenario('identity_api.feature', 'Get a registered document', features_base_dir=FEATURES)
def test_get_a_registered_document():
    pass


@scenario('identity_api.feature', 'Verify a valid register document', features_base_dir=FEATURES)
def test_verify_a_valid_register_document():
    pass


@scenario('identity_api.feature', 'Verify an corrupted register document', features_base_dir=FEATURES)
def test_verify_an_corrupted_register_document():
    pass


@scenario('identity_api.feature', 'Create authentication token without authentication delegation',
          features_base_dir=FEATURES)
def test_create_authentication_token_without_authentication_delegation():
    pass


@scenario('identity_api.feature', 'Create authentication token with authentication delegation',
          features_base_dir=FEATURES)
def test_create_authentication_token_with_authentication_delegation():
    pass


@scenario('identity_api.feature', 'Add new owner to a register document', features_base_dir=FEATURES)
def test_add_new_owner_to_a_register_document():
    pass


@scenario('identity_api.feature', 'Remove owner from a register document', features_base_dir=FEATURES)
def test_remove_owner_from_a_register_document():
    pass
