# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
from dataclasses import dataclass
from os.path import dirname, join
from typing import List

import pytest
from pytest_bdd import given, scenario, then, when

from iotics.lib.identity import AdvancedIdentityLocalApi, AdvancedIdentityRegisterApi, DIDType, IdentityApi, Issuer, \
    KeyPairSecretsHelper, Proof, RegisteredIdentity, ResolverSerializer, RESTResolverClient
from tests.behaviour.common import assert_owner_is_allowed, assert_owner_key, assert_owner_not_allowed_anymore, \
    assert_owner_pub_key_exist, get_allowed_for_auth_and_control_error, get_allowed_for_auth_error, \
    get_allowed_for_control_error, get_secrets_by_type, RESTRequesterTest

FEATURES = join(dirname(__file__), 'features')

RESOLVER_CLIENT = RESTResolverClient(RESTRequesterTest(), ResolverSerializer())
ADVANCED_API = AdvancedIdentityRegisterApi(RESOLVER_CLIENT)


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
class KeysCtx(BaseGivenContext):
    public_key_base58: str
    identity_name: str


@dataclass(frozen=True)
class RegisteredIdentityCtx(BaseGivenContext):
    registered_identity: RegisteredIdentity
    key_name: str


@dataclass(frozen=True)
class DocWithSeveralOwnersCtx(RegisteredIdentityCtx):
    all_owners: List[KeysCtx]


@dataclass(frozen=True)
class AddNewOwnerCtx(BaseGivenContext):
    initial_owner_identity: RegisteredIdentityCtx
    new_owner: KeysCtx


@dataclass(frozen=True)
class OtherExistingOwnerCtx(BaseGivenContext):
    initial_owner_identity: RegisteredIdentityCtx
    other_existing_owner_issuer: Issuer


@dataclass(frozen=True)
class AddNewAuthKeyCtx(BaseGivenContext):
    initial_owner_identity: RegisteredIdentityCtx
    new_auth_key: KeysCtx


@dataclass(frozen=True)
class OtherExistingAuthKeyCtx(BaseGivenContext):
    initial_owner_identity: RegisteredIdentityCtx
    existing_auth_key_name: str


@dataclass(frozen=True)
class RegisterIdentityAndControlDelegatedWithSeveralOwners(BaseGivenContext):
    register_identity: RegisteredIdentity
    delegated_identity: RegisteredIdentity
    proof_owner: Issuer


@dataclass(frozen=True)
class RegisteredIdentitiesForDelegCtx(BaseGivenContext):
    delegating_id: RegisteredIdentity
    delegated_id: RegisteredIdentity
    delegation_name: str


@dataclass(frozen=True)
class RegisteredIdentitiesExistingRegDelegProofCtx(RegisteredIdentitiesForDelegCtx):
    pass


@dataclass(frozen=True)
class RegisteredIdentitiesAddDelegProofCtx(RegisteredIdentitiesExistingRegDelegProofCtx):
    proof: Proof


@dataclass(frozen=True)
class RegisteredIdentityAndControllerCtx(BaseGivenContext):
    owner_identity: RegisteredIdentity
    controller: RegisteredIdentity


@dataclass
class Context:
    given: BaseGivenContext
    when_ret_values = None


def get_new_context(given_ctx) -> Context:
    return Context(given=given_ctx)


def get_registered_identity(name: str, purpose: DIDType = DIDType.TWIN) -> RegisteredIdentityCtx:
    key_name = f'{name}Key'
    identity_secrets = get_secrets_by_type(AdvancedIdentityLocalApi.create_seed(), key_name, purpose)
    if purpose == DIDType.TWIN:
        registered_twin = ADVANCED_API.new_registered_twin_identity(identity_secrets, name)
    elif purpose == DIDType.AGENT:
        registered_twin = ADVANCED_API.new_registered_agent_identity(identity_secrets, name)
    else:
        registered_twin = ADVANCED_API.new_registered_user_identity(identity_secrets, name)
    identity_ctx = RegisteredIdentityCtx(registered_identity=registered_twin, key_name=key_name)
    return identity_ctx


def get_new_identity_keys(name: str) -> KeysCtx:
    secrets = get_secrets_by_type(AdvancedIdentityLocalApi.create_seed(), f'{name}Key', DIDType.TWIN)
    key_pair = KeyPairSecretsHelper.get_key_pair(secrets)
    return KeysCtx(public_key_base58=key_pair.public_base58, identity_name=name)


@given('a registered identity', target_fixture='context')
def given_a_registered_identity():
    return get_new_context(get_registered_identity(name='#ARegIdentity1'))


@given('a registered identity owning the document', target_fixture='context')
def given_a_registered_identity_owning_the_document():
    return get_new_context(get_registered_identity(name='#ARegIdentityOwningDoc1'))


@given('a register document with several owners', target_fixture='context')
def given_a_register_document_with_several_owners():
    initial_owner = get_registered_identity('#Owner1')
    owner2_ctx = get_new_identity_keys(name='#Owner2')
    owner3_ctx = get_new_identity_keys(name='#Owner3')
    IdentityApi(ADVANCED_API).add_new_owner(owner2_ctx.identity_name, owner2_ctx.public_key_base58,
                                            initial_owner.registered_identity)
    IdentityApi(ADVANCED_API).add_new_owner(owner3_ctx.identity_name, owner3_ctx.public_key_base58,
                                            initial_owner.registered_identity)
    initial_owner_key_pair = KeyPairSecretsHelper.get_key_pair(initial_owner.registered_identity.key_pair_secrets)
    owner1_ctx = KeysCtx(public_key_base58=initial_owner_key_pair.public_base58,
                         identity_name=initial_owner.registered_identity.name)
    return get_new_context(DocWithSeveralOwnersCtx(all_owners=[owner1_ctx, owner2_ctx, owner3_ctx],
                                                   registered_identity=initial_owner.registered_identity,
                                                   key_name=initial_owner.key_name))


@given('an register document I owned and a new owner name and public key', target_fixture='context')
def given_an_register_document_i_owned_and_a_new_owner_name_and_public_key():
    initial_owner = get_registered_identity('#OwnerForNewOwner')
    new_owner = get_new_identity_keys(name='#NewOwner')

    return get_new_context(AddNewOwnerCtx(initial_owner_identity=initial_owner, new_owner=new_owner))


@given('an register document I owned and an other existing owner name and public key', target_fixture='context')
def given_an_register_document_i_owned_and_an_other_existing_owner_name_and_public_key():
    initial_owner = get_registered_identity('#IntialOwner')
    other_owner_ctx = get_new_identity_keys(name='#OtherExistingOwner')
    other_existing_owner_issuer = IdentityApi(ADVANCED_API).add_new_owner(other_owner_ctx.identity_name,
                                                                          other_owner_ctx.public_key_base58,
                                                                          initial_owner.registered_identity)
    return get_new_context(OtherExistingOwnerCtx(initial_owner_identity=initial_owner,
                                                 other_existing_owner_issuer=other_existing_owner_issuer))


@given('a register document I owned and a new authentication name and public key', target_fixture='context')
def given_a_register_document_i_owned_and_a_new_authentication_name_and_public_key():
    initial_owner = get_registered_identity('#OwnerForNewAuth')
    auth_key = get_new_identity_keys(name='#NewAuthKey')
    return get_new_context(AddNewAuthKeyCtx(initial_owner_identity=initial_owner,
                                            new_auth_key=auth_key))


@given('a register document I owned and an existing authentication name and public key', target_fixture='context')
def given_a_register_document_i_owned_and_an_existing_authentication_name_and_public_key():
    initial_owner = get_registered_identity('#OwnerForNewAuth')
    owner_key_pair = KeyPairSecretsHelper.get_key_pair(initial_owner.registered_identity.key_pair_secrets)
    existing_auth_key = get_new_identity_keys(name='#ExistingauthKey')
    ADVANCED_API.add_authentication_key_to_document(existing_auth_key.identity_name,
                                                    existing_auth_key.public_key_base58,
                                                    owner_key_pair,
                                                    initial_owner.registered_identity.issuer)
    return get_new_context(OtherExistingAuthKeyCtx(initial_owner_identity=initial_owner,
                                                   existing_auth_key_name=existing_auth_key.identity_name))


@given('a DelegatingRId owning a document and a DelegatedRId',
       target_fixture='context')
def given_a_register_identity_ida_owning_the_delegating_doc_and_a_register_identity_delegated_doc():
    delegating_id = get_registered_identity('#Delegating')
    delegated_id = get_registered_identity('#Delegated')
    return get_new_context(RegisteredIdentitiesForDelegCtx(
        delegating_id=delegating_id.registered_identity,
        delegated_id=delegated_id.registered_identity,
        delegation_name='#NewDelegation'
    ))


@given('a DelegatingRId owning a document and a delegation proof created by a DelegatedRId', target_fixture='context')
def given_a_reg_identity_ida_owning_the_delegating_doc_and_a_delegation_proof_created_by_an_other_registered_identity():
    delegating_id = get_registered_identity('#Delegating')
    delegated_id = get_registered_identity('#Delegated')
    subject_doc = ADVANCED_API.get_register_document(delegated_id.registered_identity.did)
    subject_issuer, delegation_proof = AdvancedIdentityLocalApi.create_delegation_proof(
        delegating_issuer=delegating_id.registered_identity.issuer,
        subject_doc=subject_doc,
        subject_secrets=delegated_id.registered_identity.key_pair_secrets)
    return get_new_context(RegisteredIdentitiesAddDelegProofCtx(
        delegating_id=delegating_id.registered_identity,
        delegated_id=delegated_id.registered_identity,
        proof=delegation_proof,
        delegation_name='#DelegFromPRoof'
    ))


@given('a DelegatingRId owning a document with a control delegation proof created by a DelegatedRId',
       target_fixture='context')
def given_a_register_identity_ida_owning_the_delegating_doc_with_a_ctrl_deleg_proof_created_by_an_other_reg_identity():
    delegating_id = get_registered_identity('#Delegating')
    delegated_id = get_registered_identity('#Delegated')
    subject_doc = ADVANCED_API.get_register_document(delegated_id.registered_identity.did)
    subject_issuer, delegation_proof = AdvancedIdentityLocalApi.create_delegation_proof(
        delegating_issuer=delegating_id.registered_identity.issuer,
        subject_doc=subject_doc,
        subject_secrets=delegated_id.registered_identity.key_pair_secrets)
    delegation_name = '#DelegFromPRoof'

    owner_key_pai = KeyPairSecretsHelper.get_key_pair(delegating_id.registered_identity.key_pair_secrets)
    ADVANCED_API.add_control_delegation_proof_to_document(delegation_proof,
                                                          subject_issuer,
                                                          delegation_name,
                                                          doc_owner_issuer=delegating_id.registered_identity.issuer,
                                                          doc_owner_key_pair=owner_key_pai)
    return get_new_context(RegisteredIdentitiesExistingRegDelegProofCtx(
        delegating_id=delegating_id.registered_identity,
        delegated_id=delegated_id.registered_identity,
        delegation_name=delegation_name
    ))


@given('a DelegatingRId owning a document with an auth delegation proof created by a DelegatedRId',
       target_fixture='context')
def given_a_register_identity_ida_owning_the_delegating_doc_with_a_auth_deleg_proof_created_by_an_other_reg_identity():
    delegating_id = get_registered_identity('#Delegating')
    delegated_id = get_registered_identity('#Delegated')
    subject_doc = ADVANCED_API.get_register_document(delegated_id.registered_identity.did)
    subject_issuer, delegation_proof = AdvancedIdentityLocalApi.create_delegation_proof(
        delegating_issuer=delegating_id.registered_identity.issuer,
        subject_doc=subject_doc,
        subject_secrets=delegated_id.registered_identity.key_pair_secrets)
    delegation_name = '#DelegFromPRoof'

    owner_secrets = KeyPairSecretsHelper.get_key_pair(delegating_id.registered_identity.key_pair_secrets)
    ADVANCED_API.add_authentication_delegation_proof_to_document(delegation_proof,
                                                                 subject_issuer,
                                                                 delegation_name,
                                                                 delegating_id.registered_identity.issuer,
                                                                 owner_secrets)
    return get_new_context(RegisteredIdentitiesExistingRegDelegProofCtx(
        delegating_id=delegating_id.registered_identity,
        delegated_id=delegated_id.registered_identity,
        delegation_name=delegation_name
    ))


@given('a registered identity owning a document and a controller (registered identity)', target_fixture='context')
def given_a_register_doc_and_a_controller():
    owner_identity = get_registered_identity('#AnIdentity')
    controller_identity = get_registered_identity('#Controller')

    return get_new_context(RegisteredIdentityAndControllerCtx(
        owner_identity=owner_identity.registered_identity,
        controller=controller_identity.registered_identity
    ))


@given('a DelegatingRId owning a document with an auth delegation proof created by a DelegatedRId with several owner',
       target_fixture='context')
def given_a_register_id_and_auth_delegated_several_owner():
    delegating_id = get_registered_identity('#Delegating')
    delegated_id = get_registered_identity('#Delegated')
    other_owner_secrets = get_secrets_by_type(AdvancedIdentityLocalApi.create_seed(), 'OtherOwnerKey', DIDType.TWIN)
    other_owner_key_pair = KeyPairSecretsHelper.get_key_pair(other_owner_secrets)
    other_owner_name = '#OtherOWner'
    other_existing_owner_issuer = IdentityApi(ADVANCED_API).add_new_owner(other_owner_name,
                                                                          other_owner_key_pair.public_base58,
                                                                          delegated_id.registered_identity)
    ADVANCED_API.delegate_authentication(delegating_secrets=delegating_id.registered_identity.key_pair_secrets,
                                         delegating_did=delegating_id.registered_identity.did,
                                         subject_secrets=other_owner_secrets,
                                         subject_did=delegated_id.registered_identity.did,
                                         delegation_name='#AnAuthDeleg')

    return get_new_context(RegisterIdentityAndControlDelegatedWithSeveralOwners(
        register_identity=delegating_id.registered_identity,
        delegated_identity=delegated_id.registered_identity,
        proof_owner=other_existing_owner_issuer
    ))


@given('a DelegatingRId owning a document with a control delegation proof created by a DelegatedRId with several owner',
       target_fixture='context')
def given_a_register_id_and_control_delegated_several_owner():
    delegating_id = get_registered_identity('#Delegating')
    delegated_id = get_registered_identity('#Delegated')
    other_owner_secrets = get_secrets_by_type(AdvancedIdentityLocalApi.create_seed(), 'OtherOwnerKey', DIDType.TWIN)
    other_owner_key_pair = KeyPairSecretsHelper.get_key_pair(other_owner_secrets)
    other_owner_name = '#OtherOWner'
    other_existing_owner_issuer = IdentityApi(ADVANCED_API).add_new_owner(other_owner_name,
                                                                          other_owner_key_pair.public_base58,
                                                                          delegated_id.registered_identity)
    ADVANCED_API.delegate_control(delegating_secrets=delegating_id.registered_identity.key_pair_secrets,
                                  delegating_did=delegating_id.registered_identity.did,
                                  subject_secrets=other_owner_secrets,
                                  subject_did=delegated_id.registered_identity.did,
                                  delegation_name='#ACtrlhDeleg')

    return get_new_context(RegisterIdentityAndControlDelegatedWithSeveralOwners(
        register_identity=delegating_id.registered_identity,
        delegated_identity=delegated_id.registered_identity,
        proof_owner=other_existing_owner_issuer
    ))


@when('I get the associated document')
def when_i_get_the_associated_document(context: Context):
    given_ctx: RegisteredIdentityCtx = context.given
    register_doc = ADVANCED_API.get_register_document(given_ctx.registered_identity.did)
    context.when_ret_values = register_doc


@when('I check if the registered identity is allowed for control and authentication on the associated document')
def when_i_check_if_the_registered_identity_is_allowed_for_control_and_authentication_on_the_associated_document(
        context: Context):
    given_ctx: RegisteredIdentityCtx = context.given
    context.when_ret_values = get_allowed_for_auth_and_control_error(RESOLVER_CLIENT,
                                                                     given_ctx.registered_identity.issuer,
                                                                     given_ctx.registered_identity.did)


@when('I add the new owner to the document')
def when_i_add_the_new_owner_to_the_document(context: Context):
    given_ctx: AddNewOwnerCtx = context.given
    owner_secrets = given_ctx.initial_owner_identity.registered_identity.key_pair_secrets
    owner_keys = KeyPairSecretsHelper.get_key_pair(owner_secrets)
    owner_issuer = given_ctx.initial_owner_identity.registered_identity.issuer
    new_owner_issuer = ADVANCED_API.add_public_key_to_document(given_ctx.new_owner.identity_name,
                                                               given_ctx.new_owner.public_key_base58, owner_keys,
                                                               owner_issuer)
    context.when_ret_values = new_owner_issuer


@when('I remove the other owner from the document')
def when_i_remove_the_other_owner_from_the_document(context: Context):
    given_ctx: OtherExistingOwnerCtx = context.given
    owner_secrets = given_ctx.initial_owner_identity.registered_identity.key_pair_secrets
    owner_keys = KeyPairSecretsHelper.get_key_pair(owner_secrets)
    owner_issuer = given_ctx.initial_owner_identity.registered_identity.issuer
    removed_owner_issuer = ADVANCED_API.remove_public_key_from_document(given_ctx.other_existing_owner_issuer,
                                                                        owner_keys,
                                                                        owner_issuer)
    context.when_ret_values = removed_owner_issuer


@when('I revoke the other owner key')
def when_i_revoke_the_other_owner_key(context: Context):
    given_ctx: OtherExistingOwnerCtx = context.given
    owner_secrets = given_ctx.initial_owner_identity.registered_identity.key_pair_secrets
    owner_keys = KeyPairSecretsHelper.get_key_pair(owner_secrets)
    owner_issuer = given_ctx.initial_owner_identity.registered_identity.issuer
    revoked_owner_issuer = ADVANCED_API.revoke_public_key_from_document(given_ctx.other_existing_owner_issuer.name,
                                                                        revoked=True,
                                                                        doc_owner_key_pair=owner_keys,
                                                                        doc_owner_issuer=owner_issuer)
    context.when_ret_values = revoked_owner_issuer


@when('I add the new authentication key to the document')
def when_i_add_the_new_authentication_key_to_the_document(context: Context):
    given_ctx: AddNewAuthKeyCtx = context.given
    owner_secrets = given_ctx.initial_owner_identity.registered_identity.key_pair_secrets
    owner_keys = KeyPairSecretsHelper.get_key_pair(owner_secrets)
    owner_issuer = given_ctx.initial_owner_identity.registered_identity.issuer
    new_key_issuer = ADVANCED_API.add_authentication_key_to_document(given_ctx.new_auth_key.identity_name,
                                                                     given_ctx.new_auth_key.public_key_base58,
                                                                     owner_keys,
                                                                     owner_issuer)
    context.when_ret_values = new_key_issuer


@when('I remove the authentication key from the document')
def when_i_remove_the_authentication_key_from_the_document(context: Context):
    given_ctx: OtherExistingAuthKeyCtx = context.given
    owner_secrets = given_ctx.initial_owner_identity.registered_identity.key_pair_secrets
    owner_keys = KeyPairSecretsHelper.get_key_pair(owner_secrets)
    owner_issuer = given_ctx.initial_owner_identity.registered_identity.issuer
    removed_key_issuer = ADVANCED_API.remove_authentication_key_from_document(given_ctx.existing_auth_key_name,
                                                                              owner_keys,
                                                                              owner_issuer)
    context.when_ret_values = removed_key_issuer


@when('I revoke the authentication key')
def when_i_revoke_the_authentication_key(context: Context):
    given_ctx: OtherExistingAuthKeyCtx = context.given
    owner_secrets = given_ctx.initial_owner_identity.registered_identity.key_pair_secrets
    owner_keys = KeyPairSecretsHelper.get_key_pair(owner_secrets)
    owner_issuer = given_ctx.initial_owner_identity.registered_identity.issuer
    revoked_key_issuer = ADVANCED_API.revoke_authentication_key_from_document(given_ctx.existing_auth_key_name,
                                                                              revoked=True,
                                                                              doc_owner_key_pair=owner_keys,
                                                                              doc_owner_issuer=owner_issuer)
    context.when_ret_values = revoked_key_issuer


@when('the DelegatingRId delegates control to the DelegatedRId')
def when_ida_delegates_control_to_delegated_doc(context: Context):
    given_ctx: RegisteredIdentitiesForDelegCtx = context.given
    ADVANCED_API.delegate_control(delegating_secrets=given_ctx.delegating_id.key_pair_secrets,
                                  delegating_did=given_ctx.delegating_id.did,
                                  subject_secrets=given_ctx.delegated_id.key_pair_secrets,
                                  subject_did=given_ctx.delegated_id.did,
                                  delegation_name=given_ctx.delegation_name)


@when('I add the control delegation proof to the document owned by the DelegatingRId')
def when_i_add_the_control_delegation_proof_to_the_document(context: Context):
    given_ctx: RegisteredIdentitiesAddDelegProofCtx = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegating_id.key_pair_secrets)
    ADVANCED_API.add_control_delegation_proof_to_document(proof=given_ctx.proof,
                                                          subject_issuer=given_ctx.delegated_id.issuer,
                                                          delegation_name=given_ctx.delegation_name,
                                                          doc_owner_issuer=given_ctx.delegating_id.issuer,
                                                          doc_owner_key_pair=key_pair)


@when('I remove the control delegation proof from the document owned by the DelegatingRId')
def when_i_remove_the_control_delegation_proof_from_the_document(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegating_id.key_pair_secrets)
    ADVANCED_API.remove_control_delegation_proof_from_document(delegation_name=given_ctx.delegation_name,
                                                               doc_owner_issuer=given_ctx.delegating_id.issuer,
                                                               doc_owner_key_pair=key_pair)


@when('I revoke the control delegation proof')
def when_i_revoke_the_control_delegation_proof(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegating_id.key_pair_secrets)
    ADVANCED_API.revoke_control_delegation_proof_from_document(delegation_name=given_ctx.delegation_name,
                                                               revoked=True,
                                                               doc_owner_issuer=given_ctx.delegating_id.issuer,
                                                               doc_owner_key_pair=key_pair)


@when('the DelegatingRId delegates authentication to the DelegatedRId')
def when_ida_delegates_authentication_to_delegated_doc(context: Context):
    given_ctx: RegisteredIdentitiesForDelegCtx = context.given
    ADVANCED_API.delegate_authentication(delegating_secrets=given_ctx.delegating_id.key_pair_secrets,
                                         delegating_did=given_ctx.delegating_id.did,
                                         subject_secrets=given_ctx.delegated_id.key_pair_secrets,
                                         subject_did=given_ctx.delegated_id.did,
                                         delegation_name=given_ctx.delegation_name)


@when('I add the authentication delegation proof to the document owned by the DelegatingRId')
def when_i_add_the_authentication_delegation_proof_to_the_document(context: Context):
    given_ctx: RegisteredIdentitiesAddDelegProofCtx = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegating_id.key_pair_secrets)
    ADVANCED_API.add_authentication_delegation_proof_to_document(proof=given_ctx.proof,
                                                                 subject_issuer=given_ctx.delegated_id.issuer,
                                                                 delegation_name=given_ctx.delegation_name,
                                                                 doc_owner_issuer=given_ctx.delegating_id.issuer,
                                                                 doc_owner_key_pair=key_pair)


@when('I remove the authentication delegation proof from the document owned by the DelegatingRId')
def when_i_remove_the_authentication_delegation_proof_from_the_document(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegating_id.key_pair_secrets)
    ADVANCED_API.remove_authentication_delegation_proof_from_document(delegation_name=given_ctx.delegation_name,
                                                                      doc_owner_issuer=given_ctx.delegating_id.issuer,
                                                                      doc_owner_key_pair=key_pair)


@when('I revoke the authentication delegation proof')
def when_i_revoke_the_authentication_delegation_proof(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegating_id.key_pair_secrets)
    ADVANCED_API.revoke_authentication_delegation_proof_from_document(delegation_name=given_ctx.delegation_name,
                                                                      revoked=True,
                                                                      doc_owner_issuer=given_ctx.delegating_id.issuer,
                                                                      doc_owner_key_pair=key_pair)


@when('I set the controller on my document')
def when_i_set_the_controller(context: Context):
    given_ctx: RegisteredIdentityAndControllerCtx = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.owner_identity.key_pair_secrets)
    ADVANCED_API.set_document_controller(controller=given_ctx.controller.issuer,
                                         doc_owner_key_pair=key_pair,
                                         doc_owner_issuer=given_ctx.owner_identity.issuer)


@when('the DelegatedRId owner used for the proof is revoked')
def when_the_delegated_id_owner_proof_is_revoked(context: Context):
    given_ctx: RegisterIdentityAndControlDelegatedWithSeveralOwners = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegated_identity.key_pair_secrets)
    ADVANCED_API.revoke_public_key_from_document(given_ctx.proof_owner.name,
                                                 revoked=True,
                                                 doc_owner_key_pair=key_pair,
                                                 doc_owner_issuer=given_ctx.delegated_identity.issuer)


@when('the DelegatedRId owner used for the proof is removed')
def when_the_delegated_id_owner_proof_is_removed(context: Context):
    given_ctx: RegisterIdentityAndControlDelegatedWithSeveralOwners = context.given
    key_pair = KeyPairSecretsHelper.get_key_pair(given_ctx.delegated_identity.key_pair_secrets)
    ADVANCED_API.remove_public_key_from_document(given_ctx.proof_owner,
                                                 existing_doc_owner_key_pair=key_pair,
                                                 existing_doc_owner_issuer=given_ctx.delegated_identity.issuer)


@then('the registered identity issuer did is equal to the document did')
def then_the_registered_identity_issuer_did_is_equal_to_the_document_did(context: Context):
    given_ctx: RegisteredIdentityCtx = context.given
    register_doc = context.when_ret_values
    assert register_doc.did == given_ctx.registered_identity.did, 'Register doc did should be equal to the ' \
                                                                  'registered identity did'


@then('the register document has the registered identity public key')
def then_the_register_document_has_the_identity_public_key(context: Context):
    given_ctx: RegisteredIdentityCtx = context.given
    register_doc = context.when_ret_values
    assert register_doc.public_keys.get(given_ctx.registered_identity.name), \
        'Owner public key name must belongs to the document public keys'
    assert_owner_key(register_doc, given_ctx.registered_identity.name, given_ctx.registered_identity)


@then('the registered identity is allowed')
def then_the_registered_identity_is_allowed(context: Context):
    is_allowed_fron_control_and_aut_error = context.when_ret_values
    assert not is_allowed_fron_control_and_aut_error, 'Owner registered identity should be allowed for ' \
                                                      'authentication and control on the owned document'


@then('the register document has several public keys')
def then_the_register_document_has_several_public_keys(context: Context):
    given_ctx: DocWithSeveralOwnersCtx = context.given
    register_doc = context.when_ret_values
    assert len(register_doc.public_keys) == len(given_ctx.all_owners)
    for owner_ctx in given_ctx.all_owners:
        assert_owner_pub_key_exist(register_doc, owner_ctx.identity_name, owner_ctx.public_key_base58)


@then('the new owner is allowed for authentication and control on the document')
def then_the_new_owner_is_allowed_for_authentication_and_control_on_the_document(context: Context):
    given_ctx: AddNewOwnerCtx = context.given
    doc_did = given_ctx.initial_owner_identity.registered_identity.did
    new_owner_issuer = context.when_ret_values
    assert new_owner_issuer.did == given_ctx.initial_owner_identity.registered_identity.did
    assert new_owner_issuer.name == given_ctx.new_owner.identity_name

    doc = ADVANCED_API.get_register_document(doc_did)
    assert doc.public_keys.get(new_owner_issuer.name), 'New owner key should belong to the register doc public keys'
    assert_owner_is_allowed(RESOLVER_CLIENT, new_owner_issuer, doc_did)
    assert doc.public_keys.get(given_ctx.initial_owner_identity.registered_identity.name), 'Initial owner key should ' \
                                                                                           'still belong to the ' \
                                                                                           'register doc public keys'
    assert_owner_is_allowed(RESOLVER_CLIENT, given_ctx.initial_owner_identity.registered_identity.issuer, doc_did)


@then('the removed owner is not allowed for authentication or control on the document')
def then_the_removed_owner_is_not_allowed_for_authentication_or_control_on_the_document(context: Context):
    given_ctx: OtherExistingOwnerCtx = context.given
    initial_owner_id = given_ctx.initial_owner_identity.registered_identity
    doc_did = initial_owner_id.did
    removed_owner_issuer = context.when_ret_values
    assert removed_owner_issuer.did == initial_owner_id.did
    assert removed_owner_issuer == given_ctx.other_existing_owner_issuer

    doc = ADVANCED_API.get_register_document(doc_did)
    assert not doc.public_keys.get(removed_owner_issuer.name), 'Removed owner key should NOT belong to the register ' \
                                                               'doc public keys anymore'
    assert_owner_not_allowed_anymore(RESOLVER_CLIENT, removed_owner_issuer, doc_did)
    assert doc.public_keys.get(initial_owner_id.name), 'Initial owner key should still belong to the register doc ' \
                                                       'public keys'
    assert_owner_is_allowed(RESOLVER_CLIENT, initial_owner_id.issuer, doc_did)


@then('the revoked owner is not allowed for authentication or control on the document')
def then_the_revoked_owner_is_not_allowed_for_authentication_or_control_on_the_document(context: Context):
    given_ctx: OtherExistingOwnerCtx = context.given
    initial_owner_id = given_ctx.initial_owner_identity.registered_identity
    doc_did = initial_owner_id.did
    revoked_owner_issuer = context.when_ret_values
    assert revoked_owner_issuer.did == initial_owner_id.did
    assert revoked_owner_issuer == given_ctx.other_existing_owner_issuer

    doc = ADVANCED_API.get_register_document(doc_did)
    assert doc.public_keys.get(revoked_owner_issuer.name).revoked, 'Revoked owner key should be revoked'
    assert_owner_not_allowed_anymore(RESOLVER_CLIENT, revoked_owner_issuer, doc_did)
    assert not doc.public_keys.get(initial_owner_id.name).revoked, 'Initial owner key should NOT be revoked'
    assert_owner_is_allowed(RESOLVER_CLIENT, initial_owner_id.issuer, doc_did)


@then('the authentication key owner is allowed for authentication on the document')
def then_the_authentication_key_owner_is_allowed_for_authentication_on_the_document(context: Context):
    given_ctx: AddNewAuthKeyCtx = context.given
    doc_did = given_ctx.initial_owner_identity.registered_identity.did
    new_key_issuer = context.when_ret_values
    assert new_key_issuer.did == given_ctx.initial_owner_identity.registered_identity.did
    assert new_key_issuer.name == given_ctx.new_auth_key.identity_name

    doc = ADVANCED_API.get_register_document(doc_did)
    assert doc.auth_keys.get(new_key_issuer.name), 'New auth key should belongs to the register doc auth keys'
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT, new_key_issuer, doc_did)
    assert not allowed_for_auth_err, 'New auth key issuer should be allowed for authentication'
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT, new_key_issuer, doc_did)
    assert allowed_for_control_err, 'New auth key issuer should NOT be allowed for control'


@then('the removed authentication key owner is not allowed for authentication on the document')
def then_the_removed_authentication_key_owner_is_not_allowed_for_authentication_on_the_document(context: Context):
    given_ctx: OtherExistingAuthKeyCtx = context.given
    doc_did = given_ctx.initial_owner_identity.registered_identity.did
    removed_key_issuer = context.when_ret_values
    assert removed_key_issuer.did == given_ctx.initial_owner_identity.registered_identity.did
    assert removed_key_issuer.name == given_ctx.existing_auth_key_name

    doc = ADVANCED_API.get_register_document(doc_did)
    assert not doc.auth_keys.get(removed_key_issuer.name), 'New auth key should NOT belongs to the register ' \
                                                           'doc auth keys'
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT, removed_key_issuer, doc_did)
    assert allowed_for_auth_err, 'Removed auth key issuer should NOT be allowed for authentication'
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT, removed_key_issuer, doc_did)
    assert allowed_for_control_err, 'Removed auth key issuer should NOT be allowed for control'


@then('the revoked authentication key owner is not allowed for authentication on the document')
def then_the_revoked_authentication_key_owner_is_not_allowed_for_authentication_on_the_document(context: Context):
    given_ctx: OtherExistingAuthKeyCtx = context.given
    doc_did = given_ctx.initial_owner_identity.registered_identity.did
    revoked_key_issuer = context.when_ret_values
    assert revoked_key_issuer.did == given_ctx.initial_owner_identity.registered_identity.did
    assert revoked_key_issuer.name == given_ctx.existing_auth_key_name

    doc = ADVANCED_API.get_register_document(doc_did)
    assert doc.auth_keys.get(revoked_key_issuer.name).revoked, 'Revoked auth key should be revoked'
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT, revoked_key_issuer, doc_did)
    assert allowed_for_auth_err, 'Revoked auth key issuer should NOT be allowed for authentication'
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT, revoked_key_issuer, doc_did)
    assert allowed_for_control_err, 'Revoked auth key issuer should NOT be allowed for control'


@then('the DelegatedRId is allowed for control on the document owned by the DelegatingRId')
def then_delegated_doc_is_allowed_for_control_on_the_delegating_doc(context: Context):
    given_ctx: RegisteredIdentitiesForDelegCtx = context.given
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT,
                                                            issuer=given_ctx.delegated_id.issuer,
                                                            doc_id=given_ctx.delegating_id.did)
    delegating_doc = ADVANCED_API.get_register_document(given_ctx.delegating_id.did)
    assert delegating_doc.control_delegation_proof.get(given_ctx.delegation_name), 'New delegation key ' \
                                                                                   'should belong to the ' \
                                                                                   'register doc ' \
                                                                                   'control delegation keys'
    assert not allowed_for_control_err, 'Delegated registered identity with control delegation should be allowed ' \
                                        'for control on document owned by the delegating registered identity'


@then('the DelegatedRId is still allowed for control on the document owned by the DelegatingRId')
def then_the_other_registered_identity_is_still_allowed_for_control_on_the_document(context: Context):
    given_ctx: RegisterIdentityAndControlDelegatedWithSeveralOwners = context.given
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT,
                                                            issuer=given_ctx.proof_owner,
                                                            doc_id=given_ctx.register_identity.did)
    delegated_doc = ADVANCED_API.get_register_document(given_ctx.delegated_identity.did)
    assert delegated_doc.public_keys[given_ctx.proof_owner.name].revoked
    assert not allowed_for_control_err, 'Delegated registered identity with control delegation should still be ' \
                                        'allowed for control on document owned by the delegating registered identity'


@then('the DelegatedRId is not allowed for control on the document owned by the DelegatingRId after delegation remove')
def then_the_removed_registered_identity_is_not_allowed_for_control_on_the_document(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT,
                                                            issuer=given_ctx.delegated_id.issuer,
                                                            doc_id=given_ctx.delegating_id.did)
    delegating_doc = ADVANCED_API.get_register_document(given_ctx.delegating_id.did)
    assert not delegating_doc.control_delegation_proof.get(given_ctx.delegation_name), 'Removed delegation key ' \
                                                                                       'should NOT belong to the ' \
                                                                                       'register doc ' \
                                                                                       'control delegation keys'

    assert allowed_for_control_err, 'Delegated registered identity with removed control delegation should NOT be ' \
                                    'allowed for control on document owned by the delegating registered identity'


@then('the DelegatedRId is not allowed for control on the document owned by the DelegatingRId after delegation revoke')
def then_the_revoked_registered_identity_is_not_allowed_for_control_on_the_document(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT,
                                                            issuer=given_ctx.delegated_id.issuer,
                                                            doc_id=given_ctx.delegating_id.did)
    delegating_doc = ADVANCED_API.get_register_document(given_ctx.delegating_id.did)
    deleg_name = given_ctx.delegation_name
    assert delegating_doc.control_delegation_proof.get(deleg_name).revoked, f'Control delegation key {deleg_name} ' \
                                                                            f'should be revoked'

    assert allowed_for_control_err, 'Delegated registered identity with revoked control delegation should NOT be ' \
                                    'allowed for control on document owned by the delegating registered identity'


@then('the DelegatedRId is allowed for authentication on the document owned by the DelegatingRId')
def then_delegated_doc_is_allowed_for_authentication_on_the_delegating_doc(context: Context):
    given_ctx: RegisteredIdentitiesForDelegCtx = context.given
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT, given_ctx.delegated_id.issuer,
                                                      doc_id=given_ctx.delegating_id.did)
    delegating_doc = ADVANCED_API.get_register_document(given_ctx.delegating_id.did)
    assert delegating_doc.auth_delegation_proof.get(given_ctx.delegation_name), 'New delegation key ' \
                                                                                'should belong to the ' \
                                                                                'register doc ' \
                                                                                'auth delegation keys'
    assert not allowed_for_auth_err, 'Delegated registered identity with authentication delegation should be allowed ' \
                                     'for authentication on document owned by the delegating registered identity'


@then('the DelegatedRId is still allowed for authentication on the document owned by the DelegatingRId')
def then_the_other_registered_identity_is_still_allowed_for_authentication_on_the_document(context: Context):
    given_ctx: RegisterIdentityAndControlDelegatedWithSeveralOwners = context.given
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT,
                                                      issuer=given_ctx.proof_owner,
                                                      doc_id=given_ctx.register_identity.did)
    delegated_doc = ADVANCED_API.get_register_document(given_ctx.delegated_identity.did)
    assert delegated_doc.public_keys[given_ctx.proof_owner.name].revoked

    assert not allowed_for_auth_err, 'Delegated registered identity with authentication delegation should still be ' \
                                     'allowed for authentication on document owned by the delegating registered ' \
                                     'identity'


@then('the DelegatedRId is not allowed for authentication on the document owned by the DelegatingRId after '
      'delegation remove')
def then_the_removed_registered_identity_is_not_allowed_for_authentication_on_the_document(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT,
                                                      issuer=given_ctx.delegated_id.issuer,
                                                      doc_id=given_ctx.delegating_id.did)
    delegating_doc = ADVANCED_API.get_register_document(given_ctx.delegating_id.did)
    assert not delegating_doc.auth_delegation_proof.get(given_ctx.delegation_name), 'Removed delegation key ' \
                                                                                    'should NOT belong to the ' \
                                                                                    'register doc ' \
                                                                                    'control delegation keys'

    assert allowed_for_auth_err, 'Delegated registered identity with authentication delegation should NOT be allowed ' \
                                 'for authentication on document owned by the delegating registered identity'


@then('the DelegatedRId is not allowed for authentication on the document owned by the DelegatingRId '
      'after delegation revoke')
def then_the_revoked_registered_identity_is_not_allowed_for_authentication_on_the_document(context: Context):
    given_ctx: RegisteredIdentitiesExistingRegDelegProofCtx = context.given
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT,
                                                      issuer=given_ctx.delegated_id.issuer,
                                                      doc_id=given_ctx.delegating_id.did)
    delegating_doc = ADVANCED_API.get_register_document(given_ctx.delegating_id.did)
    deleg_name = given_ctx.delegation_name
    assert delegating_doc.auth_delegation_proof.get(deleg_name).revoked, f'Control delegation key {deleg_name} ' \
                                                                         f'should be revoked'
    assert allowed_for_auth_err, 'Delegated registered identity with authentication delegation should NOT be allowed ' \
                                 'for authentication on document owned by the delegating registered identity'


@then('the DelegatedRId is not allowed for control on the document owned by the DelegatingRId anymore')
def then_the_other_registered_identity_is_not_allowed_for_control_anymore_on_the_document(context: Context):
    given_ctx: RegisterIdentityAndControlDelegatedWithSeveralOwners = context.given
    allowed_for_control_err = get_allowed_for_control_error(RESOLVER_CLIENT,
                                                            issuer=given_ctx.proof_owner,
                                                            doc_id=given_ctx.register_identity.did)
    delegated_doc = ADVANCED_API.get_register_document(given_ctx.delegated_identity.did)
    assert not delegated_doc.public_keys.get(given_ctx.proof_owner.name)

    assert allowed_for_control_err, 'Delegated registered identity with control delegation should NOT be ' \
                                    'allowed for control on document owned by the delegating registered ' \
                                    'identity anymore'


@then('the DelegatedRId is not allowed for authentication on the document owned by the DelegatingRId anymore')
def then_the_other_registered_identity_is_not_allowed_for_authentication_anymore_on_the_document(context: Context):
    given_ctx: RegisterIdentityAndControlDelegatedWithSeveralOwners = context.given
    allowed_for_auth_err = get_allowed_for_auth_error(RESOLVER_CLIENT,
                                                      issuer=given_ctx.proof_owner,
                                                      doc_id=given_ctx.register_identity.did)
    delegated_doc = ADVANCED_API.get_register_document(given_ctx.delegated_identity.did)
    assert not delegated_doc.public_keys.get(given_ctx.proof_owner.name)

    assert allowed_for_auth_err, 'Delegated registered identity with authentication delegation should NOT be ' \
                                 'allowed for authentication on document owned by the delegating registered ' \
                                 'identity anymore'


@then('the controller is allowed for control and authentication')
def then_the_controller_is_allowed_for_ctrl_and_auth(context: Context):
    given_ctx: RegisteredIdentityAndControllerCtx = context.given
    doc = ADVANCED_API.get_register_document(given_ctx.owner_identity.did)
    assert doc.controller == given_ctx.controller.issuer
    allowed_for_control_error = get_allowed_for_control_error(RESOLVER_CLIENT,
                                                              issuer=given_ctx.controller.issuer,
                                                              doc_id=given_ctx.owner_identity.did)
    assert not allowed_for_control_error, 'Controller should be allowed for control'
    allowed_for_auth_error = get_allowed_for_auth_error(RESOLVER_CLIENT,
                                                        issuer=given_ctx.controller.issuer,
                                                        doc_id=given_ctx.owner_identity.did)
    assert not allowed_for_auth_error, 'Controller should be allowed for authentication'


@scenario('advanced_identity_api.feature', 'Get a register document from a registered identity',
          features_base_dir=FEATURES)
def test_get_a_register_document_from_a_registered_identity():
    pass


@scenario('advanced_identity_api.feature', 'Register identity owning the document is in the document public key',
          features_base_dir=FEATURES)
def test_register_identity_owning_the_document_is_in_the_document_public_key():
    pass


@scenario('advanced_identity_api.feature',
          'Register identity owning the document is allowed for control and authentication', features_base_dir=FEATURES)
def test_register_identity_owning_the_document_is_allowed_for_control_and_authentication():
    pass


@scenario('advanced_identity_api.feature', 'Several registered identity can belong to the same document',
          features_base_dir=FEATURES)
def test_several_registered_identity_can_belong_to_the_same_document():
    pass


@scenario('advanced_identity_api.feature', 'Add a register document owner', features_base_dir=FEATURES)
def test_add_a_register_document_owner():
    pass


@scenario('advanced_identity_api.feature', 'Remove a register document owner', features_base_dir=FEATURES)
def test_remove_a_register_document_owner():
    pass


@scenario('advanced_identity_api.feature', 'Revoke a register document owner', features_base_dir=FEATURES)
def test_revoke_a_register_document_owner():
    pass


@scenario('advanced_identity_api.feature', 'Add an authentication key to a register document',
          features_base_dir=FEATURES)
def test_add_an_authentication_key_to_a_register_document():
    pass


@scenario('advanced_identity_api.feature', 'Remove an authentication key from a register document',
          features_base_dir=FEATURES)
def test_remove_an_authentication_key_from_a_register_document():
    pass


@scenario('advanced_identity_api.feature', 'Revoke an authentication key', features_base_dir=FEATURES)
def test_revoke_an_authentication_key():
    pass


@scenario('advanced_identity_api.feature', 'Add a control delegation between 2 existing registered identities',
          features_base_dir=FEATURES)
def test_add_a_control_delegation_between_2_existing_registered_identities():
    pass


@scenario('advanced_identity_api.feature',
          'Add a control delegation proof (created by an other registered identity) to a document',
          features_base_dir=FEATURES)
def test_add_a_control_delegation_proof_from_an_other_registered_identity_to_a_document():
    pass


@scenario('advanced_identity_api.feature', 'Remove a control delegation proof from a register document',
          features_base_dir=FEATURES)
def test_remove_a_control_delegation_proof_from_a_register_document():
    pass


@scenario('advanced_identity_api.feature', 'Revoke a control delegation proof', features_base_dir=FEATURES)
def test_revoke_a_control_delegation_proof():
    pass


@scenario('advanced_identity_api.feature', 'Add an authentication delegation between 2 existing registered identities',
          features_base_dir=FEATURES)
def test_add_an_authentication_delegation_between_2_existing_registered_identities():
    pass


@scenario('advanced_identity_api.feature',
          'Add an authentication delegation proof (created by an other registered identity) to a document',
          features_base_dir=FEATURES)
def test_add_an_authentication_delegation_proof_from_an_other_registered_identity_to_a_document():
    pass


@scenario('advanced_identity_api.feature', 'Remove an authentication delegation proof from a register document',
          features_base_dir=FEATURES)
def test_remove_an_authentication_delegation_proof_from_a_register_document():
    pass


@scenario('advanced_identity_api.feature', 'Revoke an authentication delegation proof', features_base_dir=FEATURES)
def test_revoke_an_authentication_delegation_proof():
    pass


@scenario('advanced_identity_api.feature', 'Document controller is allowed for auth and control',
          features_base_dir=FEATURES)
def test_controller_allowed_for_auth_and_control():
    pass


@scenario('advanced_identity_api.feature', 'Authentication delegation is still valid if the delegated identity has '
                                           'several owners and the key used in the proof is revoked',
          features_base_dir=FEATURES)
def test_auth_deleg_still_valid():
    pass


@scenario('advanced_identity_api.feature', 'Authentication delegation is not valid if the delegated identity has '
                                           'several owners and the key used in the proof is removed',
          features_base_dir=FEATURES)
def test_auth_deleg_not_valid_anymore():
    pass


@scenario('advanced_identity_api.feature', 'Control delegation is still valid if the delegated identity has '
                                           'several owners and the key used in the proof is revoked',
          features_base_dir=FEATURES)
def test_control_deleg_still_valid():
    pass


@scenario('advanced_identity_api.feature', 'Control delegation is not valid if the delegated identity has '
                                           'several owners and the key used in the proof is removed',
          features_base_dir=FEATURES)
def test_control_deleg_not_valid_anymore():
    pass
