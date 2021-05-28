# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
import secrets
from typing import Callable, Optional, Tuple

from iotics.lib.identity.api.advanced_api_keys import RegisterAuthDelegPublicDocKeysApi, RegisterAuthPublicDocKeysApi, \
    RegisterCtrlDelegPublicDocKeysApi, RegisterPublicDocKeysApi
from iotics.lib.identity.const import DEFAULT_TOKEN_START_OFFSET_SECONDS
from iotics.lib.identity.crypto.identity import make_identifier
from iotics.lib.identity.crypto.issuer import Issuer, IssuerKey
from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.crypto.key_pair_secrets import DIDType, KeyPairSecrets, KeyPairSecretsHelper
from iotics.lib.identity.crypto.keys import KeyPair, KeysHelper
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.error import IdentityRegisterIssuerNotFoundError, IdentityResolverConflictError, \
    IdentityResolverDocNotFoundError, IdentityValidationError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.document_helper import RegisterDocumentHelper
from iotics.lib.identity.register.key_pair import RegisteredIdentity
from iotics.lib.identity.register.keys import RegisterDelegationProof, \
    RegisterPublicKey
from iotics.lib.identity.register.resolver import ResolverClient
from iotics.lib.identity.validation.document import DocumentValidation


class AdvancedIdentityLocalApi:
    @staticmethod
    def get_key_pair_from_hex_private_key(private_expo_hex: str) -> KeyPair:
        """
        Get keypair given the private exponent as a hex string
        :param private_expo_hex: private exponent as hex string
        :return: KeyPair instance

        :raises:
            IdentityDependencyError: if incompatible EllipticCurve dependency
        """
        private_key = KeysHelper.get_private_ECDSA(private_expo_hex)
        public_bytes, public_base58 = KeysHelper.get_public_keys_from_private_ECDSA(private_key)
        return KeyPair(private_key=private_key,
                       public_bytes=public_bytes,
                       public_base58=public_base58)

    @staticmethod
    def get_issuer_by_public_key(doc: RegisterDocument, public_base58: str) -> Issuer:
        """
        Get issuer matching the public key from a register document public keys.
        :param doc: register document
        :param public_base58: issuer public key base 58
        :return: corresponding issuer

        :raises:
            IdentityRegisterIssuerNotFoundError: if the issuer matching the public key is not found
        """
        issuer = RegisterDocumentHelper.get_issuer_from_public_key(doc, public_base58)
        if not issuer:
            raise IdentityRegisterIssuerNotFoundError(f'User secrets not allowed to update \'{doc.did}\'')
        return issuer

    @staticmethod
    def create_agent_auth_token(agent_key_pair: KeyPair, agent_issuer: Issuer, user_did: str, duration: int,
                                audience: str, start_offset: int = DEFAULT_TOKEN_START_OFFSET_SECONDS):
        """
        Create an agent authentication token.
        :param agent_key_pair: agent key pair
        :param agent_issuer: agent issuer
        :param user_did: user register document decentralised identifier
        :param duration: token duration in seconds
        :param audience: Optional token audience
        :param start_offset: Optional offset for token valid-from time used (default=DEFAULT_TOKEN_START_OFFSET_SECONDS)
        :return: encoded jwt token

        :raises:
            IdentityValidationError: if invalid agent secrets
            IdentityValidationError: if invalid token data
            IdentityDependencyError: if incompatible library dependency
        """
        return JwtTokenHelper.create_auth_token(str(agent_issuer),
                                                user_did,
                                                audience,
                                                duration,
                                                agent_key_pair.private_key,
                                                start_offset)

    @staticmethod
    def create_twin_token(twin_key_pair: KeyPair, twin_issuer: Issuer, duration: int,
                          audience: str, start_offset: int = DEFAULT_TOKEN_START_OFFSET_SECONDS):
        """
        Create a twin authentication token.
        :param twin_key_pair: twin key pair
        :param twin_issuer: twin issuer
        :param duration: token duration in seconds
        :param audience: Optional token audience
        :param start_offset: Optional offset for token valid-from time used (default=DEFAULT_TOKEN_START_OFFSET_SECONDS)
        :return: encoded jwt token

        :raises:
            IdentityValidationError: if invalid twin secrets
            IdentityValidationError: if invalid token data
            IdentityDependencyError: if incompatible library dependency
        """
        return JwtTokenHelper.create_auth_token(str(twin_issuer),
                                                twin_issuer.did,
                                                audience,  # type: ignore
                                                duration,
                                                twin_key_pair.private_key,
                                                start_offset)

    @staticmethod
    def create_proof(key_secrets: KeyPairSecrets, issuer: Issuer, content: bytes) -> Proof:
        """
        Create a proof.
        :param key_secrets: secrets used to build the proof signature
        :param issuer: proof issuer
        :param content: proof content
        :return: proof

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityDependencyError: if incompatible library dependency
        """
        return Proof.build(key_secrets, issuer, content=content)

    @staticmethod
    def create_delegation_proof(delegating_issuer: Issuer,
                                subject_doc: RegisterDocument,
                                subject_secrets: KeyPairSecrets) -> Tuple[Issuer, Proof]:
        """
        Create a delegation proof.
        :param delegating_issuer: delegating issuer
        :param subject_doc: subject/delegated register document
        :param subject_secrets: subject/delegated secrets
        :return: subject/delegated issuer and proof

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityRegisterIssuerNotFoundError: if the issuer matching the subject/delegated secrets is not found
            IdentityDependencyError: if incompatible library dependency
        """
        subject_key_pair = KeyPairSecretsHelper.get_key_pair(subject_secrets)
        subject_issuer = AdvancedIdentityLocalApi.get_issuer_by_public_key(subject_doc,
                                                                           subject_key_pair.public_base58)
        proof = AdvancedIdentityLocalApi.create_proof(subject_secrets, subject_issuer,
                                                      content=delegating_issuer.did.encode())
        return subject_issuer, proof

    @staticmethod
    def create_identifier(public_bytes: bytes) -> str:
        """
        Create a new decentralised identifier.
        :param public_bytes: public key as bytes
        :return: decentralised identifier
        """
        return make_identifier(public_bytes)

    @staticmethod
    def validate_document_proof(doc: RegisterDocument):
        """
        Validate a register document proof.
        :param doc: register document

        :raises:
            IdentityInvalidDocumentError: if register document proof is invalid
        """
        DocumentValidation.validate_new_document_proof(doc)

    @staticmethod
    def create_seed(length: Optional[int] = 256) -> bytes:
        """
        Create a new seed (secrets).
        :param length: seed length
        :return: seed

        :raises:
            IdentityValidationError: if invalid seed length
        """
        if length not in (128, 256):
            raise IdentityValidationError('length must be 128 or 256')
        return secrets.token_bytes(nbytes=int(length / 8))


class AdvancedIdentityRegisterApi:
    def __init__(self, resolver_client: ResolverClient):
        self.resolver_client = resolver_client
        self.public_key_api = RegisterPublicDocKeysApi()
        self.auth_key_api = RegisterAuthPublicDocKeysApi()
        self.ctrl_deleg_api = RegisterCtrlDelegPublicDocKeysApi()
        self.auth_deleg_api = RegisterAuthDelegPublicDocKeysApi()

    def _update_doc(self, doc_owner_key_pair: KeyPair, doc_owner_issuer: Issuer, get_updated_doc: Callable, **kwargs):
        doc = self.get_register_document(doc_owner_issuer.did)
        updated_doc = get_updated_doc(doc, **kwargs)
        self.register_updated_document(updated_doc, doc_owner_key_pair, doc_owner_issuer)

    def register_updated_document(self, doc: RegisterDocument, doc_owner_key_pair: KeyPair, doc_owner_issuer: Issuer):
        """
        Register a new version of a register document against the resolver.
        :param doc: register document
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityResolverError: if resolver error
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error
        """
        self.resolver_client.register_document(doc, doc_owner_key_pair.private_key, doc_owner_issuer)

    def get_register_document(self, doc_did) -> RegisterDocument:
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
        return self.resolver_client.get_document(doc_did)

    def get_document_if_exists(self, doc_did: str) -> Optional[RegisterDocument]:
        """
        Get a register document from the resolver if the document exists.
        :param doc_did: register document decentralised identifier
        :return: associated register document if exists else None

        :raises:
            IdentityResolverError: if invalid resolver response
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error
        """
        try:
            return self.get_register_document(doc_did)
        except IdentityResolverDocNotFoundError:
            return None

    def register_new_doc(self, key_pair_secrets: KeyPairSecrets, issuer: Issuer,
                         purpose: DIDType):
        """
        Create and register a new document against the resolver.
        :param key_pair_secrets: new register document owner secrets
        :param issuer: new register document owner issuer
        :param purpose: register document purpose (HOST, TWIN, USER or AGENT)

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityInvalidDocumentError: if document build error
            IdentityDependencyError: if incompatible library dependency
        """
        key_pair = KeyPairSecretsHelper.get_key_pair(key_pair_secrets)
        proof = AdvancedIdentityLocalApi.create_proof(key_pair_secrets, issuer, content=issuer.did.encode())
        doc = RegisterDocumentBuilder() \
            .add_public_key(issuer.name, key_pair.public_base58, revoked=False) \
            .build(issuer.did, purpose, proof.signature, revoked=False)
        self.register_updated_document(doc, key_pair, issuer)

    def register_new_identity_if_not_exists(self, issuer_key: IssuerKey, key_pair_secrets: KeyPairSecrets,
                                            purpose: DIDType):
        """
        Create and register a new registered identity and its associated register document against the resolver if not
        exists.
        :param issuer_key: new registered identity owner issuer key
        :param key_pair_secrets: new registered identity owner secrets
        :param purpose: registered identity purpose (HOST, TWIN, USER or AGENT)
        :return: registered identity

        :raises:
            IdentityInvalidDocumentError: if document build error
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        issuer = issuer_key.issuer
        try:
            doc = self.get_document_if_exists(issuer.did)
            if not doc:
                self.register_new_doc(key_pair_secrets, issuer_key.issuer, purpose)
            else:
                issuer = AdvancedIdentityLocalApi.get_issuer_by_public_key(doc, issuer_key.public_key_base58)
            return RegisteredIdentity(key_pair_secrets, issuer)
        except IdentityRegisterIssuerNotFoundError as err:
            raise IdentityResolverConflictError(f'Register document {issuer.did} already exist and new registered '
                                                f'identity with name {issuer.name} is not a owner') from err

    def new_registered_identity(self, purpose: DIDType, key_pair_secrets: KeyPairSecrets,
                                name: str = None, override_doc: bool = False) -> RegisteredIdentity:
        """
        Create and register a new registered identity and its associated register document against the resolver.
        :param key_pair_secrets: new registered identity owner secrets
        :param name: Optional new registered identity name (default: '#<purpose>-0')
                     following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param purpose: registered identity purpose (HOST, TWIN, USER or AGENT)
        :param override_doc: override registered identity document if already exist (default False)
        :return: registered identity

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityValidationError: if invalid name
            IdentityInvalidDocumentError: if document build error
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        key_pair = KeyPairSecretsHelper.get_key_pair(key_pair_secrets)
        did = AdvancedIdentityLocalApi.create_identifier(key_pair.public_bytes)
        name = name or f'#{purpose}-0'
        issuer = Issuer.build(did, name)
        if override_doc:
            self.register_new_doc(key_pair_secrets, issuer, purpose)
            return RegisteredIdentity(key_pair_secrets, issuer)

        issuer_key = IssuerKey.build(issuer.did, issuer.name, key_pair.public_base58)
        return self.register_new_identity_if_not_exists(issuer_key, key_pair_secrets, purpose)

    def new_registered_user_identity(self, key_pair_secrets: KeyPairSecrets,
                                     name: str = None, override_doc: bool = False):
        """
        Create and register a new user registered identity and its associated register document against the resolver.
        :param key_pair_secrets: new user registered identity owner secrets
        :param name: Optional new user registered identity name (default: '#user-0')
                     following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param override_doc: override registered identity document if already exist (default False)
        :return: user registered identity

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityValidationError: if invalid name
            IdentityInvalidDocumentError: if document build error
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        return self.new_registered_identity(DIDType.USER, key_pair_secrets, name, override_doc)

    def new_registered_agent_identity(self, key_pair_secrets: KeyPairSecrets,
                                      name: str = None, override_doc: bool = False):
        """
        Create and register a new agent registered identity and its associated register document against the resolver.
        :param key_pair_secrets: new agent registered identity owner secrets
        :param name: Optional new agent registered identity name (default: '#agent-0')
                     following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param override_doc: override registered identity document if already exist (default False)
        :return: agent registered identity

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityValidationError: if invalid name
            IdentityInvalidDocumentError: if document build error
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        return self.new_registered_identity(DIDType.AGENT, key_pair_secrets, name, override_doc)

    def new_registered_twin_identity(self, key_pair_secrets: KeyPairSecrets,
                                     name: str = None,
                                     override_doc: bool = False):
        """
        Create and register a new twin registered identity and its associated register document against the resolver.
        :param key_pair_secrets: new twin registered identity owner secrets
        :param name: Optional new twin registered identity name (default: '#twin-0')
                     following this pattern: '#[a-zA-Z\\-\\_0-9]{1, 24}'
        :param override_doc: override registered identity document if already exist (default False)
        :return: twin registered identity

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityValidationError: if invalid name
            IdentityInvalidDocumentError: if document build error
            IdentityResolverConflictError: register document already exists with different owners
            IdentityResolverError: if can not interact with the resolver
            IdentityDependencyError: if incompatible library dependency
        """
        return self.new_registered_identity(DIDType.TWIN, key_pair_secrets, name, override_doc)

    def validate_register_document(self, doc: RegisterDocument):
        """
        Validate a register document against the resolver.
        :param doc: register document

        :raises:
            IdentityInvalidDocumentDelegationError: if one of the register document delegation proof is invalid
        """
        DocumentValidation.validate_document_against_resolver(self.resolver_client, doc)

    def set_document_controller(self, doc_owner_key_pair: KeyPair,
                                doc_owner_issuer: Issuer,
                                controller: Issuer):
        """
        Set register document controller issuer.
        :param controller: register document controller issuer
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer,
                         get_updated_doc=RegisterDocumentBuilder().build_from_existing, controller=controller)

    def set_document_creator(self, doc_owner_key_pair: KeyPair,
                             doc_owner_issuer: Issuer,
                             creator: str):
        """
        Set register document creator.
        :param creator: register document creator decentralised identifier
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityValidationError: if invalid creator decentralised identifier
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer,
                         get_updated_doc=RegisterDocumentBuilder().build_from_existing, creator=creator)

    def set_document_revoked(self, doc_owner_key_pair: KeyPair,
                             doc_owner_issuer: Issuer,
                             revoked: bool):
        """
        Set register document revoke field.
        :param revoked: is register document revoked
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer,
                         get_updated_doc=RegisterDocumentBuilder().build_from_existing, revoked=revoked)

    def add_public_key_to_document(self, name: str,
                                   new_public_key_base58: str,
                                   doc_owner_key_pair: KeyPair,
                                   doc_owner_issuer: Issuer) -> Issuer:
        """
        Add a new register public key to a register document.
        :param name: new public key name
        :param new_public_key_base58: public key base 58
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer
        :return: new register document owner issuer

        :raises:
            IdentityValidationError: if invalid new public key name
            IdentityRegisterDocumentKeyConflictError: if public key name is not unique within the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        new_key = RegisterPublicKey.build(name, new_public_key_base58)
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.public_key_api.add_doc_key,
                         key=new_key)
        return Issuer.build(doc_owner_issuer.did, name)

    def remove_public_key_from_document(self, removed_doc_owner_issuer: Issuer,
                                        existing_doc_owner_key_pair: KeyPair,
                                        existing_doc_owner_issuer: Issuer) -> Issuer:
        """
        Remove a register public key from a register document.
        :param removed_doc_owner_issuer: register document owner issuer to remove
        :param existing_doc_owner_key_pair: other existing register document owner key pair
        :param existing_doc_owner_issuer: other existing register document owner issuer
        :return: removed register document owner issuer

        :raises:
            IdentityValidationError: if invalid public key name
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        doc = self.get_register_document(removed_doc_owner_issuer.did)
        updated_doc = self.public_key_api.remove_doc_key(doc, key_name=removed_doc_owner_issuer.name)
        self.register_updated_document(updated_doc, existing_doc_owner_key_pair, existing_doc_owner_issuer)
        return removed_doc_owner_issuer

    def revoke_public_key_from_document(self, name: str, revoked: bool,
                                        doc_owner_key_pair: KeyPair,
                                        doc_owner_issuer: Issuer) -> Issuer:
        """
        Set register public key revoke field.
        :param name: public key name
        :param revoked: is revoked
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer
        :return: register document owner issuer

        :raises:
            IdentityValidationError: if invalid public key name
            IdentityRegisterDocumentKeyNotFoundError: if register public key not found
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.public_key_api.revoke_doc_key,
                         key_name=name, revoked=revoked)
        return Issuer.build(doc_owner_issuer.did, name)

    def add_authentication_key_to_document(self, name: str,
                                           new_public_key_base58: str,
                                           doc_owner_key_pair: KeyPair,
                                           doc_owner_issuer: Issuer) -> Issuer:
        """
        Add a new register authentication public key to a register document.
        :param name: new authentication public key name
        :param new_public_key_base58: public key base 58
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer
        :return: new key issuer

        :raises:
            IdentityValidationError: if invalid new authentication public key name
            IdentityRegisterDocumentKeyConflictError: if authentication public key name is not unique within
                                                        the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        new_key = RegisterPublicKey.build(name, new_public_key_base58)
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.auth_key_api.add_doc_key,
                         key=new_key)
        return Issuer.build(doc_owner_issuer.did, name)

    def remove_authentication_key_from_document(self, name: str,
                                                doc_owner_key_pair: KeyPair,
                                                doc_owner_issuer: Issuer) -> Issuer:

        """
        Remove a register authentication public key from a register document.
        :param name: authentication public key name
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer
        :return: new key issuer

        :raises:
            IdentityValidationError: if invalid authentication public key name
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.auth_key_api.remove_doc_key,
                         key_name=name)
        return Issuer.build(doc_owner_issuer.did, name)

    def revoke_authentication_key_from_document(self, name: str, revoked: bool,
                                                doc_owner_key_pair: KeyPair,
                                                doc_owner_issuer: Issuer) -> Issuer:
        """
        Set register authentication public key revoke field.
        :param name: authentication public key name
        :param revoked: is revoked
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer
        :return: new key issuer

        :raises:
            IdentityValidationError: if invalid authentication public key name
            IdentityRegisterDocumentKeyNotFoundError: if register authentication public key not found
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.auth_key_api.revoke_doc_key,
                         key_name=name, revoked=revoked)
        return Issuer.build(doc_owner_issuer.did, name)

    def add_authentication_delegation_proof_to_document(self, proof: Proof,
                                                        subject_issuer: Issuer,
                                                        delegation_name: str,
                                                        doc_owner_issuer: Issuer,
                                                        doc_owner_key_pair: KeyPair):
        """
        Add register authentication delegation proof to a register document.
        :param proof: proof
        :param subject_issuer: subject/delegated issuer
        :param delegation_name: register authentication delegation proof name
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityValidationError: if invalid register authentication delegation proof name
            IdentityRegisterDocumentKeyConflictError: if authentication delegation proof name is not unique within
                                                        the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        key = RegisterDelegationProof.build(delegation_name, subject_issuer, proof.signature)
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.auth_deleg_api.add_doc_key, key=key)

    def remove_authentication_delegation_proof_from_document(self, delegation_name: str,
                                                             doc_owner_issuer: Issuer,
                                                             doc_owner_key_pair: KeyPair):
        """
        Remove register authentication delegation proof from a register document.
        :param delegation_name: register authentication delegation proof name
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityValidationError: if invalid register authentication delegation proof name
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.auth_deleg_api.remove_doc_key,
                         key_name=delegation_name)

    def revoke_authentication_delegation_proof_from_document(self, delegation_name: str,
                                                             revoked: bool,
                                                             doc_owner_issuer: Issuer,
                                                             doc_owner_key_pair: KeyPair):
        """
        Set register authentication delegation proof revoke field.
        :param delegation_name: register authentication delegation proof name
        :param revoked: is revoked
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityValidationError: if invalid register authentication delegation proof name
            IdentityRegisterDocumentKeyNotFoundError: if register authentication delegation proof not found
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.auth_deleg_api.revoke_doc_key,
                         key_name=delegation_name, revoked=revoked)

    def add_control_delegation_proof_to_document(self, proof: Proof,
                                                 subject_issuer: Issuer,
                                                 delegation_name: str,
                                                 doc_owner_issuer: Issuer,
                                                 doc_owner_key_pair: KeyPair):
        """
        Add register control delegation proof to a register document.
        :param proof: proof
        :param subject_issuer: subject/delegated issuer
        :param delegation_name: register control delegation proof name
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityValidationError: if invalid register control delegation proof name
            IdentityRegisterDocumentKeyConflictError: if control delegation proof name is not unique within
                                                       the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
       """
        key = RegisterDelegationProof.build(delegation_name, subject_issuer, proof.signature)
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.ctrl_deleg_api.add_doc_key, key=key)

    def remove_control_delegation_proof_from_document(self, delegation_name: str,
                                                      doc_owner_issuer: Issuer,
                                                      doc_owner_key_pair: KeyPair):
        """
        Remove register control delegation proof from a register document.
        :param delegation_name: register control delegation proof name
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityValidationError: if invalid register control delegation proof name
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.ctrl_deleg_api.remove_doc_key,
                         key_name=delegation_name)

    def revoke_control_delegation_proof_from_document(self, delegation_name: str,
                                                      revoked: bool,
                                                      doc_owner_issuer: Issuer,
                                                      doc_owner_key_pair: KeyPair):
        """
        Set register control delegation proof revoke field.
        :param delegation_name: register control delegation proof name
        :param revoked: is revoked
        :param doc_owner_key_pair: register document owner key pair
        :param doc_owner_issuer: register document owner issuer

        :raises:
            IdentityValidationError: if invalid register control delegation proof name
            IdentityRegisterDocumentKeyNotFoundError: if register control delegation proof not found
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
        """
        self._update_doc(doc_owner_key_pair, doc_owner_issuer, get_updated_doc=self.ctrl_deleg_api.revoke_doc_key,
                         key_name=delegation_name, revoked=revoked)

    def delegate_authentication(self, delegating_secrets: KeyPairSecrets, delegating_did: str,
                                subject_secrets: KeyPairSecrets, subject_did: str, delegation_name):
        """
        Delegate authentication between delegating registered identity and delegated registered identity.
        :param delegating_secrets: delegating identity secrets
        :param delegating_did: delegating identity decentralised identifier
        :param subject_secrets: subject/delegated identity secrets
        :param subject_did: subject/delegated identity decentralised identifier
        :param delegation_name: register authentication delegation proof name

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityValidationError: if invalid register authentication delegation proof name
            IdentityRegisterIssuerNotFoundError: if the delegating (or delegated) issuer matching the delegating
                                                (or delegated) secrets is not found
            IdentityRegisterDocumentKeyConflictError: if authentication delegation proof name is not unique within
                                                      the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
            IdentityDependencyError: if incompatible library dependency
        """
        delegating_doc = self.get_register_document(delegating_did)
        subject_doc = self.get_register_document(subject_did)
        delegating_key_pair = KeyPairSecretsHelper.get_key_pair(delegating_secrets)
        delegating_issuer = AdvancedIdentityLocalApi.get_issuer_by_public_key(delegating_doc,
                                                                              delegating_key_pair.public_base58)

        subject_issuer, proof = AdvancedIdentityLocalApi.create_delegation_proof(delegating_issuer,
                                                                                 subject_doc,
                                                                                 subject_secrets)
        self.add_authentication_delegation_proof_to_document(proof, subject_issuer, delegation_name,
                                                             delegating_issuer, delegating_key_pair)

    def delegate_control(self, delegating_secrets: KeyPairSecrets, delegating_did: str, subject_secrets: KeyPairSecrets,
                         subject_did: str, delegation_name):
        """
        Delegate control between delegating registered identity and delegated registered identity.
        :param delegating_secrets: delegating identity secrets
        :param delegating_did: delegating identity decentralised identifier
        :param subject_secrets: subject/delegated identity secrets
        :param subject_did: subject/delegated identity decentralised identifier
        :param delegation_name: register control delegation proof name

        :raises:
            IdentityValidationError: if invalid secrets
            IdentityValidationError: if invalid register control delegation proof name
            IdentityRegisterIssuerNotFoundError: if the delegating (or delegated) issuer matching the delegating
                                                (or delegated) secrets is not found
            IdentityRegisterDocumentKeyConflictError: if control delegation proof name is not unique within
                                                      the register document
            IdentityInvalidDocumentError: if invalid register document
            IdentityResolverError: if resolver error
            IdentityDependencyError: if incompatible library dependency
        """
        delegating_doc = self.get_register_document(delegating_did)
        subject_doc = self.get_register_document(subject_did)
        delegating_key_pair = KeyPairSecretsHelper.get_key_pair(delegating_secrets)
        delegating_issuer = AdvancedIdentityLocalApi.get_issuer_by_public_key(delegating_doc,
                                                                              delegating_key_pair.public_base58)

        subject_issuer, proof = AdvancedIdentityLocalApi.create_delegation_proof(delegating_issuer,
                                                                                 subject_doc,
                                                                                 subject_secrets)
        self.add_control_delegation_proof_to_document(proof, subject_issuer, delegation_name,
                                                      delegating_issuer, delegating_key_pair)

    def get_proof_from_challenge_token(self, challenge_token: str) -> Proof:
        """
        Get the proof from a challenge token.
        :param challenge_token: challenge jwt token
        :return: valid proof

        :raises:
            IdentityValidationError: if invalid challenge token
        """
        return Proof.from_challenge_token(self.resolver_client, challenge_token)
