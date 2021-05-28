# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from time import time as unixtime
from typing import Dict, Optional, Set

from iotics.lib.identity.const import DOCUMENT_VERSION, SUPPORTED_VERSIONS
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import DIDType
from iotics.lib.identity.error import IdentityInvalidDocumentError, IdentityRegisterDocumentKeyConflictError
from iotics.lib.identity.register.document import Metadata, RegisterDocument
from iotics.lib.identity.register.keys import RegisterAuthenticationPublicKey, RegisterDelegationProof, \
    RegisterPublicKey
from iotics.lib.identity.validation.identity import IdentityValidation


def get_unix_time_ms() -> int:
    return int(unixtime() * 1000)


class RegisterDocumentBuilder:
    def __init__(self):
        self.public_keys: Dict[str, RegisterPublicKey] = {}
        self.auth_keys: Dict[str, RegisterAuthenticationPublicKey] = {}
        self.control_delegations: Dict[str, RegisterDelegationProof] = {}
        self.auth_delegations: Dict[str, RegisterDelegationProof] = {}
        self.name_set: Set[str] = set()
        self.revoked: bool = False

    def _check_and_update_map(self, name: str, val: object, key_map: dict, message_prefix: str):
        if name in self.name_set and not val.is_equal(key_map.get(name)):  # type: ignore
            raise IdentityRegisterDocumentKeyConflictError(f'{message_prefix} \'{name}\' already in use')

        self.name_set.add(name)
        key_map[name] = val

    def _remove_key(self, name: str):
        self.name_set.discard(name)
        self.public_keys.pop(name, None)
        self.auth_keys.pop(name, None)
        self.control_delegations.pop(name, None)
        self.auth_delegations.pop(name, None)

    def add_public_key(self, name: str, public_base58: str,
                       revoked: Optional[bool] = False) -> 'RegisterDocumentBuilder':
        """
        Add public key to document under build.
        :param name: key name
        :param public_base58: public key base58
        :param revoked: is revoked (default=False)
        :return: self

        :raises:
            IdentityValidationError: if invalid public key
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        key = RegisterPublicKey.build(name, public_base58, revoked)
        self._check_and_update_map(name, key, self.public_keys, 'Public key name')
        return self

    def add_public_key_obj(self, key: RegisterPublicKey) -> 'RegisterDocumentBuilder':
        """
        Add public key to document under build.
        :param key: register public key
        :return: self

        :raises:
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        self._check_and_update_map(key.name, key, self.public_keys, 'Public key name')
        return self

    def add_authentication_key(self, name: str, public_base58: str,
                               revoked: Optional[bool] = False) -> 'RegisterDocumentBuilder':
        """
        Add authentication public key to document under build.
        :param name: key name
        :param public_base58: authentication public key base58
        :param revoked: is revoked (default=False)
        :return: self

        :raises:
            IdentityValidationError: if invalid authentication public key
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        key = RegisterAuthenticationPublicKey.build(name, public_base58, revoked)
        self._check_and_update_map(name, key, self.auth_keys, 'Authentication key name')
        return self

    def add_authentication_key_obj(self, key: RegisterAuthenticationPublicKey) -> 'RegisterDocumentBuilder':
        """
        Add authentication public key to document under build.
        :param key: register authentication public key
        :return: self

        :raises:
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        self._check_and_update_map(key.name, key, self.auth_keys, 'Authentication key name')
        return self

    def add_control_delegation(self, name: str, controller: Issuer, proof: str,
                               revoked: Optional[bool] = False) -> 'RegisterDocumentBuilder':
        """
        Add control delegation public key to document under build.
        :param name: key name
        :param controller: control delegation controller
        :param proof: control delegation proof
        :param revoked: is revoked (default=False)
        :return: self

        :raises:
            IdentityValidationError: if invalid control delegation public key
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        key = RegisterDelegationProof.build(name, controller, proof, revoked)
        self._check_and_update_map(name, key, self.control_delegations, 'Control delegation name')
        return self

    def add_control_delegation_obj(self, key: RegisterDelegationProof) -> 'RegisterDocumentBuilder':
        """
        Add control delegation public key to document under build.
        :param key: register control delegation public key
        :return: self

        :raises:
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        self._check_and_update_map(key.name, key, self.control_delegations, 'Control delegation name')
        return self

    def add_authentication_delegation(self, name: str, controller: Issuer, proof: str,
                                      revoked: Optional[bool] = False) -> 'RegisterDocumentBuilder':
        """
        Add authentication delegation public key to document under build.
        :param name: key name
        :param controller: authentication delegation controller
        :param proof: authentication delegation proof
        :param revoked: is revoked (default=False)
        :return: self

        :raises:
            IdentityValidationError: if invalid authentication delegation public key
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        key = RegisterDelegationProof.build(name, controller, proof, revoked)
        self._check_and_update_map(name, key, self.auth_delegations,
                                   'Authentication delegation name')
        return self

    def add_authentication_delegation_obj(self, key: RegisterDelegationProof) -> 'RegisterDocumentBuilder':
        """
        Add authentication delegation public key to document under build.
        :param key: register authentication delegation public key
        :return: self

        :raises:
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        self._check_and_update_map(key.name, key, self.auth_delegations,
                                   'Authentication delegation name')
        return self

    def remove_key(self, key_name: str) -> 'RegisterDocumentBuilder':
        """
        Remove a key from the doc under build. Do nothing if the key do not
        belongs to the doc.
        :param key_name: the key name
        :return: self
        """
        self._remove_key(key_name)
        return self

    def set_keys_from_existing(self, doc: RegisterDocument) -> 'RegisterDocumentBuilder':
        """
        Set keys from a valid immutable register document from an existing one.
        :param doc: existing register document
        :return: self

        :raises:
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
       """
        for pub_key in doc.public_keys.values():
            self.add_public_key_obj(pub_key)
        for auth_key in doc.auth_keys.values():
            self.add_authentication_key_obj(auth_key)
        for auth_proof in doc.auth_delegation_proof.values():
            self.add_authentication_delegation_obj(auth_proof)
        for ctrl_proof in doc.control_delegation_proof.values():
            self.add_control_delegation_obj(ctrl_proof)
        return self

    def build(self, did: str, purpose: DIDType, proof: str, revoked: bool,
              metadata: Metadata = Metadata(), creator: Optional[str] = None,
              spec_version: Optional[str] = DOCUMENT_VERSION,
              update_time: Optional[int] = None,
              controller: Issuer = None) -> RegisterDocument:
        """
        Build a valid immutable register document.
        :param did: register document decentralised identifier
        :param purpose: register document purpose (HOST, TWIN, USER or AGENT)
        :param proof: register document proof
        :param revoked: is register document revoked
        :param metadata: register document optional metadata.
        :param creator: register document optional creator identifier.
        :param spec_version: register document version (default=DOCUMENT_VERSION)
        :param update_time: register document update time (unix time ms). Automatically set to know if not provided.
        :param controller: register document optional controller
        :return: valid register document

        :raises:
            IdentityInvalidDocumentError: if version ot supported
            IdentityValidationError: if invalid controller
            IdentityInvalidDocumentError: if invalid document (no controller and no public key)
        """
        IdentityValidation.validate_identifier(did)
        if spec_version not in SUPPORTED_VERSIONS:
            raise IdentityInvalidDocumentError(f'Unsupported version {spec_version} not in {SUPPORTED_VERSIONS}')
        if creator:
            IdentityValidation.validate_identifier(creator)
        if not controller and not self.public_keys:
            raise IdentityInvalidDocumentError('Invalid document, no Controller or Public Keys provided')
        return RegisterDocument(did=did, purpose=purpose, proof=proof, revoked=revoked,
                                metadata=metadata, creator=creator,
                                public_keys=self.public_keys,
                                auth_keys=self.auth_keys,
                                control_delegation_proof=self.control_delegations,
                                auth_delegation_proof=self.auth_delegations,
                                spec_version=spec_version,
                                update_time=update_time or get_unix_time_ms(),
                                controller=controller)

    def build_from_dict(self, data: dict) -> RegisterDocument:
        """
        Build a valid immutable register document from dict.
        :param data: register document as dict
        :return: valid register document

        :raises:
            IdentityInvalidDocumentError: if invalid dict data
            IdentityInvalidDocumentError: if invalid document
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        try:
            for k in data['publicKey']:
                self.add_public_key_obj(RegisterPublicKey.from_dict(k))
            for k in data.get('authentication', []):
                self.add_authentication_key_obj(RegisterAuthenticationPublicKey.from_dict(k))
            for k in data.get('delegateAuthentication', []):
                self.add_authentication_delegation_obj(RegisterDelegationProof.from_dict(k))
            for k in data.get('delegateControl', []):
                self.add_control_delegation_obj(RegisterDelegationProof.from_dict(k))
            raw_controller = data.get('controller')
            controller = Issuer.from_string(raw_controller) if raw_controller else None
            return self.build(data['id'], DIDType(data['ioticsDIDType']), data['proof'], data.get('revoked', False),
                              Metadata.from_dict(data.get('metadata', {})), data.get('creator'),
                              data['ioticsSpecVersion'], data['updateTime'], controller)
        except (TypeError, KeyError, ValueError) as err:
            raise IdentityInvalidDocumentError(f'Can not parse invalid register document: \'{err}\'') from err

    def build_from_existing(self, doc: RegisterDocument,
                            revoked: Optional[bool] = None,
                            metadata: Optional[Metadata] = None,
                            creator: Optional[str] = None,
                            spec_version: Optional[str] = None,
                            controller: Optional[Issuer] = None,
                            populate_with_doc_keys: Optional[bool] = True) -> RegisterDocument:
        """
        Build a valid immutable register document from an existing one.
        :param doc: existing register document
        :param revoked: is register document revoked. Optional, takes the existing doc value if not provided.
        :param metadata: register document optional metadata. Optional, takes the existing doc value if not provided.
        :param creator: register document optional creator identifier. Optional, takes the existing doc value
        if not provided.
        :param spec_version: register document version (default=DOCUMENT_VERSION). Optional, takes the existing doc
        value if not provided.
        :param controller: register document optional controller. Optional, takes the existing doc value
        if not provided.
        :param populate_with_doc_keys: populate builder keys with keys from the existion document (default=True)
        :return: valid register document

        :raises:
            IdentityValidationError: if invalid controller
            IdentityInvalidDocumentError: if invalid document
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        if populate_with_doc_keys:
            self.set_keys_from_existing(doc)
        revoked = revoked if revoked is not None else doc.revoked
        return self.build(doc.did, doc.purpose, doc.proof,
                          revoked,
                          metadata or doc.metadata,
                          creator or doc.creator,
                          spec_version or doc.spec_version,
                          controller=controller or doc.controller)
