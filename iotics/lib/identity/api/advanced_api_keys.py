# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
from abc import ABC, abstractmethod
from typing import Optional

from iotics.lib.identity.error import IdentityRegisterDocumentKeyNotFoundError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.keys import RegisterAuthenticationPublicKey, RegisterDelegationProof, \
    RegisterKeyBase, RegisterPublicKey


class RegisterDocKeyApi(ABC):

    @abstractmethod
    def add_key_to_builder(self, builder: RegisterDocumentBuilder, key: RegisterKeyBase):
        """
        Add a new register key to the register document builder
        :param builder: register document builder
        :param key: register key base
        :raises:
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        raise NotImplementedError

    @abstractmethod
    def get_key_from_doc(self, doc: RegisterDocument, key_name: str) -> Optional[RegisterKeyBase]:
        """
        Get a register key from the document
        :param doc: register document
        :param key_name: key name
        :return: optional associated register key
        """
        raise NotImplementedError

    def add_doc_key(self, doc: RegisterDocument, key: RegisterKeyBase) -> RegisterDocument:
        """
        Add a new register key to the register document
        :param doc: register document
        :param key: register key base

        :raises:
            IdentityInvalidDocumentError: if invalid document
            IdentityRegisterDocumentKeyConflictError: if key name is not unique
        """
        builder = RegisterDocumentBuilder()
        self.add_key_to_builder(builder, key)
        return builder.build_from_existing(doc)

    @staticmethod
    def remove_doc_key(doc: RegisterDocument, key_name: str) -> RegisterDocument:
        """
        Remove a register key from a register document
        :param doc: register document
        :param key_name: register key name
        :return:
        """
        return RegisterDocumentBuilder() \
            .set_keys_from_existing(doc) \
            .remove_key(key_name) \
            .build_from_existing(doc, populate_with_doc_keys=False)

    def revoke_doc_key(self, doc: RegisterDocument, key_name: str, revoked: bool) -> RegisterDocument:
        """
        Create a new document setting revoked to the key associated to the key name
        :param doc: a register document
        :param key_name: a key name
        :param revoked: is the key revoked
        :return: a register document

        :raises:
        - IdentityRegisterDocumentKeyNotFoundError: if the key to revoke is not found

        """
        key = self.get_key_from_doc(doc, key_name)
        if not key:
            raise IdentityRegisterDocumentKeyNotFoundError(f'Can mot revoke key {key_name} fron document {doc.did}:'
                                                           f'key not found')
        builder = RegisterDocumentBuilder() \
            .set_keys_from_existing(doc) \
            .remove_key(key_name)
        self.add_key_to_builder(builder, key.get_new_key(revoked))
        return builder.build_from_existing(doc, populate_with_doc_keys=False)


class RegisterPublicDocKeysApi(RegisterDocKeyApi):

    def get_key_from_doc(self, doc: RegisterDocument, key_name: str) -> Optional[RegisterKeyBase]:
        return doc.public_keys.get(key_name)

    def add_key_to_builder(self, builder: RegisterDocumentBuilder, key: RegisterPublicKey):  # type: ignore
        builder.add_public_key_obj(key)


class RegisterAuthPublicDocKeysApi(RegisterDocKeyApi):
    def get_key_from_doc(self, doc: RegisterDocument, key_name: str) -> Optional[RegisterKeyBase]:
        return doc.auth_keys.get(key_name)

    def add_key_to_builder(self, builder: RegisterDocumentBuilder,  # type: ignore
                           key: RegisterAuthenticationPublicKey):
        builder.add_authentication_key_obj(key)


class RegisterCtrlDelegPublicDocKeysApi(RegisterDocKeyApi):

    def get_key_from_doc(self, doc: RegisterDocument, key_name: str) -> Optional[RegisterKeyBase]:
        return doc.control_delegation_proof.get(key_name)

    def add_key_to_builder(self, builder: RegisterDocumentBuilder, key: RegisterDelegationProof):  # type: ignore
        builder.add_control_delegation_obj(key)


class RegisterAuthDelegPublicDocKeysApi(RegisterDocKeyApi):

    def get_key_from_doc(self, doc: RegisterDocument, key_name: str) -> Optional[RegisterKeyBase]:
        return doc.auth_delegation_proof.get(key_name)

    def add_key_to_builder(self, builder: RegisterDocumentBuilder, key: RegisterDelegationProof):  # type: ignore
        builder.add_authentication_delegation_obj(key)
