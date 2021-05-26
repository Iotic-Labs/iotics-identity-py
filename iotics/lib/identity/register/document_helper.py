# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from typing import Callable, Optional

import base58

from iotics.lib.identity.crypto.identity import make_identifier
from iotics.lib.identity.crypto.issuer import Issuer, IssuerKey
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.keys import RegisterDelegationProof, RegisterKey, RegisterPublicKey

GetControllerDocFunc = Callable[[str], RegisterDocument]


class RegisterDocumentHelper:
    @staticmethod
    def get_owner_register_public_key(doc: RegisterDocument) -> Optional[RegisterPublicKey]:
        """
        Get the register document initial owner public key
        :param doc: existing register document
        :return: RegisterPublicKey if found or None
        """
        for key in doc.public_keys.values():
            public_bytes = base58.b58decode(key.base58)
            key_id = make_identifier(public_bytes)
            if key_id == doc.did:  # It is the original key
                return key
        return None

    @staticmethod
    def get_issuer_from_public_key(doc: RegisterDocument, public_base58: str) -> Optional[Issuer]:
        """
        Find a register key by issuer and returns True/False if found.
        Lookup in the register document public keys (and authentication keys if include_auth is set to True).
        :param doc: existing register document
        :param public_base58: public key to search for as base58 string
        :return: Issuer or None

        :raises:
            IdentityValidationError: if invalid name or did
        """
        for key in doc.public_keys.values():
            if key.base58 == public_base58:
                return Issuer.build(doc.did, key.name)
        return None

    @staticmethod
    def is_issuer_in_keys(issuer_name: str, doc: RegisterDocument, include_auth: bool) -> bool:
        """
        Find an issuer key and returns True/False if found
        :param issuer_name: #name to search for
        :param doc: existing register document
        :param include_auth: include authentication keys
        :return: True/False if found
        """
        return RegisterDocumentHelper.get_issuer_register_key(issuer_name, doc, include_auth) is not None

    @staticmethod
    def get_issuer_register_key(issuer_name: str, doc: RegisterDocument, include_auth: bool) -> Optional[RegisterKey]:
        """
        Find a register key by issuer.
        Lookup in the register document public keys (and authentication keys if include_auth is set to True).
        :param issuer_name: #name to search for
        :param doc: existing register document
        :param include_auth: include authentication keys
        :return: RegisterKey or None
        """
        pub_key = doc.public_keys.get(issuer_name)
        if pub_key:
            return pub_key
        if include_auth:
            return doc.auth_keys.get(issuer_name)
        return None

    @staticmethod
    def get_issuer_register_delegation_proof(issuer_name: str, doc: RegisterDocument,
                                             include_auth: bool) -> Optional[RegisterDelegationProof]:
        """
        Find a register delegation proof by issuer.
        Lookup in the register document control delegation proofs
        (and authentication delegation proofs if include_auth is set to True).
        :param issuer_name: #name to search for
        :param doc: existing register document
        :param include_auth: include authentication keys
        :return: RegisterDelegationProof or None
        """
        control_deleg = doc.control_delegation_proof.get(issuer_name)
        if control_deleg:
            return control_deleg
        if include_auth:
            return doc.auth_delegation_proof.get(issuer_name)
        return None

    @staticmethod
    def get_register_delegation_proof_by_controller(controller: Issuer, doc: RegisterDocument,
                                                    include_auth: bool) -> Optional[RegisterDelegationProof]:
        """
        Find a register delegation proof by controller issuer.
        Lookup in the register document control delegation proofs
        (and authentication delegation proofs if include_auth is set to True).
        :param controller: Issuing controller
        :param doc: existing register document
        :param include_auth: include authentication keys
        :return: RegisterDelegationProof or None
        """
        keys = list(doc.control_delegation_proof.values())
        if include_auth:
            keys += list(doc.auth_delegation_proof.values())
        for key in keys:
            if key.controller == controller:
                return key
        return None

    @staticmethod
    def get_valid_issuer_key_for(doc: RegisterDocument, issuer_name: str, get_controller_doc: GetControllerDocFunc,
                                 include_auth: bool, ) -> Optional[IssuerKey]:
        """
        Get a valid issuer key matching issuer name
        :param doc: existing register document
        :param issuer_name: name of issuer
        :param get_controller_doc: resolver discover function
        :param include_auth: include authentication keys
        :return: IssuerKey or None

        :raises:
            IdentityValidationError: if invalid name or did
        """
        key = RegisterDocumentHelper.get_issuer_register_key(issuer_name, doc, include_auth)
        if key:
            return IssuerKey.build(doc.did, issuer_name, key.base58)

        deleg_key = RegisterDocumentHelper.get_issuer_register_delegation_proof(issuer_name, doc, include_auth)
        if deleg_key:
            controlled_doc = get_controller_doc(deleg_key.controller.did)
            key = RegisterDocumentHelper.get_issuer_register_key(issuer_name, controlled_doc, include_auth)
            if key:
                return IssuerKey.build(doc.did, issuer_name, key.base58)
        return None

    @staticmethod
    def get_valid_issuer_key_for_control_only(doc: RegisterDocument, issuer_name: str,
                                              get_controller_doc: GetControllerDocFunc) -> Optional[IssuerKey]:
        """
        Get a valid issuer key matching issuer name from the control keys and delegation proofs only
        :param doc: existing register document
        :param issuer_name: name of issuer
        :param get_controller_doc: resolver discover function
        :return: IssuerKey or None

        :raises:
            IdentityValidationError: if invalid name or did
        """
        return RegisterDocumentHelper.get_valid_issuer_key_for(doc, issuer_name, get_controller_doc, include_auth=False)

    @staticmethod
    def get_valid_issuer_key_for_auth(doc: RegisterDocument, issuer_name: str,
                                      get_controller_doc: GetControllerDocFunc) -> Optional[IssuerKey]:
        """
        Get a valid issuer key matching issuer name from the control and authentication keys and delegation proofs
        :param doc: existing register document
        :param issuer_name: name of issuer
        :param get_controller_doc: resolver discover function
        :return: IssuerKey or None

        :raises:
            IdentityValidationError: if invalid name or did
        """
        return RegisterDocumentHelper.get_valid_issuer_key_for(doc, issuer_name, get_controller_doc, include_auth=True)
