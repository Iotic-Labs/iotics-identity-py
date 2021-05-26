# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.error import IdentityInvalidDocumentError, IdentityInvalidProofError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.document_helper import RegisterDocumentHelper
from iotics.lib.identity.register.resolver import ResolverClient
from iotics.lib.identity.validation.proof import DelegationValidation, ProofValidation


class DocumentValidation:

    @staticmethod
    def validate_new_document_proof(doc: RegisterDocument):
        """
        Validate register document proof.
        :param doc: register document.

        :raises:
            IdentityInvalidDocumentError: if register document initial owner public key has been removed
            IdentityInvalidDocumentError: if register document proof is invalid
        """
        try:
            key = RegisterDocumentHelper.get_owner_register_public_key(doc)
            if not key:
                raise IdentityInvalidDocumentError(f'Invalid document \'{doc.did}\', no owner public key')
            ProofValidation.validate_proof(
                Proof(Issuer.build(doc.did, key.name), doc.did.encode('ascii'), doc.proof), key.base58)
        except IdentityInvalidProofError as err:
            raise IdentityInvalidDocumentError(f'Invalid document \'{doc.did}\' proof: {err}') from err

    @staticmethod
    def validate_document_against_resolver(resolver_client: ResolverClient, doc: RegisterDocument):
        """
        Validate a register document against the resolver.
        :param resolver_client: resolver client interface
        :param doc: register document

        :raises:
            IdentityInvalidDocumentDelegationError: if one of the register document delegation proof is invalid
        """
        for key in doc.control_delegation_proof.values():
            DelegationValidation.validate_delegation(resolver_client, doc.did, key)

        for key in doc.auth_delegation_proof.values():
            DelegationValidation.validate_delegation(resolver_client, doc.did, key)
