# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.crypto.identity import is_same_identifier
from iotics.lib.identity.crypto.keys import KeysHelper
from iotics.lib.identity.crypto.proof import Proof
from iotics.lib.identity.error import IdentityInvalidDocumentDelegationError, IdentityInvalidProofError, \
    IdentityResolverError, \
    IdentityValidationError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.keys import RegisterDelegationProof
from iotics.lib.identity.register.resolver import ResolverClient


class ProofValidation:
    @staticmethod
    def validate_proof(proof: Proof, public_base58: str):
        """
        Validate proof.
        :param proof: proof
        :param public_base58: public key base 58 used to create the proof

        :raises:
            IdentityInvalidProofError: if invalid proof signature
            IdentityInvalidProofError: if invalid proof
        """
        public_ecdsa = KeysHelper.get_public_ECDSA_from_base58(public_base58)
        try:
            signature = base64.b64decode(proof.signature)
            public_ecdsa.verify(signature, proof.content, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as err:
            raise IdentityInvalidProofError('Invalid proof: invalid signature') from err
        except ValueError as err:
            raise IdentityInvalidProofError(f'Invalid proof: \'{err}\'') from err


class DelegationValidation:
    @staticmethod
    def validate_delegation_from_doc(doc_id: str, controller_doc: RegisterDocument,
                                     deleg_proof: RegisterDelegationProof):
        """
        Validate register delegation proof against the deleagtion controller register document.
        :param doc_id: decentralised id of the register document owning the register delegation proof
        :param controller_doc: delegation controller register document
        :param deleg_proof: register delegation proof under validation

        :raises:
            IdentityInvalidDocumentDelegationError: if controller issuer does not belongs to the controller document
                                                    public keys
            IdentityInvalidDocumentDelegationError: if invalid register delegation proof signature
        """
        try:
            controller_issuer = deleg_proof.controller
            public_key = controller_doc.public_keys.get(controller_issuer.name)
            if not public_key:
                raise IdentityValidationError(f'Public key \'{controller_issuer.name}\' not found'
                                              f' on controller doc \'{controller_doc.did}\'')
            proof = Proof(controller_issuer, doc_id.encode('ascii'), deleg_proof.proof)
            ProofValidation.validate_proof(proof, public_key.base58)
        except IdentityValidationError as err:
            raise IdentityInvalidDocumentDelegationError(f'Invalid delegation for doc \'{doc_id}\''
                                                         f' with controller: \'{deleg_proof.name}\': {err}') from err

    @staticmethod
    def validate_delegation(resolver_client: ResolverClient, doc_id: str, deleg_proof: RegisterDelegationProof):
        """
        Validate register delegation proof.
        :param resolver_client: resolver client interface
        :param doc_id: decentralised id of the register document owning the register delegation proof
        :param deleg_proof: register delegation proof under validation

        :raises:
            IdentityInvalidDocumentDelegationError: if the register delegation proof is invalid
            IdentityInvalidDocumentDelegationError: if the register delegation proof controller can not be fetched
                                                    from the resolver
        """
        try:
            if is_same_identifier(doc_id, str(deleg_proof.controller)):
                raise IdentityInvalidDocumentDelegationError(f'Delegation on self no allowed on doc \'{doc_id}\'')

            controller_doc = resolver_client.get_document(deleg_proof.controller.did)
            DelegationValidation.validate_delegation_from_doc(doc_id, controller_doc, deleg_proof)
        except IdentityResolverError as err:
            raise IdentityInvalidDocumentDelegationError(f'Invalid delegation for doc \'{doc_id}\''
                                                         f' with controller: \'{deleg_proof.name}\': {err}') from err
