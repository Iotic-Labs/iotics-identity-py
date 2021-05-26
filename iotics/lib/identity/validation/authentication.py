# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
from iotics.lib.identity.crypto.identity import is_same_identifier
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.error import IdentityAuthenticationFailed, IdentityInvalidDocumentDelegationError, \
    IdentityInvalidRegisterIssuerError, IdentityNotAllowed, IdentityResolverError, IdentityValidationError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.document_helper import RegisterDocumentHelper
from iotics.lib.identity.register.resolver import ResolverClient
from iotics.lib.identity.validation.proof import DelegationValidation


class IdentityAuthValidation:
    @staticmethod
    def is_allowed_for(issuer: Issuer, issuer_doc: RegisterDocument, subject_doc: RegisterDocument,
                       include_auth: bool) -> bool:
        """
        Check if the issuer is allowed for control (authentication if include_auth = True) on the subject register
        document.
        Issuer is allowed if both the issuer and subject register document are not revoked
        AND (
             ( the issuer is the owner of the subject register document
             OR
              if a include_auth=True the issuer is in the authentication public keys of the subject register document
             )
             OR
             the issuer is delegated for control (authentication if include_auth = True) with a valid delegation proof
             on the subject registered document
        )

        :param issuer: issuer
        :param issuer_doc: issuer register document
        :param subject_doc: subject register document
        :param include_auth: include authentication keys and delegation proof is set to True
        :return: True is allowed else False
        """
        if issuer_doc.revoked or subject_doc.revoked:
            return False

        if is_same_identifier(issuer.did, subject_doc.did):  # it is the same document
            issuer_key = RegisterDocumentHelper.get_issuer_register_key(issuer.name, subject_doc, include_auth)
            if issuer_key and not issuer_key.revoked:
                return True

        delegation_proof = RegisterDocumentHelper.get_register_delegation_proof_by_controller(issuer, subject_doc,
                                                                                              include_auth)
        if delegation_proof:
            try:
                DelegationValidation.validate_delegation_from_doc(subject_doc.did, issuer_doc, delegation_proof)
            except IdentityInvalidDocumentDelegationError:
                return False
            return not delegation_proof.revoked
        return False

    @staticmethod
    def _check_allowed_on_doc_or_controller(resolver_client: ResolverClient, issuer: Issuer, subject_id: str,
                                            include_auth: bool):
        """
        Validate if issuer is allowed for control  (authentication if include_auth = True) on the register document
        associated to the subject decentralised identifier.
        Issuer is allowed if both the issuer and subject register document can be fetched
        AND (
            if the issuer is allowed on the subject register document
            OR
            if the issuer is allowed on the subject controller register document
        )

        :param resolver_client: resolver client interface
        :param issuer: issuer under validation
        :param subject_id: subject register document decentralised identifier
        :param include_auth: include authentication keys and delegation proof is set to True

        :raises:
             IdentityNotAllowed: if issuer not allowed
        """
        try:
            issuer_doc = resolver_client.get_document(issuer.did)
            subject_doc = resolver_client.get_document(subject_id)
            if IdentityAuthValidation.is_allowed_for(issuer, issuer_doc, subject_doc, include_auth):
                return
            # Check if allowed for controller
            if subject_doc.controller:
                controller_doc = resolver_client.get_document(subject_doc.controller.did)
                if IdentityAuthValidation.is_allowed_for(issuer, issuer_doc, controller_doc, include_auth):
                    return
        except IdentityResolverError as err:
            raise IdentityNotAllowed(f'Cannot validate issuer {issuer} is allowed for {subject_id}: {err}') from err
        raise IdentityNotAllowed(f'Issuer {issuer} not allowed for {subject_id}')

    @staticmethod
    def validate_allowed_for_control(resolver_client: ResolverClient, issuer: Issuer, subject_id: str):
        """
        Validate if issuer is allowed for control on the register document associated to the subject decentralised
        identifier.
        :param resolver_client: resolver client interface
        :param issuer: issuer under validation
        :param subject_id: subject register document decentralised identifier

        :raises:
            IdentityNotAllowed: if the issuer is not allowed for control
        """
        IdentityAuthValidation._check_allowed_on_doc_or_controller(resolver_client, issuer, subject_id,
                                                                   include_auth=False)

    @staticmethod
    def validate_allowed_for_auth(resolver_client: ResolverClient, issuer: Issuer, subject_id: str):
        """
        Validate if issuer is allowed for authentication on the register document associated to the subject
        decentralised identifier.
        :param resolver_client: resolver client interface
        :param issuer: issuer under validation
        :param subject_id: subject register document decentralised identifier

        :raises:
            IdentityNotAllowed: if the issuer is not allowed for authentication
        """
        IdentityAuthValidation._check_allowed_on_doc_or_controller(resolver_client, issuer, subject_id,
                                                                   include_auth=True)

    @staticmethod
    def verify_authentication(resolver_client: ResolverClient, token: str) -> dict:
        """
        Verify if the authentication token is allowed for authentication.
        :param resolver_client: resolver client interface
        :param token: jwt authentication token
        :return: decoded verified authentication token

        :raises:
            IdentityAuthenticationFailed: if not allowed for authentication
        """
        try:
            unverified_token = JwtTokenHelper.decode_token(token)
            for field in ('iss', 'sub', 'aud', 'iat', 'exp'):
                if field not in unverified_token:
                    raise IdentityValidationError(f'Invalid token, missing {field} field')
            issuer = Issuer.from_string(unverified_token['iss'])
            doc = resolver_client.get_document(issuer.did)
            get_controller_doc = resolver_client.get_document
            issuer_key = RegisterDocumentHelper.get_valid_issuer_key_for_auth(doc, issuer.name, get_controller_doc)
            if not issuer_key:
                raise IdentityInvalidRegisterIssuerError(f'Invalid issuer {issuer}')
            verified_token = JwtTokenHelper.decode_and_verify_token(token, issuer_key.public_key_base58,
                                                                    unverified_token['aud'])

            IdentityAuthValidation.validate_allowed_for_auth(resolver_client, issuer_key.issuer, verified_token['sub'])

            return {'iss': verified_token['iss'],
                    'sub': verified_token['sub'],
                    'aud': verified_token['aud'],
                    'iat': verified_token['iat'],
                    'exp': verified_token['exp']}
        except (IdentityValidationError, IdentityResolverError,
                IdentityInvalidRegisterIssuerError, IdentityNotAllowed) as err:
            raise IdentityAuthenticationFailed('Not authenticated') from err
