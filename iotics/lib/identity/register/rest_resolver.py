# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from http import HTTPStatus
from typing import Optional, Union

import requests
from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.jwt import JwtTokenHelper
from iotics.lib.identity.error import IdentityInvalidRegisterIssuerError, IdentityResolverCommunicationError, \
    IdentityResolverError, IdentityResolverHttpDocNotFoundError, IdentityResolverHttpError, \
    IdentityResolverTimeoutError, IdentityValidationError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.document_helper import GetControllerDocFunc, RegisterDocumentHelper
from iotics.lib.identity.register.resolver import ResolverClient


class ResolverSerializer:
    @staticmethod
    def get_valid_doc_from_token(token: str, get_controller_doc: GetControllerDocFunc) -> RegisterDocument:
        """
        Get a valid RegisterDocument from a resolver token.
        :param token: resolver token
        :param get_controller_doc: get controller register document function
        :return: valid register document

        :raises:
            IdentityResolverError: if invalid token
            IdentityResolverError: if invalid document
        """
        try:
            unverified = JwtTokenHelper.decode_token(token)
            doc = RegisterDocumentBuilder().build_from_dict(unverified['doc'])
            issuer = Issuer.from_string(unverified['iss'])
            issuer_key = RegisterDocumentHelper.get_valid_issuer_key_for_control_only(doc, issuer.name,
                                                                                      get_controller_doc)
            if not issuer_key:
                raise IdentityInvalidRegisterIssuerError(f'Invalid issuer {issuer}')
            JwtTokenHelper.decode_and_verify_token(token, issuer_key.public_key_base58, unverified['aud'])
            return doc
        except (KeyError, ValueError, IdentityValidationError, IdentityInvalidRegisterIssuerError) as exc:
            raise IdentityResolverError(f'Can not deserialized invalid resolver token: \'{exc}\'') from exc

    @staticmethod
    def serialize_to_token(document: RegisterDocument, private_key: ec.EllipticCurvePrivateKey,
                           issuer: Issuer, audience: str = '') -> str:
        """
        Serialize a register document to resolver token.
        :param document: register document
        :param private_key: token issuer private key
        :param issuer: token issuer
        :param audience: token audience
        :return: resolver token

        :raises:
            IdentityResolverError: if can not encode the token
        """
        try:
            return JwtTokenHelper.create_doc_token(issuer, audience, document, private_key)
        except IdentityValidationError as err:
            raise IdentityResolverError(f'Can not serialized to register document resolver token: \'{err}\'') from err


class RESTResolverRequester:

    def __init__(self, address: str, timeout: Optional[Union[int, float]] = 60.0):
        """
        Rest resolver requester.
        :param address: http REST resolver url
        :param timeout: optional timeout seconds. Default=60s. If set to 0, requests will have no timeout.
        """
        self.address = address
        self.timeout = None if timeout and timeout <= 0 else timeout

    def get_token(self, doc_id: str) -> str:
        """
        Request the REST resolver to get the token associated to the provided doc identifier.
        :param doc_id: register document decentralised identifier
        :return: resolver token

        :raises:
            IdentityResolverError: if invalid resolver response
            IdentityResolverHttpDocNotFoundError: if document not found
            IdentityResolverHttpError: if http error
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error

        """
        try:
            rsp = requests.get(
                f'{self.address}/1.0/discover/{doc_id}',
                timeout=self.timeout
            )
            rsp.raise_for_status()
            return rsp.json()['token']
        except (KeyError, ValueError) as exc:
            raise IdentityResolverError(f'Unexpected token format received: \'{exc}\'') from exc
        except requests.HTTPError as exc:
            if exc.response.status_code == HTTPStatus.NOT_FOUND:
                raise IdentityResolverHttpDocNotFoundError(f'Identity token for {doc_id} not found') from exc
            raise IdentityResolverHttpError('Identity token could not be retrieved') from exc
        except requests.Timeout as exc:
            raise IdentityResolverTimeoutError(f'Token retrieval from {self.address} '
                                               f'with timeout: \'{self.timeout}\' timed out') from exc
        except requests.RequestException as exc:
            raise IdentityResolverCommunicationError(f'Failed to retrieve token from {self.address}') from exc

    def register_token(self, token: str):
        """
        Register a new document token against the REST resolver.
        :param token: document token

        :raises:
            IdentityResolverHttpError: if http error
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error
        """
        try:
            rsp = requests.post(
                f'{self.address}/1.0/register',
                headers={'Content-type': 'text/plain'},
                data=token,
                timeout=self.timeout
            )
            rsp.raise_for_status()
        except requests.HTTPError as exc:
            raise IdentityResolverHttpError(f'Can not register Resolver token ot {self.address}: \'{exc}\'') from exc
        except requests.Timeout as exc:
            raise IdentityResolverTimeoutError(f'Token registration with {self.address} '
                                               f'with timeout: \'{self.timeout}\' timed out') from exc
        except requests.RequestException as exc:
            raise IdentityResolverCommunicationError(
                f'Can not register Resolver token ot {self.address}: \'{exc}\'') from exc


class RESTResolverClient(ResolverClient):

    def __init__(self, requester: RESTResolverRequester, serializer: ResolverSerializer):
        self.requester = requester
        self.serializer = serializer

    def get_document(self, doc_id: str) -> RegisterDocument:
        """
        Get a valid register document from the REST resolver.
        :param doc_id: register document decentralised identifier
        :return: valid register document

        :raises:
            IdentityResolverError: if invalid resolver response
            IdentityResolverHttpDocNotFoundError: if document not found
            IdentityResolverHttpError: if http error
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error

        """
        token = self.requester.get_token(doc_id)
        return self.serializer.get_valid_doc_from_token(token, get_controller_doc=self.get_document)

    def register_document(self, document: RegisterDocument, private_key: ec.EllipticCurvePrivateKey,
                          issuer: Issuer, audience: str = ''):
        """
        Register a register document against the REST Resolver.
        :param document: register document
        :param issuer: issuer
        :param private_key: issuer private key
        :param audience: audience

        :raises:
            IdentityResolverHttpError: if http error
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error
            IdentityResolverError: if can not serialize document
        """
        token = self.serializer.serialize_to_token(document, private_key, issuer, audience)
        self.requester.register_token(token)


def get_rest_resolver_client(address: str, timeout: Optional[Union[int, float]] = 60.0) -> RESTResolverClient:
    """
    Get a REST resolver client
    :param address: http REST resolver url
    :param timeout: optional timeout seconds. Default=60s. If set to 0, requests will have no timeout.
    :return: REST resolver client
    """
    requester = RESTResolverRequester(address, timeout)
    serializer = ResolverSerializer()
    return RESTResolverClient(requester, serializer)
