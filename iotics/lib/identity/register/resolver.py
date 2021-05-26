# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.register.document import RegisterDocument


class ResolverClient(ABC):

    @abstractmethod
    def get_document(self, doc_id: str) -> RegisterDocument:
        """
        Get a valid register document from the resolver.
        :param doc_id: register document decentralised identifier
        :return: valid register document

        :raises:
            IdentityResolverError: if invalid resolver response
            IdentityResolverDocNotFoundError: if document not found
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error
        """
        raise NotImplementedError

    @abstractmethod
    def register_document(self, document: RegisterDocument, private_key: ec.EllipticCurvePrivateKey,
                          issuer: Issuer, audience: str = ''):
        """
        Register a register document against the Resolver.
        :param document: register document
        :param issuer: issuer
        :param private_key: issuer private key
        :param audience: audience

        :raises:
            IdentityResolverError: if resolver error
            IdentityResolverError: if can not serialize document
            IdentityResolverTimeoutError: if timeout error
            IdentityResolverCommunicationError: if communication error
        """
        raise NotImplementedError
