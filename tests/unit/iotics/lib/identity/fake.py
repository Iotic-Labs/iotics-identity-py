# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from typing import Dict

from cryptography.hazmat.primitives.asymmetric import ec

from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.error import IdentityResolverDocNotFoundError
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.resolver import ResolverClient


class ResolverClientTest(ResolverClient):
    def __init__(self, docs: Dict[str, RegisterDocument] = None):
        self.docs = docs or {}

    def get_document(self, doc_id: str) -> RegisterDocument:
        doc = self.docs.get(doc_id.split('#')[0])
        if not doc:
            raise IdentityResolverDocNotFoundError(doc_id)
        return doc

    def register_document(self, document: RegisterDocument, private_key: ec.EllipticCurvePrivateKey,
                          issuer: Issuer, audience: str = ''):
        self.docs[issuer.did] = document
