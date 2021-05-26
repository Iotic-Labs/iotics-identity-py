# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from dataclasses import dataclass
from typing import Dict, Optional

from iotics.lib.identity.const import DOCUMENT_CONTEXT, DOCUMENT_MAX_COMMENT_LENGTH, DOCUMENT_MAX_LABEL_LENGTH, \
    DOCUMENT_MAX_URL_LENGTH, DOCUMENT_VERSION
from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import DIDType
from iotics.lib.identity.error import IdentityValidationError
from iotics.lib.identity.register.keys import RegisterAuthenticationPublicKey, RegisterDelegationProof, \
    RegisterPublicKey


@dataclass(frozen=True)
class Metadata:
    label: Optional[str] = None
    comment: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self):
        ret = {}
        if self.label:
            ret['label'] = self.label
        if self.comment:
            ret['comment'] = self.comment
        if self.url:
            ret['url'] = self.url
        return ret

    @staticmethod
    def from_dict(data: dict):
        """
        Build register metadata from dict.
        :param data: register metadata as dict
        :return: valid register metadata

        :raises:
            IdentityValidationError: if invalid metadata as dict
        """
        return Metadata.build(data.get('label'), data.get('comment'), data.get('url'))

    @staticmethod
    def build(label: Optional[str], comment: Optional[str], url: Optional[str]):
        """
        Build register metadata.
        :param label: metadata label
        :param comment: metadata comment
        :param url: metadata url
        :return: valid register metadata

        :raises:
            IdentityValidationError: if invalid label
            IdentityValidationError: if invalid comment
            IdentityValidationError: if invalid url
        """
        if label and len(label) > DOCUMENT_MAX_LABEL_LENGTH:
            raise IdentityValidationError(f'Document metadata label it too long, max size: \'{label}\'')
        if comment and len(comment) > DOCUMENT_MAX_COMMENT_LENGTH:
            raise IdentityValidationError(f'Document metadata comment it too long, max size: \'{comment}\'')
        if url and len(url) > DOCUMENT_MAX_URL_LENGTH:
            raise IdentityValidationError(f'Document metadata url it too long, max size: \'{url}\'')
        return Metadata(label, comment, url)


@dataclass(frozen=True)
class RegisterDocument:
    public_keys: Dict[str, RegisterPublicKey]
    auth_keys: Dict[str, RegisterAuthenticationPublicKey]
    auth_delegation_proof: Dict[str, RegisterDelegationProof]
    control_delegation_proof: Dict[str, RegisterDelegationProof]
    did: str
    purpose: DIDType
    proof: str
    revoked: bool
    spec_version: str = DOCUMENT_VERSION
    metadata: Metadata = Metadata()
    creator: Optional[str] = None
    update_time: Optional[int] = None
    controller: Optional[Issuer] = None

    def to_dict(self) -> dict:
        """
        Serialise thee register document to dict.
        :return: register document as dict
        """
        ret = {
            '@context': DOCUMENT_CONTEXT,
            'id': self.did,
            'ioticsSpecVersion': self.spec_version,
            'ioticsDIDType': self.purpose.value,
            'updateTime': self.update_time,
            'proof': self.proof,
            'publicKey': [k.to_dict() for _, k in self.public_keys.items()],
            'authentication': [k.to_dict() for _, k in self.auth_keys.items()],
            'delegateControl': [k.to_dict() for _, k in self.control_delegation_proof.items()],
            'delegateAuthentication': [k.to_dict() for _, k in self.auth_delegation_proof.items()],
            'metadata': self.metadata.to_dict(),
            'revoked': self.revoked

        }
        if self.controller:
            ret['controller'] = str(self.controller)
        if self.creator:
            ret['creator'] = self.creator
        return ret
