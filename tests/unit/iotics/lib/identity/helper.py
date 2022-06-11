# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from typing import Iterable

from iotics.lib.identity.crypto.key_pair_secrets import DIDType
from iotics.lib.identity.register.document import RegisterDocument
from iotics.lib.identity.register.document_builder import RegisterDocumentBuilder
from iotics.lib.identity.register.keys import RegisterPublicKey, RegisterAuthenticationPublicKey, \
    RegisterDelegationProof


def get_doc_with_keys(public_keys: Iterable[RegisterPublicKey] = None,
                      auth_keys: Iterable[RegisterAuthenticationPublicKey] = None,
                      deleg_control: Iterable[RegisterDelegationProof] = None,
                      deleg_auth: Iterable[RegisterDelegationProof] = None,
                      controller: str = None,
                      did: str = None) -> RegisterDocument:
    builder = RegisterDocumentBuilder()
    _ = [builder.add_public_key_obj(k) for k in (public_keys or ())]
    _ = [builder.add_authentication_key_obj(k) for k in (auth_keys or ())]
    _ = [builder.add_control_delegation_obj(k) for k in (deleg_control or ())]
    _ = [builder.add_authentication_delegation_obj(k) for k in (deleg_auth or ())]

    return builder.build(did=did or 'did:iotics:iotDadb3rSWedk8iqExSbwqLtijG5XQByHC7',
                         purpose=DIDType.TWIN,
                         proof='a proof',
                         revoked=True,
                         controller=controller)
