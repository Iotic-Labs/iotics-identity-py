# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from _blake2 import blake2b  # type: ignore

import base58

from iotics.lib.identity.const import IDENTIFIER_PREFIX, ISSUER_SEPARATOR


def is_same_identifier(issuer_a: str, issuer_b: str) -> bool:
    """
    check if 2 issuers string have the same identifier
    :param issuer_a: issuer string a
    :param issuer_b: issuer string b
    :return: True if identifier are the same else False
    """
    return issuer_a.split(ISSUER_SEPARATOR)[0] == issuer_b.split(ISSUER_SEPARATOR)[0]


IDENTIFIER_METHOD = 0x05
IDENTIFIER_VERSION = 0x55
IDENTIFIER_PAD = 0x59


def make_identifier(public_bytes: bytes) -> str:
    """
    Generate a new decentralised identifier from public key as bytes
    :param public_bytes: public key as bytes
    :return: decentralised identifier
    """
    bl2 = blake2b(digest_size=20)
    bl2.update(public_bytes)
    pk_digest = bl2.digest()

    cl2 = blake2b(digest_size=20)
    cl2.update(pk_digest)
    checksum = bytearray.fromhex(cl2.hexdigest())[:4]

    return IDENTIFIER_PREFIX + base58.b58encode(bytes([IDENTIFIER_METHOD, IDENTIFIER_VERSION, IDENTIFIER_PAD])
                                                + pk_digest + checksum).decode('ascii')
