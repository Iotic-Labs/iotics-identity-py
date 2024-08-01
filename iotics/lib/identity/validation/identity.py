# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import re
from hashlib import blake2b

import base58

from iotics.lib.identity.const import IDENTIFIER_ID_PATTERN, IDENTIFIER_NAME_PATTERN, ISSUER_PATTERN, IDENTIFIER_PREFIX
from iotics.lib.identity.error import IdentityValidationError


class IdentityValidation:
    @staticmethod
    def validate_identifier(did: str):
        """
        Validate decentralised identifier.
        :param did: decentralised identifier

        :raises:
            IdentityValidationError: if invalid identifier
        """
        result = re.match(IDENTIFIER_ID_PATTERN, did)
        if result is None:
            raise IdentityValidationError(f'Identifier does not match pattern {did} - {IDENTIFIER_ID_PATTERN}')

        did_bytes = base58.b58decode(did[len(IDENTIFIER_PREFIX):], alphabet=base58.BITCOIN_ALPHABET)
        did_digest = did_bytes[3:23]
        did_checksum = did_bytes[-4:].hex()

        cl2 = blake2b(digest_size=20)
        cl2.update(did_digest)
        checksum = cl2.hexdigest()[:8]

        if did_checksum != checksum:
            raise IdentityValidationError(f'Identifier checksum does not match {did_checksum} != {checksum}')

    @staticmethod
    def validate_issuer_string(issuer: str):
        """
        Validate issuer.
        :param issuer: issuer as string

        :raises:
            IdentityValidationError: if invalid issuer
        """
        result = re.match(ISSUER_PATTERN, issuer)
        if result is None:
            raise IdentityValidationError(f'Identifier does not match pattern {issuer} - {ISSUER_PATTERN}')

    @staticmethod
    def validate_key_name(name: str) -> bool:
        """
        Validate key name.
        :param name: key name

        :raises:
            IdentityValidationError: if invalid key name
        """
        m = re.match(IDENTIFIER_NAME_PATTERN, name)
        if m is None:
            raise IdentityValidationError(f'Name is not valid: {name} - {IDENTIFIER_NAME_PATTERN}')
        return True
