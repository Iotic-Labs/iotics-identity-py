# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

# Secrets validation

MIN_SEED_METHOD_NONE_LEN = 16
KEY_PAIR_PATH_PREFIX = 'iotics/0'

# Identifier Validation
NAME_PATTERN_RAW = r'[a-zA-Z\-\_0-9]{1,24}'
ISSUER_SEPARATOR = '#'
IDENTIFIER_PREFIX = 'did:iotics:'
IDENTIFIER_ID = fr'{IDENTIFIER_PREFIX}iot(?P<hash>[a-km-zA-HJ-NP-Z1-9]{{33}})'
IDENTIFIER_ID_PATTERN = fr'^{IDENTIFIER_ID}$'
IDENTIFIER_NAME_PATTERN = fr'^\{ISSUER_SEPARATOR}{NAME_PATTERN_RAW}$'
ISSUER_PATTERN = fr'^{IDENTIFIER_ID}\#{NAME_PATTERN_RAW}'

# Document constants
DOCUMENT_CONTEXT = 'https://w3id.org/did/v1'
DOCUMENT_VERSION = '0.0.1'
SUPPORTED_VERSIONS = ('0.0.0', DOCUMENT_VERSION)
# public key type string
DOCUMENT_PUBLIC_KEY_TYPE = 'Secp256k1VerificationKey2018'
# authentication public key type string
DOCUMENT_AUTHENTICATION_TYPE = 'Secp256k1SignatureAuthentication2018'
# Document metadata validation
DOCUMENT_MAX_LABEL_LENGTH = 64
DOCUMENT_MAX_COMMENT_LENGTH = 512
DOCUMENT_MAX_URL_LENGTH = 512

# Token constants
# Default offset for token valid-from time used. This is to avoid tokens being rejected when the client time is
# marginally ahead of the server (i.e. resolver or Iotics host).
DEFAULT_TOKEN_START_OFFSET_SECONDS = -30
TOKEN_ALGORITHM = 'ES256'
