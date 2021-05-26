# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

from dataclasses import dataclass

from iotics.lib.identity.crypto.issuer import Issuer
from iotics.lib.identity.crypto.key_pair_secrets import KeyPairSecrets


@dataclass(frozen=True)
class RegisteredIdentity:
    key_pair_secrets: KeyPairSecrets
    issuer: Issuer

    @property
    def did(self):
        return self.issuer.did

    @property
    def name(self):
        return self.issuer.name
