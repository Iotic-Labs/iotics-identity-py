# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.
# For pkgutil namespace compatibility only. Must NOT contain anything else. See also:
# https://packaging.python.org/guides/packaging-namespace-packages/#pkgutil-style-namespace-packages
__path__ = __import__('pkgutil').extend_path(__path__, __name__)  # type: ignore

from iotics.lib.identity.api import *  # noqa: F403,F401
from iotics.lib.identity.error import *  # noqa: F403,F401
from iotics.lib.identity.register.resolver import *  # noqa: F403,F401
from iotics.lib.identity.register.rest_resolver import *  # noqa: F403,F401
