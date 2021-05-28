# iotics-identity-py

This is a Python v3.8+ library for Decentralised Identity (DID) management with Iotics.

## License

Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) in the project root for license information.

## Identity API

The identity API is used to manage identities and authentication in the Iotics Host.
The API is split in 3 level according to the user needs:

* [High level identity API](iotics/lib/identity/api/high_level_api.py): minimal set of features to interact with Iotics Host
* [Identity API](iotics/lib/identity/api/regular_api.py): set of features for basic identities management
* [Advanced identity API](iotics/lib/identity/api/advanced_api.py): set of features for advanced identities management

## How to

Two examples are provided to illustrate the usage of the **high level API** and the **regular api**.
See [Iotics Identity API How To](./how_to/README.md).

* Setup your dev environment: \
  `pip install .[dev]`

* Run the linter: \
  `tox -e lint`

* Run type analysis: \
  `tox -e mypy`

* Run unit tests: \
  `tox -e pytest`

* Run BDD tests: \
  `tox -e pytestbdd`

## Technology Used

* Markdown
* Python
* pylint
* pytest
* mypy
* Tox
* DID
* BDD
