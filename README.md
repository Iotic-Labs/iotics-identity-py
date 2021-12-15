# iotics-identity-py

[![PyPi version](https://pypip.in/v/iotics-identity/badge.svg)](https://pypi.org/project/iotics-identity/)
[![PyPi downloads](https://pypip.in/d/iotics-identity/badge.svg)](https://pypi.org/project/iotics-identity/#files)
[![PyPi wheel](https://pypip.in/wheel/iotics-identity/badge.svg)](https://pypi.org/project/iotics-identity/#files)
[![PyPi license](https://pypip.in/license/iotics-identity/badge.svg)](https://pypi.org/project/iotics-identity)
[![GitHub Issues](https://img.shields.io/github/issues/Iotic-Labs/iotics-identity-py)](https://github.com/Iotic-Labs/iotics-identity-py/issues)
[![GitHub Contributors](https://img.shields.io/github/contributors/Iotic-Labs/iotics-identity-py)](https://github.com/Iotic-Labs/iotics-identity-py)

Create Data Mesh. Use interoperable digital twins to create data interactions and build powerful real-time data products. This repository is a library for Decentralised Identity (DID) management with Iotics for applications in Python v3.8+.

You need to have an IOTICSpace to take advantage of this DID SDK. Contact <a href="mailto:product@iotics.com">product@iotics.com</a> for a free trial or [![sign up](https://img.shields.io/badge/sign%20up-164194.svg?style=flat)](https://www.iotics.com/signup-preview-program/)

## Introduction to Iotics

Interoperate any data, digital twin or service across legacy, on-prem, cloud, IoT, and analytical technologies creating a secure decentralised, federated network of interactions.

Power long-term digital transformation using real-time business event streams. Unlock the power of your business by eliminating complex infrastructure and shortening time-to-value.

To learn more about IOTICS see our [website](https://www.iotics.com/) or [documentation site](https://docs.iotics.com).

## Identity API

The identity API is used to manage identities and authentication in the Iotics Host.
The API is split in 3 level according to the user needs:

* [High level identity API](https://github.com/Iotic-Labs/iotics-identity-py/tree/main/iotics/lib/identity/api/high_level_api.py): minimal set of features to interact with Iotics Host
* [Identity API](https://github.com/Iotic-Labs/iotics-identity-py/tree/main/iotics/lib/identity/api/regular_api.py): set of features for basic identities management
* [Advanced identity API](https://github.com/Iotic-Labs/iotics-identity-py/tree/main/iotics/lib/identity/api/advanced_api.py): set of features for advanced identities management

## How to

Two examples are provided to illustrate the usage of the **high level API** and the **regular api**.
See [Iotics Identity API How To](https://github.com/Iotic-Labs/iotics-identity-py/tree/main/how_to/README.md).

You can also follow these tutorials on [docs.iotics.com](https://docs.iotics.com/docs/create-decentralized-identity-documents).

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

## Reporting issues

The issue tracker for this project is currently located at [GitHub](https://github.com/Iotic-Labs/iotics-identity-py/issues).

Please report any issues there with a sufficient description of the bug or feature request. Bug reports should ideally be accompanied by a minimal reproduction of the issue. Irreproducible bugs are difficult to diagnose and fix (and likely to be closed after some period of time).

Bug reports must specify the version of the `iotics-identity-py` module.

## Contributing

This project is open-source and accepts contributions. See the [contribution guide](https://github.com/Iotic-Labs/iotics-identity-py/tree/main/CONTRIBUTING.md) for more information.

## License

Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/Iotic-Labs/iotics-identity-py/tree/main/LICENSE) in the project root for license information.

## Technology Used

* Markdown
* Python
* pylint
* pytest
* mypy
* Tox
* DID
* BDD
