# Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

import os

from setuptools import setup


def get_version():
    version = os.environ.get('VERSION')
    if not version:
        raise ValueError('The VERSION environment variable must be set and not empty')
    return version


if __name__ == '__main__':
    setup(version=get_version())
