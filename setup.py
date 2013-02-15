#! /usr/bin/env python

from setuptools import setup

setup(
    name = 'bta',
    version = '0.1',
    packages=['ntds', 'ntds/backend', 'ntds/miners', ],
    scripts = ['bin/miners', 'bin/ntds2db'],

    # Metadata
    author = 'Philippe Biondi',
    author_email = 'phil@secdev.org',
    description = 'Active Directory Auditing tool',
)
