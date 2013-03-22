#! /usr/bin/env python

from setuptools import setup

setup(
    name = 'bta',
    version = '0.1',
    packages=['bta', 'bta/backend', 'bta/miners', 'bta/formatters', 
              'libesedb'],
    scripts = ['bin/miners', 'bin/ntds2db'],

    # Metadata
    author = 'Philippe Biondi',
    author_email = 'phil@secdev.org',
    description = 'Active Directory Auditing tool',
)
