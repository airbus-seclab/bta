#! /usr/bin/env python

from setuptools import setup, Command

class PyLint(Command):
    description = "run pylint"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        import sys,subprocess
        errno = subprocess.call(["pylint", "--rcfile", "./lint/pylintrc", "bta"],
                                env={"PYTHONPATH":"lint"})
        raise SystemExit(errno)




setup(
    name = 'bta',
    version = '0.3',
    packages=['bta', 'bta/tools', 'bta/backend', 'bta/miners', 'bta/formatters', 
              'libesedb'],
    scripts = ['bin/btaminer', 'bin/ntds2db', 'bin/btadiff', 'bin/btalist'],

    # Metadata
    author = 'Philippe Biondi',
    author_email = 'phil@secdev.org',
    description = 'Active Directory Auditing tool',

    cmdclass = {'lint': PyLint},

)
