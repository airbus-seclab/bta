#! /usr/bin/env python

import os
from setuptools import setup, Command

class PyLint(Command):
    description = "run pylint"
    user_options = [
        ("reports","r", "Output pylint reports"),
        ("errors-only", "E", "Output errors only"),
    ]
    def initialize_options(self):
        self.reports = False
        self.errors_only = False
    def finalize_options(self):
        pass
    def run(self):
        import sys,subprocess
        pth = os.path.dirname(__file__)
        lintpth = os.path.join(pth, "lint")
        pylintrcpth = os.path.join(lintpth, "pylintrc")
        btapth = os.path.join(pth, "bta")
        cmd = ["pylint", "--rcfile", pylintrcpth, btapth]
        if self.reports:
            cmd += ["--reports=y"]
        if self.errors_only:
            cmd += ["--errors-only"]
        errno = subprocess.call(cmd, env={"PYTHONPATH":lintpth})
        raise SystemExit(errno)

class PyTest(Command):
    description = "run py.test unit tests"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        import sys,subprocess
        pth = os.path.dirname(__file__)
        testpth = os.path.join(pth, "test")
        runtestspth = os.path.join(pth, "runtests.py")
        errno = subprocess.call([sys.executable, runtestspth, testpth])
        raise SystemExit(errno)




setup(
    name = 'bta',
    version = '0.3',
    packages=['bta', 'bta/tools', 'bta/backend', 'bta/miners', 'bta/formatters', 
              'libesedb'],
    scripts = ['bin/btaminer', 'bin/btaimport', 'bin/btadiff', 'bin/btamanage'],

    # Metadata
    author = 'Philippe Biondi',
    author_email = 'phil@secdev.org',
    description = 'Active Directory Auditing tool',

    cmdclass = {
        'lint': PyLint,
        'test': PyTest,
    },

)
