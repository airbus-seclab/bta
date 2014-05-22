#! /usr/bin/env python

# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

"""
Stores action logs to the "log" table in backend.
Used for long-running operations (ex. btaimport).
Automatically action status (exception occurred, interrupted, success).
"""

import sys
import datetime
import pkg_resources
import contextlib

class DBLogEntry(object):
    def __init__(self, backend):
        self.backed = backend
        self.log = backend.open_table("log")
        self.log.ensure_created()

    @classmethod
    @contextlib.contextmanager
    def dblog_context(cls, backend):
        dblog = cls(backend)
        dblog.create_entry()
        try:
            yield dblog
        except KeyboardInterrupt:
            dblog.update_entry("Interrupted by user (Ctrl-C)")
            raise
        except Exception, e:
            dblog.update_entry("ERROR: %s" % e)
            raise
        else:
            dblog.update_entry("Graceful exit")

    def create_entry(self):
        e = dict(
            date = datetime.datetime.now(),
            program = sys.argv[0],
            args = sys.argv,
            # pylint: disable=maybe-no-member
            version = pkg_resources.get_distribution("bta").version,
            # pylint: enable=maybe-no-member
            actions = [],
            )
        self.entry_id = self.log.insert(e)

    def update_entry(self, action):
        act = dict(
            date = datetime.datetime.now(),
            )
        if type(action) is dict:
            act.update(action)
        else:
            act["action"] = action

        self.log.update({"_id": self.entry_id},
                        {"$push":{"actions":act}})

