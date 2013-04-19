#! /usr/bin/env python

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
        except Exception,e:
            dblog.update_entry("ERROR: %s" % e)
            raise
        else:
            dblog.update_entry("Graceful exit")

    def create_entry(self):
        e = dict(
            date = datetime.datetime.now(),
            program = sys.argv[0],
            args = sys.argv,
            version = pkg_resources.get_distribution("bta").version,
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

