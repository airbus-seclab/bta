#! /usr/bin/env python

import sys
import datetime
import pkg_resources

class DBLogEntry(object):
    def __init__(self, backend):
        self.backed = backend
        self.log = backend.open_table("log")
        self.log.ensure_created()

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

