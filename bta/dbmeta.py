#! /usr/bin/env python

# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

"""
Stores metadata to the "metadata" table in backend.
Used for import metadata, as a key-value store.
Ex: bta-import database format version
"""

class DBMetadataEntry(object):
    def __init__(self, backend):
        self.backend = backend
        self.log = backend.open_table("metadata")
        self.log.ensure_created()

    def get_value(self, key):
        """Get metadata value.

        :returns: None if value does not exist

        """
        result = self.log.find_one({key: {"$exists": "true"}})
        if result is None:
            return None
        return result[key]

    def set_value(self, key, value):
        """Set or update metadata value"""
        self.log.update({key: {"$exists": "true"}}, {key: value}, True, multi=False)

