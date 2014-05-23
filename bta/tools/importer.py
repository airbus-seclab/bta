# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import logging

log = logging.getLogger("bta.importer")

def importer_for(path):
    def import_all(path=path):
        import os,pkgutil
        folder = os.path.dirname(path)
        for importer,name,_ in pkgutil.iter_modules([folder]):
            loader = importer.find_module(name)
            try:
                loader.load_module(name)
            except ImportError,e:
                log.warning("Cannot load BTA plugin [%s]. Root cause: %s" % (name,e))
    return import_all
