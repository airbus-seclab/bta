# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

def importer_for(path):
    def import_all(path=path):
        import os,pkgutil
        folder = os.path.dirname(path)
        for importer,name,_ in pkgutil.iter_modules([folder]):
            loader = importer.find_module(name)
            loader.load_module(name)
    return import_all
