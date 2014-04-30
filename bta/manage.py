#! /usr/bin/env python

import argparse
import logging
from bta.tools.registry import Registry
from bta.backend import Backend
from bta.tools.ask import ask
import bta.backend.mongo

log = logging.getLogger("bta.manage")

class CommandRegistry(Registry):
    pass


class Command(object):
    _name_ = "noname"
    _desc_ = "N/A"

    @staticmethod
    def register(f):
        return CommandRegistry.register_ref(f, key="_name_")

    @classmethod
    def create_arg_parser(cls):
        parser = argparse.ArgumentParser()
        parser.add_argument("--connection", "-C", default="127.0.0.1:27017")
        parser.add_argument("--backend-type", "-B", default="mongo",
                            help="database backend (amongst: %s)" % (", ".join(Backend.backends.keys())))

        subparsers = parser.add_subparsers(dest="command_name", help="Commands")
        for cmd in CommandRegistry.itervalues():
            p = subparsers.add_parser(cmd._name_, help=cmd._desc_)
            cmd.create_arg_subparser(p)
        return parser

    @classmethod
    def create_arg_subparser(cls, parser):
        pass

    def __init__(self, options):
        self.options = options
        self.db = options.cnx

    def run(self):
        raise NotImplementedError()

@Command.register
class List(Command):
    _name_ = "ls"
    _desc_ = "List all BTA databases along with their latest modification"

    def run(self):
        for dbn in self.db.database_names():
            db = self.db[dbn]
            if db.log.count() == 0:
                continue
            acts = db.log.find().sort("date",-1).limit(1).next()
            print "%-15s: %s" % (dbn, acts["actions"][-1]["action"])

@Command.register
class Remove(Command):
    _name_ = "rm"
    _desc_ = "Remove BTA databases"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("dbnames", nargs="+")
        parser.add_argument("--force", "-f", action="store_true")
        parser.add_argument("--interactive", "-i", action="store_true")
        parser.add_argument("--dry-run", "-N", action="store_true")

    def run(self):
        for dbn in self.options.dbnames:
            db = self.db[dbn]
            if db.log.count() == 0:
                print "{0} does not look like a BTA database".format(dbn),
                if self.options.force:
                    print "but deletion is forced"
                else:
                    print ". Nothing done."
                    continue
            if self.options.interactive:
                if ask("Remove {0} ?".format(dbn),"yn") == "n":
                    continue
            if not self.options.dry_run:
                self.db.drop_database(dbn)

def main():
    parser = Command.create_arg_parser()
    options = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-5s: %(message)s")

    backend = Backend.get_backend(options.backend_type)
    options.cnx = backend.connect(options)

    cmd = CommandRegistry.get(options.command_name)
    c = cmd(options)
    c.run()


if __name__ == "__main__":
    main()
