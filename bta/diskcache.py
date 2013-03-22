import os
import cPickle
import functools
import itertools
import hashlib
import tempfile


def hashfile(fname, args):
    components = (fname,)+args
    hash = "bta"+"".join([hashlib.md5(x).hexdigest() for x in components])
    return os.path.join(tempfile.gettempdir(), hash)

def diskcache(*argsieve):
    def deco(f):
        @functools.wraps(f)
        def wrapper(*args):
            cache = hashfile(f.__name__, tuple(itertools.compress(args, argsieve)))
            if os.path.exists(cache):
                return cPickle.load(open(cache))
            ret = f(*args)
            cPickle.dump(ret, open(cache,"w"))
            return ret
    
        return wrapper
    return deco
