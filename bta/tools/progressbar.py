# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import sys
import time, datetime

def stderr_progress_bar(total, desc="Progress", step=100, obj="rec"):
    t0 = time.time()
    tprevstep = t0-0.01 # t0-tprevstem must always be != 0
    i = 0
    iprevstep = 0
    iprevcall = -1
    while True:
        new_i = yield
        i = new_i if new_i is not None else i+1
        if iprevcall/step != i/step or i >= total:
            t = time.time()
            avg = i/(t-t0)
            inst = (i-iprevstep)/(t-tprevstep)
            eta = datetime.timedelta(seconds=int((total-i)/inst))
            elapsed = datetime.timedelta(seconds=int(t-t0))
            tprevstep = t
            iprevstep = i
            sys.stderr.write("\033[A\033[K%s: %i / %i  --  avg=%.2f %s/s inst=%.2f %s/s  --  ETA=%s elapsed=%s\n" % 
                             (desc, i, total, avg, obj, inst, obj, eta, elapsed))
        iprevcall = i
