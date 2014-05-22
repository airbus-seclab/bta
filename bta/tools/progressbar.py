# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import sys
import time, datetime
import struct, fcntl

def string_progress_bar(total, desc="Progress", step=100, obj="rec"):
    t0 = time.time()
    tprevstep = t0-0.01 # t0-tprevstem must always be != 0
    i = 0
    iprevstep = 0
    iprevcall = -1
    progress = None
    while True:
        new_i = yield progress
        progress = None
        i = new_i if new_i is not None else i+1
        if iprevcall/step != i/step or i >= total:
            t = time.time()
            avg = i/(t-t0)
            inst = (i-iprevstep)/(t-tprevstep)
            eta = datetime.timedelta(seconds=int((total-i)/inst))
            elapsed = datetime.timedelta(seconds=int(t-t0))
            tprevstep = t
            iprevstep = i
            progress = "%s: %i / %i  --  avg=%.2f %s/s inst=%.2f %s/s  --  ETA=%s elapsed=%s" % (desc, i, total, avg, obj, inst, obj, eta, elapsed)
        iprevcall = i

def stderr_progress_bar(*args, **kargs):
    spb = string_progress_bar(*args, **kargs)
    nval = None
    while True:
        r = spb.send(nval)
        if r is not None:
            # pylint: disable=anomalous-backslash-in-string
            sys.stderr.write("\033[A\033[K%s\n" % r)
        nval = yield


def null_progress_bar(total, desc="Progress", step=100, obj="rec"):
    # pylint: disable=unused-argument
    while True:
        yield


class MultiProgressBar(object):
    def __init__(self, mothership, *args, **kargs):
        self.mothership = mothership
        self.spb = string_progress_bar(*args, **kargs)
    def next(self):
        p = next(self.spb)
        if p is not None:
            self.mothership.update(self, p)
    def send(self, val):
        p = self.spb.send(val)
        if p is not None:
            self.mothership.update(self, p)
    def __del__(self):
        self.mothership.delete(self)

class StderrMultiProgressBarMothership(object):
    TIOCGWINSZ = 0x5413
    def __init__(self, manager):
        self.progress = manager.dict()
        self.lock = manager.Lock()
    def __call__(self, *args, **kargs):
        child = MultiProgressBar(self, *args, **kargs)
        self.progress[id(child)] = "--"
        return child
    def update(self, child, progress):
        if progress is not None:
            self.progress[id(child)] = progress
        self.refresh_screen()
    def delete(self, child):
        del(self.progress[id(child)])
        self.refresh_screen()
    def refresh_screen(self):
        # pylint: disable=anomalous-backslash-in-string
        with self.lock:
            # retrieve terminal window size
            rows,_cols = struct.unpack("HH", fcntl.ioctl(sys.stderr, self.TIOCGWINSZ,"xxxx"))
            sys.stderr.write("\033[s\033[r") # save cursor pos and remove scroll restrictions
            for row,p in enumerate(self.progress.values()+["=================="]):
                # go to row i, erase and write progress
                sys.stderr.write("\033[%i;1H\033[K%s" % (row+1, p))
            # set up scrolling to protect upper lines and restore cursor
            sys.stderr.write("\033[%i;%ir\033[u" % (len(self.progress)+2,rows))
    def __del__(self):
        # pylint: disable=anomalous-backslash-in-string
        sys.stderr.write("\033[r") # remove scrolling restrictions
