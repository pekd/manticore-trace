#!/usr/bin/env python2

import os
import sys
from manticore import Manticore

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [binary]\n" % (sys.argv[0],))
        sys.exit(2)

    m = Manticore(sys.argv[1], sys.argv[2:])

    @m.hook(None)
    def explore(state):
        rsp = state.cpu.RSP
        size = 0x00007fffffffffff - rsp + 1
        rawstack = state.cpu.read_bytes(rsp, size, True)
        stack = bytearray(rawstack)
        os.write(1, stack)
        sys.exit(0)

    #m.run(procs=3)
    m.run()

    #print("Executed " + m.context['count'] + " instructions.")
