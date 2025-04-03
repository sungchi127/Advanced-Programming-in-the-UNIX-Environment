#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import base64
import hashlib
import time
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    print(time.time(), "done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))

if __name__ == '__main__':
    #r = remote('localhost', 10330);
    r = remote('up23.zoolab.org', 10363)
    solve_pow(r)
    print('***')
    p=r.recvuntil(b"?") # 接收(num)行
    # print(p)
    n=p.rfind(b':')
    que=p[n+1:-3]
    ques=que.split(b' ')
    strans=ques[1]+ques[2]+ques[3]
    ans=eval(strans)
    # print("ans:",ans)
    littlebyte=(ans).to_bytes(16, 'little').rstrip(b'\x00')
    bytes_encode = base64.b64encode(littlebyte)
    r.sendline(bytes_encode)
    print("bytes_encode",bytes_encode)

    numindex=p.find(b"challenges")
    num=p[numindex-4:numindex-1]


    # print("num:",num)
    # print('*******')
    intnum=int(num)
    for i in range(intnum-1):
        pp=r.recvuntil(b'?')
        n=pp.rfind(b':')
        que=pp[n+1:-3]
        ques=que.split(b' ')
        strans=ques[1]+ques[2]+ques[3]
        ans=eval(strans)
        print(ans)
        littlebyte=(ans).to_bytes(16, 'little').rstrip(b'\x00')
        bytes_encode = base64.b64encode(littlebyte)
        r.sendline(bytes_encode)

    r.interactive()
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
