from pwn import *


r = remote("192.168.1.19", 50000)

def solve_stage_1():
  print r.recvuntil("secret message : ")
  enc_secret = r.recvline()[:-1].decode('hex')
  iv = enc_secret[:16]
  secret_msg = ""

  for i in range(4):
    payload = iv + secret_msg + "\x00"*16
    
    r.sendlineafter("Choose : ", "1")
    r.sendline(payload.encode("hex"))
    r.recvuntil("Encryption of your message : ")
    
    intermediate = r.recvline()[:-1].decode("hex")[16*(i+1):16*(i+2)]
    frac_msg = xor(intermediate, enc_secret[16*(i+1):16*(i+2)])
    secret_msg += frac_msg

  r.sendline("2")
  r.sendlineafter("Secret message : ", secret_msg.encode("hex"))


def solve_stage_2():
  print r.recv()
  print r.recvuntil("Test Message : ")
  test_msg  = r.recvline()[:-1].decode("hex")
  test_msg = [test_msg[i:i+16] for i in range(0, len(test_msg), +16)]
  print r.recvuntil("Signature    : ")
  signature = r.recvline()[:-1].decode("hex")
  iv = signature[:16]
  enc_real = [signature[i:i+16] for i in range(16, len(signature), +16)]
  
  plain    = iv
  payload  = ''
  payload += test_msg[0]
  payload += iv

  for i in range(1,len(enc_real)):
    new_plain = xor(plain, test_msg[i-1])
    new_plain = xor(new_plain, test_msg[i])
    plain     = new_plain
    payload  += new_plain
  
  r.sendlineafter("Input message : ", payload.encode("hex"))
  print r.recvuntil("}")


if __name__ == '__main__':
  solve_stage_1()
  solve_stage_2() 