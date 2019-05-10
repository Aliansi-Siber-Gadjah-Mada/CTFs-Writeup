#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import os
import sys

FLAG = open("flag.txt").read()

class Unbuffered(object):
  def __init__(self, stream):
    self.stream = stream
  def write(self, data):
    self.stream.write(data)
    self.stream.flush()
  def writelines(self, datas):
    self.stream.writelines(datas)
    self.stream.flush()
  def __getattr__(self, attr):
    return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

def pad(msg):
  byte = 16 - len(msg) % 16
  return msg + (chr(byte) * byte)


def unpad(msg):
  return msg[:-ord(msg[-1])]


def encrypt_cfb(msg, key):
  msg = pad(msg)
  iv  = msg[:16]
  msg = msg[16:]
  obj = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
  return iv + obj.encrypt(msg)


def encrypt_cbc(msg, iv, key):
  obj = AES.new(key, AES.MODE_CBC, iv)
  return obj.encrypt(msg)


def something_block_cipher(msg, key):
  iv    = msg[:16]
  msg   = [msg[i:i+16] for i in range(16, len(msg), +16)]
  prop  = iv
  cips  = ''

  for i in range(len(msg)):
    enc   = encrypt_cbc(msg[i], prop, key)
    cips += enc
    prop  = strxor(msg[i], enc)

  return iv+cips


def banner():
  print """
    ______                 __        __          __  
    / ____/______  ______  / /_____  / /   ____ _/ /_ 
  / /   / ___/ / / / __ \/ __/ __ \/ /   / __ `/ __ \\
  / /___/ /  / /_/ / /_/ / /_/ /_/ / /___/ /_/ / /_/ /
  \____/_/   \__, / .___/\__/\____/_____/\__,_/_.___/ 
            /____/_/

           Welcome to CryptoLab Challenge
         Solve this 2 stage to get the flag                                  
  """

def stage1():
  iv          = os.urandom(16)
  key         = os.urandom(16)
  secret_msg  = os.urandom(64)
  enc_msg     = encrypt_cfb((iv+secret_msg), key)

  print "======================== STAGE 1 ========================"
  print "Encrypted secret message : {}".format(enc_msg.encode('hex'))
  print """\nNow we open a service
  [1] Encrypt message
  [2] Guess secret message
  """
  while True:
    choice = raw_input("Choose : ")
    if choice == "1":
      plaintext = raw_input("Input your message : ")
      try:
        plaintext = plaintext.decode("hex")
        assert len(plaintext) >= 16
      except:
        print "Error !"
        exit()
      
      enc_plain = encrypt_cfb(plaintext, key)
      print "Encryption of your message : {}".format(enc_plain.encode("hex"))
    elif choice == "2":
      guess = raw_input("Secret message : ")
      try:
        guess = guess.decode("hex")
      except:
        print "Error !"
        exit()

      if guess == secret_msg:
        print "Success, continue to Stage 2 !"
        return
      else:
        print "Wrong guess !"
    else:
      print "Invalid choice !"


def stage2():
  iv          = os.urandom(16)
  key         = os.urandom(16)
  test_msg    = os.urandom(64)
  signature   = something_block_cipher((iv+test_msg), key)
  
  print "======================== STAGE 2 ========================"
  print "Test Message : {}".format(test_msg.encode("hex"))
  print "Signature    : {}".format(signature.encode("hex"))
  print "\nSend different message with same signature (ignore iv) !"
  while True:
    input_msg = raw_input("Input message : ")
    try:
      input_msg = input_msg.decode("hex")
      msg       = input_msg[16:]
      assert len(input_msg) >= 32 and len(input_msg) % 16 == 0 
    except:
      print "Error !"
      exit()

    if msg == test_msg:
      print "Nope, same message is not allowed !"
      exit()

    enc_input = something_block_cipher(input_msg, key)
    if enc_input[16:] == signature[16:]:
      return
    else:
      print "Signature not match !"

    
if __name__ == "__main__":
  banner()
  stage1()
  stage2()
  print "Congrats, you pwn this Lab :)"
  print "FLAG : {}".format(FLAG)