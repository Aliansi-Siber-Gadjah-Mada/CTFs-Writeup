#!/usr/bin/env python

import time
from Crypto.Util.number import *
from sympy import *
import random
from fractions import gcd
import os
import sys
from wiener import generateKeys

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


FLAG        = "JOINTS19{Blind_Rs4_Inj3ction(?)}"
time_limit  = 7
stages      = 35
liss        = ["fermat","singleprime","pollard","wiener","marsenne"]
mersenne    = [2281,3217,4253,4423,2203,1279]
 
print("Solve {} stage to get the flag !".format(stages))
print("You have {} second per stage".format(time_limit))
print("Send decrypted c in decimal form\n")

for i in range(stages):
  print("----------------STAGE {}----------------".format(i+1))
  message = os.urandom(64)
  teknik = random.choice(liss)

  if teknik == "fermat":
    while True:
      p = getStrongPrime(1024)
      q = nextprime(nextprime(nextprime(nextprime(p))))
      n = p*q
      e = 65537
      check = gcd(e, (p-1)*(q-1)) == 1
      if check: break

  elif teknik == "singleprime":
    n = getStrongPrime(2048)
    e = 65537

  elif teknik == "pollard":
    while True:
      p = nextprime(random.randrange(100000,300000))
      q = getStrongPrime(1024)
      n = p * q
      e = 65537
      check = gcd(e, (p-1)*(q-1)) == 1
      if check: break

  elif teknik == "marsenne":
    while True:
      e = 65537
      p = pow(2,random.choice(mersenne))-1
      q = pow(2,random.choice(mersenne))-1
      n = p*q
      check = (gcd(e, (p-1)*(q-1)) == 1) and (p != q)
      if check: break

  else:
    e,n,d = generateKeys(1024)

  
  enc = pow(bytes_to_long(message),e,n)
  print("n : {}".format(n))
  print("e : {}".format(e))
  print("c : {}".format(enc))

  awal    = time.time()
  submit  = raw_input("Answer : ")
  akhir   = time.time()

  if akhir - awal <= time_limit:
    try:
      submit = int(submit)
    except:
      print("\nError!")
      break
    if long_to_bytes(submit) == message:
      print("\nCorrect")
      if i == stages-1:
          print("Congratulation, your flag : {}".format(FLAG))
    else:
      print("\nWrong!")
      break
  else:
    print("\nTimes Up")
    break       
          