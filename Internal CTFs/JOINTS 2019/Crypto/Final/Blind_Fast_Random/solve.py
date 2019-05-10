#!/usr/bin/env python

from fractions import gcd
import gmpy
from Crypto.Util.number import *
from pwn import *
from sympy import isprime
import time
from wiener import ContinuedFractions, Arithmetic

def factor_fermat(N):
    a = gmpy.sqrt(N)
    b2 = a*a - N
    tes = 0
    while not gmpy.is_square(gmpy.mpz(b2)):
        b2 += 2*a + 1
        a += 1
        tes+=1
        if tes > 3000:
            return "x","x"
	factor1 = a - gmpy.sqrt(b2)
	factor2 = a + gmpy.sqrt(b2)
    return (long(factor1.digits()), long(factor2.digits()))


def factor_rho(M):
    i=1
    power=2
    x=y=2
    p=1
    tes = 0
    while p==1:
        i+=1
        x=(x*x+2)%M
        p=gcd(abs(x-y),M)
        if i==power:
            y=x
            power*=2
        tes+=1
        if tes > 3000:
            return "x"
    if p!=M: return p
    else: return None

def wiener_attack(e,n):
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)
    for (k,d) in convergents:
        #check if d is actually the key
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s*s - 4*n
            if(discr>=0):
                t = Arithmetic.is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
		            return d


marsenne = [2281,3217,4253,4423,9689,2203,1279]
conn = remote("192.168.1.19", 50001)
awal = time.time()
for i in range(35):
  print "-----SOLVING STAGE {}----".format(i)
  conn.recvuntil("---\n", timeout=3)

  n = int(conn.recvline()[:-1].split(": ")[1])
  e = int(conn.recvline()[:-1].split(": ")[1])
  c = int(conn.recvline()[:-1].split(": ")[1])

  if isprime(n) == True:
    print "SINGLE PRIME"
    phi = n-1
    d = inverse(e,phi)
    hasil = pow(c,d,n)
    conn.sendline(str(hasil))
    continue

  binn = bin(n)[2:]
  satu = binn.count("1")
  nol = binn.count("0")

  if(satu in marsenne and nol in marsenne):
    p = pow(2,satu) - 1
    q = pow(2,nol) -1
    if p*q != n:
      print "salah"
    phi = (p-1)*(q-1)
    d = inverse(e,phi)
    hasil = pow(c,d,n)
    print "MERSENNE PRIME"
    conn.sendline(str(hasil))
    continue
  if e > 65537:
    print "WIENER ATTACK"
    d = wiener_attack(e,n)
    hasil = pow(c,d,n)
    conn.sendline(str(hasil))
    continue
  
  p,q = factor_fermat(n)
  if p != "x":
    print "FACTOR FERMAT"
    phi = (p-1)*(q-1)
    d = inverse(e,phi)
    hasil = pow(c,d,n)
    conn.sendline(str(hasil))
    continue

  p = factor_rho(n)
  if p!= "x":
    print "POLLARD RHO"
    q = n/p
    phi = (p-1)*(q-1)
    d = long(inverse(e,phi))
    hasil = pow(c,d,n)
    conn.sendline(str(hasil))
    continue

end = time.time()
print "\nTotal Waktu = {} detik".format(end - awal)
print conn.recvuntil("}")


    
