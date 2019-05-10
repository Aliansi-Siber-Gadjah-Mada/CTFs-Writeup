from pwn import *
import os

os.popen("""tshark -r canvas.pcapng -Tfields -e usb.capdata | awk -F: '{x=$3$4;y=$5$6}{z=$7}$1=="02"{print x,y,z}' > dump.txt""")
f = open('data.txt','wb')

for i in open('dump.txt').readlines():
    ii = i.strip().split(' ')
    x = int(ii[0], 16)
    y = int(ii[1], 16)
    z = int(ii[2], 16)

    if z > 0:
        f.write(u16(struct.pack(">H", x)), u16(struct.pack(">H", y)) + '\n')

os.popen('''gnuplot -e "plot 'data.txt'; pause -1"''')