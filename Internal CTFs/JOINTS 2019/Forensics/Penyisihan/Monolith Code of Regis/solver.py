from bs4 import BeautifulSoup
from glob import glob
import os

def parse(filename):
	html  = open(filename).read()	
	soup  = BeautifulSoup(html,'lxml')
	row   = soup.select('div[class="row"]')
	block = [i.select('div[class="block"]') for i in row]
	res   = ''

	for i in block:
		init = [1 if j.find('div') else 0 for j in i]
		for count, dot in enumerate(init):
			if dot:
				res += ('0','1')[not count%2]

	data = [int(res[i:i+8], 2)for i in range(0,len(res),8)]
	return ''.join(map(chr,data))

file = glob('dump/*.html')
res  = []
for i,j in enumerate(file):
	res += [parse(j)]
	print '%s\n%s\n' % (j,res[i])

print '[+] Getting flag'
data = res[5]
out  = data.replace(' \n','')
open('flag.zip','wb').write(out.decode('base64'))
os.popen('7z x -p{} flag.zip'.format(res[4])) 
os.system('cat flag.txt')
