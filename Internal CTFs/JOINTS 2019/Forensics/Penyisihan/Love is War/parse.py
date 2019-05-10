from PIL import Image
from qr import read
import re, requests, os, time

print '[+] Parsing PCAP file'
if not os.path.exists('parse.txt'):
	os.popen("""tshark -r dns.pcap | awk '{print $7,$4,$6,$9}' | head -2 > parse.txt""")
if not os.path.exists('parse2.txt'):
	os.popen("""tshark -r dns.pcap -d 'udp.port==58,dns' -Y 'udp.port==58' | awk '{print $14}' | head -14 | egrep '[A-Z]' | sort | uniq > parse2.txt""")
if not os.path.exists('names.txt'):
	os.popen("""tshark -r dns.pcap -d 'udp.port==58,dns' -Tfields -e dns.qry.name | sed 's/\.joints.id//g' | grep '\.' | uniq > names.txt""")

data  = open('parse.txt').read().split('\n')[:-1]
data2 = open('parse2.txt').read().split('\n')[:-1]
data  = map(lambda x : x.split(),data)
print ' [v] Protocol\t: {}'.format(data[0][0])
print ' [v] Port\t: {}, {}'.format(data[0][3],data[1][3])
print ' [v] IPv4\t: {}, {}'.format(data[0][1],data[0][2])
print
print '[+] Decoding UDP packet as DNS'
print ' [v] DNS Query : {}'.format(', '.join(data2))
print
print '[+] Collecting DNS Query Name'
print ' [v] Found Messages'

r    = re.compile(r'[^A-Za-z0-9+/=.: -]')
file = open('names.txt').read().split('\n')[:-1]
hexa = map(lambda x : ''.join(x.strip().split('.')), file)
res  = ''

for i in hexa:
	tmp  = i[18:].decode('hex')
	res += r.sub('',tmp)

url  = res[:34]
cont = re.findall(r'<p>(.*?)</p>',requests.get(url).text)
print '  - ',url
print '  - ','\n     '.join(cont[4:6])

b64 = res[36:-28]
print '  - ',b64[:8]
print '  - ',b64[:8].decode('base64')[:-1]
print '  - ',res[-28:]
print '[+] Dumping PNG file'
open('out.png','wb').write(b64.decode('base64'))
time.sleep(2.0)
Image.open('out.png').show()
print read('out.png')