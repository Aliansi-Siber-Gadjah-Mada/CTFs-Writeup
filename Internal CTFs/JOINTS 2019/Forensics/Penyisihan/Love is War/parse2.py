import os,re, time

print '[+] Parsing PCAP file'
if not os.path.exists('parse3.txt'):
    os.popen("""tshark -r captured_log.pcap | awk '{print $7,$4,$6,$9}' | head -5 | sort | uniq > parse3.txt""")
if not os.path.exists('parse4.txt'):
	os.popen("""tshark -r captured_log.pcap -Y 'http.request.method==POST' -Tfields -e http.file_data | head -4 > parse4.txt""")
if not os.path.exists('parse5.txt'):
	os.popen("""tshark -r captured_log.pcap -Y 'frame.number==8' -Tfields -e data > parse5.txt""")
if not os.path.exists('file1'):
	os.popen("""tshark -r captured_log.pcap -Y 'http.request.method==POST and frame.time_delta > 1.5 and frame.number < 533' -Tfields -e data  > file1""")
if not os.path.exists('file2'):
	os.popen("""tshark -r captured_log.pcap -Y 'http.request.method==POST and frame.time_delta > 1.5 and frame.number > 533' -Tfields -e data  > file2""")

def decode(filename):
    f = open(filename).read().rstrip('\r').split('\n')[:-1]
    n = map(lambda x : x.rstrip('\r').decode('hex'), f)
    res = ''
    for i in n:
        match = re.findall(r'(.*?)\x00\x00\xff',i[120:])[0].decode('base64')
        res += re.findall(r"\/\*\*\/'(.*?)'\/\*\*\/", match)[0]
    return res
data  = open('parse3.txt').read().split('\n')[:-1]
data  = map(lambda x : x.split(),data)
data2 = open('parse4.txt').read().split('\n')[:-1]
data3 = open('parse5.txt').read().strip().decode('hex')

print ' [v] Protocol\t: {}, {}'.format(data[0][0], data[1][0])
print ' [v] Port\t\t: {}, {}'.format(data[1][3],data[2][3])
print ' [v] IPv4\t\t: {}, {}'.format(data[0][1],data[0][2])
print ' [V] Request\t: GET, {}'.format(data[0][3])
print
print '[+] Analyzing POST Request'
print ' [v] Body params'
print '  {}'.format('\n  '.join(data2))
print
print '[+] Analyzing uploaded file'
print data3[:100]
tmp = re.findall(r'(.*?)\x00\x00\xff',data3[120:])[0]
print tmp
print
print '[+] Decoding EXIF-data payload'
print tmp.decode('base64')
print
print '[+] Arranging char based on Time-based Blind SQL injection'
passwd = decode('file1'); print ' [v]', passwd
path   = decode('file2'); print ' [v]', path
print '[+] Getting flag'
os.popen('wget -Oflag.zip https://challs.phionify.web.id/{}'.format(path))
os.popen('7z x -p{} flag.zip'.format(passwd))
