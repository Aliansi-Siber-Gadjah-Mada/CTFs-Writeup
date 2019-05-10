from pydub import AudioSegment
from scipy.io import wavfile
import qrtools, os

def decode_rand(freq,rate,mode=0):
	uniq = sorted(set(freq))
	init = min(uniq, key=abs)
	uniq.remove(init); uniq.remove(init*-1);

	norm = 500 if not mode else 500*10
	offx = 8 if mode else 2
	offy = 3 if mode else 8
	dic  = {}; count = 0; d=0
	key  = {}; uniq += [uniq[0]]
	keys = []; keys.append(uniq[0])

	for i in range(len(uniq)-1):
		if abs(uniq[i] - uniq[i+1]) > norm:
			tmp            = key.get(count,list())
			dic[uniq[i]]   = str(count)
			if not tmp:
				key[count] = tmp
				tmp       += keys
				freq       = [uniq[i] if j in tmp else j for j in freq]
			count 	 += 1
			keys 	  = []
		keys.append(uniq[i+1])

	pos  = {freq.index(i) : i for i in dic}
	freq = freq[min(pos):]
	data = '';

	print dic
	for i in range(len(freq)-1):
		if freq[i] != freq[i+1] and freq[i] != 8 and freq[i] != -8:
			sign    = dic.get(freq[i])
			# print freq[i]
			count   = round(d/((rate/10)*1.0))
			data   += sign * int(count) 
			d 		= 0
		d += 1

	return ''.join(chr(int(data[i:i+offy],offx)%256) for i in range(0,len(data),offy))

def main():
	passwd = '0boet3_1m4_s3nk4'
	s,msg_dat = wavfile.read('message.wav')
	x = decode_rand(msg_dat.tolist(),s,0)
	f = open('message.png','wb').write(x)
	
	s,priv_dat = wavfile.read('private.wav')
	y = decode_rand(priv_dat.tolist(),s,1)
	g = open('private.png','wb').write(y)

	qr = qrtools.QR()
	qr.decode('message.png')
	print qr.data
	os.popen('wget -O msg.gpg https://pastebin.com/raw/{}'.format(qr.data.split('/')[3]))

	qr.decode('private.png')
	print qr.data

	os.popen('wget -O private.key https://pastebin.com/raw/{}'.format(qr.data.split('/')[3]))
	os.popen('gpg --allow-secret-key-import --import private.key')
	os.popen('gpg -d --batch --passphrase {} msg.gpg > flag.zip'.format(passwd))

if __name__ == '__main__':
	main()
