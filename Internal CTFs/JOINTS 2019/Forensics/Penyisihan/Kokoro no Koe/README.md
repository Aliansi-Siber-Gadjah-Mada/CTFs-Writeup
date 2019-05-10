## Kokoro no Koe  (500 pts)

### Description

>  Suara... Dengarkanlah aku Apa kabarnya, pujaan hatiku Aku di sini menunggunya, masih berharap, di dalam hatinya, aa...

*Hint : The audio waveform were composed by either bi-pattern or oct-pattern*

Diberikan sebuah file attachment berupa `cast.pcapng`. Kemudian akan dilakukan network packet analysis menggunakan bantuan Wireshark & `tshark` CLI. Adapun tahapannya ialah sebagai berikut:

**Analyze UDP data**

Seperti biasanya, dilakukan enumerasi terkait statistik dari paket data. Hasilnya diperoleh:

![](imgs/file-0017.jpg)

Dari sini, dapat diketahui bahwa `31570 packet.frame` yang mayoritas nya memuat udp.data field. Kemudian, sebelum membuat deduksi lebih lanjut, dilakukan pengecekan terhadap `tcp.data` field

```bash
OPTIONS rtsp://192.168.8.100:5008/passwd.sdp RTSP/1.0
CSeq: 2
User-Agent: LibVLC/3.0.4 (LIVE555 Streaming Media v2016.11.28)

RTSP/1.0 200 OK
Server: VLC/3.0.4
Content-Length: 0
Cseq: 2
Public: DESCRIBE,SETUP,TEARDOWN,PLAY,PAUSE,GET_PARAMETER

DESCRIBE rtsp://192.168.8.100:5008/passwd.sdp RTSP/1.0
CSeq: 3
User-Agent: LibVLC/3.0.4 (LIVE555 Streaming Media v2016.11.28)
Accept: application/sdp

RTSP/1.0 200 OK
Server: VLC/3.0.4
Date: Mon, 28 Jan 2019 17:22:11 GMT
Content-Type: application/sdp
Content-Base: rtsp://192.168.8.100:5008/passwd.sdp
OPTIONS rtsp://192.168.8.100:5008/passwd.sdp RTSP/1.0
CSeq: 2
User-Agent: LibVLC/3.0.4 (LIVE555 Streaming Media v2016.11.28)

RTSP/1.0 200 OK
Server: VLC/3.0.4
Content-Length: 0
Cseq: 2
Public: DESCRIBE,SETUP,TEARDOWN,PLAY,PAUSE,GET_PARAMETER

DESCRIBE rtsp://192.168.8.100:5008/passwd.sdp RTSP/1.0
CSeq: 3
User-Agent: LibVLC/3.0.4 (LIVE555 Streaming Media v2016.11.28)
Accept: application/sdp

RTSP/1.0 200 OK
Server: VLC/3.0.4
Date: Mon, 28 Jan 2019 17:22:11 GMT
Content-Type: application/sdp
Content-Base: rtsp://192.168.8.100:5008/passwd.sdp
```

Hasilnya, diketahui bahwa terdapat aktivitas streaming dengan VLC server terhadap `rtsp://192.168.8.100:5008`. Dari sini, diduga bahwa terdapat audio streams yang disembunyikan pada `RTP.streams`.  Selanjutnya, dilakukan pengecekan kembali terhadap playlist apa saja yang dijalankan.

```bash
$ tshark -r cast.pcapng -Y tcp -Tfields -e data | tr -d '\n' | xxd -r -p | grep 'PLAY'
Public: DESCRIBE,SETUP,TEARDOWN,PLAY,PAUSE,GET_PARAMETER
PLAY rtsp://192.168.8.100:5008/passwd.sdp RTSP/1.0
Public: DESCRIBE,SETUP,TEARDOWN,PLAY,PAUSE,GET_PARAMETER
PLAY rtsp://192.168.8.100:5016/message.sdp RTSP/1.0
Public: DESCRIBE,SETUP,TEARDOWN,PLAY,PAUSE,GET_PARAMETER
PLAY rtsp://192.168.8.100:5012/private.sdp RTSP/1.0
```

Dari sini, didapat dugaan bahwa informasi flag disembunyikan dengan skema kriptografi asimetris yang melibatkan kunci privat. Kemudian, dilakukan proses ekstraksi audio streams untuk playlist passwd.sdp, message.sdp, dan private.sdp, dengan menggunakan RTP Streams Analysis pada Wireshark. 
Frequency Analysis with Audacity
Setelah sample audio telah terkumpul, dilakukan proses analisa sample audio dengan menggunakan Audacity.

**a.	Passwd.wav**

Sebelum melakukan analisis lebih lanjut, dilakukan pengecekan terhadap channel `spectrogram`. Hasilnya diperoleh representasi text berupa `'0boet3_1m4_s3nk4'`

 ![](imgs/spectogram.png)

**b.	Message.wav & privkey.wav**
 
![](imgs/waveform.png)

Berdasarkan representasi wave-form yang ada, tampak terlihat bahwa terdapat beberapa pola lembah-puncak yang berulang. Kemudian, mengacu pada hint yang diberikan, diketahui bahwa audio disusun dengan `bi-pattern` atau `oct-pattern`, yang bisa diasumsikan sebagai `pola binary` dan `pola octal`. Dari sini didapat dugaan bahwa terdapat sebuah `ASCII char` yang diencode sebagai `binary/octal` yang kemudian dikomposisikan sebagai sample-wave.

Akan tetapi, apabila diperhatikan lebih seksama, transition offset dari sample-wave tidak terlalu jelas, sehingga diperlukan estimasi panjang interval yang dibutuhkan setiap ASCII char pada sampe-wave. Dalam konteks ini, diambil estimasi pendekatan dengan mengambil pembulatan dari pembagian `(interval/(sampleRate/10))`. Adapun snippet-code yang digunakan ialah sebagai berikut:
 
````python
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

if __name__ == '__main__':
	main()

````


Hasilnya, didapatkan 2 buah PNG-file berupa QR-code, yang masing memuat informasi
 
![](imgs/qr1.png)

 ```bash
# private.png
$ python2 -c "import qrtools; qr=qrtools.QR(); qr.decode('private.png'); print qr.data"
https://pastebin.com/yfkkpqie


$ wget -Oprivkey 'https://pastebin.com/raw.php?i=yfkkpqie'
$ head privkey
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP v2.0.8
Comment: https://sela.io/pgp/

xcaGBFxJ7YkBEACi/kLog3pZGsVwgbvIlb35CjMDW49aEM0Z52gh8GfVY7j457au
wTvqmFMe3rnepSNy9/pSDORfXywBPgqr4GdBZXgYG5iB6ya9u4S2WOfBw/zcPBH6
qfXVkYDKUZ17/2O9xPp758dk81W+gAbQZ5IGhXdXie/kpb7Lc2AfWFigKRGB6HuP
hZJOwYXtufZHt8w+0qQKLL8gKh8YW72VvLN2JoRwZqPiyz7XoM4MBaSoGSd59/Bp
TVWBGh1pino97Kpa7p1nkYoX1SZ3q+JIoF8SJgZpi6L7FW51EdYweqtnOdzACMJp
uJD7lzbqk2Bkb58vPXcg2GYYuiEs7QbslXSJ6jx3Eh+7yfMQakNeWs6l6K819Szs
```

![](imgs/qr2.png)

 ```bash
#message.png
$ python2 -c "import qrtools; qr=qrtools.QR(); qr.decode('message.png'); print qr.data"
https://pastebin.com/EMLzXpYb 


$ wget -Omessage 'https://pastebin.com/raw.php?i=EMLzXpYb'
$ head message
-----BEGIN PGP MESSAGE-----

hQEMA2ieS2bi7e/OAQgAvn9Xef2fGrLrUOZ/DqY2UmQlYCRFnysiGtU1Td+E+fNd
mmmS/KOYSWtjDILjYaltlFzyA5SZv9mUILaXFE+jbTnHWKaj1ogW3UUFP3d5IqUs
CUmjs7kB9ji/W+kvs9Hper161EHhrR6ebYTkawkvJuQCpFC+JVW5NAicSnq6bzxq
6ASB4y4uyMYQx58opcKtcYIuaC91Qrab6SRz1pFseGNxyCzwiFLmfFlrwGMlFWSK
+VfyEGnBvesvLpDAjcngqjM2yB+ndePdoWhJFva/O/ZFJ9fYStXMVBy3/AHTb9GE
fbc7Uih24UmszcUEqbtel5ERHGXIL8aZBVofuwoAhtLBOQHKPr5U2U5FAQoFIAbG
nfKTfCRKMoo394fPbgid9+uiiD9knApu7ODWDqNscA0Fn8Hjk3AjpannekvYdmLs
qHf4Fhr+Ja5XY4m+d6ktiAjCNjaZAiqIOtGxFOtvkiOp1Gm6HsSe72Lsb4HIV9A+
```

Berdasarkan penemuan tersebut, ditemukan `PGP Private Key` beserta `PGP Message.` Kemudian, dengan mengelaborasikan password yang diperoleh dari proses sebelumnya, dilakukan proses dekripsi GPG sehingga diperoleh file `flag.zip` yang memuat flag.

```bash
$ gpg --allow-secret-key-import --import privkey
gpg: keyring `/home/shouko/.gnupg/secring.gpg' created
gpg: keyring `/home/shouko/.gnupg/pubring.gpg' created
gpg: key CD297ED5: secret key imported
gpg: /home/shouko/.gnupg/trustdb.gpg: trustdb created
gpg: key CD297ED5: public key "rinne.sonogami@dal.dal" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

$ gpg -d --passphrase 0boet3_1m4_s3nk4 message > flag.zip

You need a passphrase to unlock the secret key for
user: "rinne.sonogami@dal.dal"
2048-bit RSA key, ID E2EDEFCE, created 2019-01-24 (main key ID CD297ED5)

gpg: encrypted with 2048-bit RSA key, ID E2EDEFCE, created 2019-01-24
      "rinne.sonogami@dal.dal"
gpg: Signature made Fri Jan 25 16:01:29 2019 SEAST using RSA key ID E2EDEFCE
gpg: Good signature from "rinne.sonogami@dal.dal"
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: C026 C9A8 43BE A9E0 ADB2  9B36 7E88 0194 CD29 7ED5
     Subkey fingerprint: A720 5697 991E 960A BD88  9290 689E 4B66 E2ED EFCE

$ 7z x flag.zip && cat flag.txt
JOINTS19{h4ve_u_f0und_th3_m0st_pr3ci0us_th1ng_t0_y0u}
```


**FLAG : JOINTS19{h4ve_u_f0und_th3_m0st_pr3ci0us_th1ng_t0_y0u}**

#### Catatan penulis:

Sehubungan adanya miss-com dengan panitia, soal ini ternyata dirilis sebagai soal ke-4 untuk kategori forensik pada penyisihan. Oleh karenanya, mohon maaf apabila komposisi soal menjadi tidak seimbang dengan kategori soal lainnya .-.

[Octal-embedded Audio Referrence](https://www.aperikube.fr/docs/pragyan_2018/ears_to_the_rescue/)
