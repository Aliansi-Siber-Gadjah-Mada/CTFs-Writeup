# CryptoLab

## Stage 1
Deskripsi : 
  - Enkripsi menggunakan AES mode CFB (Cipher FeedBack)
  - Secret message merupakan 64 byte random data yang sebelumnya akan di-padding menjadi 80 byte untuk masuk ke proses enkripsi
  - Diberikan hasil enkripsi secret message dengan susunan (IV + Cipher)
  - Terdapat 2 opsi, yaitu enkripsi dan menebak plain text secret message untuk melanjutkan ke stage 2

Solve :
  1. Karena enkripsi CFB awalnya menggunakan IV untuk digunakan enkripsi block cipher lalu hasilnya di-xor dengan plaintext untuk mendapatkan ciphertext, maka dengan mengirimkan IV yang sama lalu diikuti dengan plaintext berupa ```'\x00' * 16``` , akan didapatkan hasil enkripsi yang merupakan nilai intermediate dari proses enkripsi IV pada block cipher
  2. Plaintext dari secret message pada block pertama pun dapat diketahui dengan cara ```intermediate[i] xor ciphertext[i]``` (dimana indeks menunjukan block ke-berapa)
  3. Untuk mendapatkan nilai intermediate pada block selanjutnya, akan dikirimkan pesan dengan komposisi ```(IV + plaintext_secret_message[i] + '\x00'*16)```
  4. Dilakukan lagi proses pada step 2 untuk mendapatkan plaintext secret message pada block-block selanjutnya
  5. Proses ini dilakukan sebanyak jumlah block pada secret_msg

## Stage 2
Deskripsi :
  - Enkripsi pada stage ini menggunakan sebuah fungsi yang beranama ```something_block_cipher``` , dimana pada fungsi ini nantinya akan memanggil fungsi enkripsi AES CBC
  - Dapat dilihat dari potongan kodenya, bahwa enkripsi ini merupakan jenis AES PCBC (Propagating Cipher Block Chaining)
  - Jenis AES ini mirip dengan CBC, hanya saja untuk proses enkripsi pada block kedua dan selanjutnya, nilai yang digunakan untuk di-xor dengan plaintext adalah ```plaintext_sebelumnya xor ciphertext_sebelumnya```
  - Diberikan string Test Message dan Signaturenya. Signature sendiri dalam stage ini hanyalah merupakan hasil enkripsi dari Test Message.
  - Untuk menyelesaikan stage 2 dan mendapatkan flag, user diminta untuk menginput payload dengan komposisi ```(IV + modified_test_message)``` 
  - Modified Test Message yang dikirimkan harus kelipatan 16 dan setidaknya berisi 32 byte (karena 16 byte pertamanya IV)
  - ```modified_test_message``` sendiri harus berbeda dengan nilai Test Message yang sebelumnya telah diberikan

Solve :
  1. Proses enkripsi AES pada stage 2 ini tidak ada padding sehingga memudahkan untuk melakukan modifikasi plaintext
  2. Untuk mendapatkan hasil signature (enkripsi) yang sama dengan plain text yang berbeda, disina akan dilakukan swap antara ```IV``` dan ```plaintext``` pada block pertama
  3. Pada tahap ini, block pertama plaintext bernilai ```IV``` dan ```IV``` akan bernilai plaintext block pertama
  4. Selanjutnya, dilakukan modifikasi untuk plaintext pada block[i] selanjutnya dengan payload : ```test_message[i-1] xor modified_test_message[i-1] xor test_message[i]```
  5. Proses pada step 3 lalu diulangi sebanyak jumlah block enkripsi - 1
  6. Jika sudah didapatkan modified dari test message, maka kirim payload dengan susunan ```hex(IV + modified_test_message)``` dan flag akan didapatkan