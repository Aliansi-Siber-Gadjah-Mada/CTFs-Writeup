# Blind_Fast_Random

Deskripsi :
  - Diberikan sebuah service nc berupa challenge
  - Jika dilakukan analisis dan jika dicoba beberapa kali, maka user akan diminta untuk menyelesaikan challenge berupa dekripsi ciphertext RSA sebanyak 35 kali dengan waktu tiap stage nya adalah 7 detik
  - Jika diamati dengan melakukan beberapa kali testing, dapat ditemukan bahwa terdapat beberapa metode untuk menyelesaikan dekripsi RSA yang diberikan
  - (Beberapa jam setelah lomba berlangsung, Source Code diberikan dengan sedikit me-```redacted``` tipe serangan yang akan digunakan)

Solve :
  1. Identifikasi bahwa terdapat 5 jenis serangan yang mungkin, yaitu : ```Factor Fermat, Phollard Rho, Mersenne Prime, SinglePrime Modulus dan Wiener Attack```
  2. Karena setiap stage akan mengeluarkan enkripsi RSA dengan vektor attack yang berbeda-beda, maka dapat dibuat script untuk testing setiap jenis serangan pada tiap stage
  3. Karena waktu setiap stage dibatasi hanya 7 detik, maka fungsi pencarian untuk ```Factor Fermat``` dan ```Phollard Rho``` dibatasi waktu eksekusinya sehingga jika sudah melebihi batas ```treshold``` waktu yang diinginkan, maka dapat diasumsikan bahwa vektor serangan yang tepat bukan merupakan kedua jenis serangan tersebut
  4. Pada solver ini, pembatasan pencarian pada kedua vektor serangan diatas hanya dilakukan dengan cara membatasi jumlah ```loop``` untuk pencarian sebanyak 3000