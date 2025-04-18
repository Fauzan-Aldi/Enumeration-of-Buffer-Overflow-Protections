# Enumeration-of-Buffer-Overflow-Protections BOF

BOF ini dapat digunakan untuk menghitung proses sistem dan mengidentifikasi tingkat proteksi masing-masing. Informasi tambahan, seperti relasi layanan, pengguna, sesi, dan jalur, juga dikembalikan. Informasi ini jika digabungkan dapat digunakan untuk mengidentifikasi kandidat yang baik untuk ditelusuri untuk pembajakan DLL tingkat SISTEM. Proses yang ideal adalah:

1. Tidak terlindungi
2. Berhubungan dengan layanan, sehingga dapat dijalankan/dihentikan
3. Tidak menggunakan Perangkat lunak pihak ketiga. Microsoft sangat ahli dalam mengidentifikasi pembajakan komponen Microsoft. 

# Penggunaan
![alt text](img/enumprotections.PNG)

# Kompilasi
Alat ini ditulis tanpa menggunakan deklarasi BOF API normal (misalnya file bofdefs.h).Makefile untuk alat ini memanggil objcopy, mengoper file imports_enumprotectionsXX.txt yang berisi penggantian simbol yang tepat ke alat tersebut yang kemudian membuat BOF dapat digunakan. 

Saya telah menulis sebuah alat bernama BOFPatcher yang mengotomatiskan proses ini. Hal ini memungkinkan pengguna untuk menulis BOF sebagai bahasa C biasa tanpa perlu khawatir dengan deklarasi API yang tidak praktis:

![alt text](img/bofpatcher.PNG)

Alat ini tersedia bagi mereka yang membeli kursus [BOF Development and Tradecraft] (https://training.zeropointsecurity.co.uk/courses/bof-dev-and-tradecraft). 

Terima kasih juga kepada banyak orang berbakat yang karyanya telah dikorek oleh ChatGPT dan saya gunakan.

# Pesan
 Tahap ini Masi dalam Pengembangan dan masi memiliki Kekurangan
