Ýlk olarak kullanýcýdan plain text deðerini ve key deðerini aldýk.Ardýndan bunlarý
fonksiyonlara atamak için sakladýk.Ýki temel fonksiyon tanýmladýk Encrypt ve Decrypt
Plaintext deðerimizi inputwhitening iþlemine tabi tuttuktan sonra key ile birlikte 16 kez döndürecek bir iþlem gerçekleþtirdik.
plaintext ve keyi hex iþlemine tabi tutarak 128 bitlik bloklar haline getirdik.
ve key ile plaintextin hexli halini exor iþlemine tabi tuttuk.Sonrasýnda S-box
tanýmladýk.Bu çýktýyý f fonksiyonuna sokarak gelen çýktýyý ror ve rol iþlemine tabi
tutarak bitleri öteledik.Bu çýktýlar ile ötelenmiþ bitlerden gelen çýktýlarý deðiþtirerek
tekrar dörtlü bloklar haline getirdik.Gelen verileri 8 bit halinde MDS iþlemine tabi tuttuk
ve S-BOX da tanýmladýðýmýz deðerler ile denk gelen deðerlere exor iþlemi uyguladýk.
ardýndan permütasyon iþlemine tabi tutarak bir mds matrixi oluþturduk.Sonrasýnda 
subkey oluþturma iþlemini fonksiyon aracýlýðý ile baþlattýk.Decrypt fonksiyonunda ise
tüm bu iþlemleri ters bir þekilde kullanarak tekrar þifrelenmiþ veriyi kullanýcýnýn
girdiði veriye dönüþtürdük.Program phyton ile yazýldýðý için herhangi bir çalýþmama 
problemine karþýlýk kütüphaneleri ile birlikte bir klasörde toplandý.
