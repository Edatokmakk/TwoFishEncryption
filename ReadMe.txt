�lk olarak kullan�c�dan plain text de�erini ve key de�erini ald�k.Ard�ndan bunlar�
fonksiyonlara atamak i�in saklad�k.�ki temel fonksiyon tan�mlad�k Encrypt ve Decrypt
Plaintext de�erimizi inputwhitening i�lemine tabi tuttuktan sonra key ile birlikte 16 kez d�nd�recek bir i�lem ger�ekle�tirdik.
plaintext ve keyi hex i�lemine tabi tutarak 128 bitlik bloklar haline getirdik.
ve key ile plaintextin hexli halini exor i�lemine tabi tuttuk.Sonras�nda S-box
tan�mlad�k.Bu ��kt�y� f fonksiyonuna sokarak gelen ��kt�y� ror ve rol i�lemine tabi
tutarak bitleri �teledik.Bu ��kt�lar ile �telenmi� bitlerden gelen ��kt�lar� de�i�tirerek
tekrar d�rtl� bloklar haline getirdik.Gelen verileri 8 bit halinde MDS i�lemine tabi tuttuk
ve S-BOX da tan�mlad���m�z de�erler ile denk gelen de�erlere exor i�lemi uygulad�k.
ard�ndan perm�tasyon i�lemine tabi tutarak bir mds matrixi olu�turduk.Sonras�nda 
subkey olu�turma i�lemini fonksiyon arac�l��� ile ba�latt�k.Decrypt fonksiyonunda ise
t�m bu i�lemleri ters bir �ekilde kullanarak tekrar �ifrelenmi� veriyi kullan�c�n�n
girdi�i veriye d�n��t�rd�k.Program phyton ile yaz�ld��� i�in herhangi bir �al��mama 
problemine kar��l�k k�t�phaneleri ile birlikte bir klas�rde topland�.
