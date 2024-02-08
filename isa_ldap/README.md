# LDAP server do předmětu ISA FIT VUT
## Authors

- [xpejch08](https://git.fit.vutbr.cz/xpejch08)


## datum vytvoření
10.11.2023
## Popis
Program je implementace LDAP serveru využívaného například pro komunikaci pomocí nástroje ldapsearch. Spojení je nejprve navázáno pomocí zprávy bindRequest a ověřeno posláním zprávy bindResponse. Jeho úkolem je pomocí filtrů, které dekóduje z posloupnosti bytů zakódovaných v hexadecimální soustavě a poslaných pomocí TCP komunikace vyhledáavat v databázi usery. V databázi, která má formát csv souboru může vyhledáavat podle jednotlivých sloupců a to sice uid, cn, nebo mail. Výsledek následně posílá pomocí zprávy searchResEntry a searchResDone zpět klientovi.
## spuštění
Soubor je nejprve pootřeba přeložit pomocí nástroje make, výslednou binárku poté můžeme zapnout například takto:sudo ./isa-ldapserver -p 389 -f normal.csv .
Kde -p nám říká na jakém portu bude server spuštěn a -f nám uvádí cestu k souboru s databází. Server musí být spuštěn s root privileges. 
## seznam souborů
- ldap.cpp: implementace serveru
- ldap.h: hlavičkový soubor serveru
- ldapParser.cpp: logika ldap kódování, dekódování a filtrace
- decodeLdap.cpp: implementace pomocných funkcí pro kódování, dekódování a filtraci
- decodeLdap.h: definice všech tříd používaných v decodeLdap.cpp a ldapParser.cpp
- normal.csv: ukázková datbáze
- test.sh: implementované testy
- expectedOut: adresář s očekávanými výstupy pro testy
- makefile: soubor pro přeložení projektu pomocí make a odstranění výsledné binárky pomocí make clean.
- manual.pdf: soubor obsahující dokumentaci