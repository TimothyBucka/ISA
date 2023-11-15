# ISA - Projekt: Monitorovani DHCP komunikace

**Autor**: Timotej Bucka (xbucka00)

**Datum**: 15.11.2023

**Popis**: Program monitoruje DHCP komunikaciu na rozhrani resp. cita komunikaciu zo suboru a vypisuje statistiky o zaplneni IP prefixov. Program je implementovany v jazyku `C++` a pri spusteni prikazu make prelozeny kompilatorom `g++`. Program rata s korektnym formatom DHCP paketov.

**Priklad spustenia**:

-   `./dhcp-stats -i eth0 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24` - monitorovanie rozhrania
-   `./dhcp-stats -r dhcp.pcap 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24` - monitorovanie komunikacie zo suboru

**Odovzdane subory**:

-   `dhcp-stats.cpp` - hlavne funkcie programu
-   `dhcp-stats.hpp` - hlavickovy subor
-   `IPPrefix.cpp` - trieda pre uchovanie IP prefixu
-   `Makefile`
-   `manual.pdf`
-   `dhcp-stats.1`
-   `README.md`
