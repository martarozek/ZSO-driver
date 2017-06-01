Marta Rożek
360953

Opis rozwiązania:
Wykorzystuję blok DMA. Jedno urządzenie ma jeden blok poleceń (a nie każdy
kontekst). Napisałam pomocnicze funkcje do obsługi bufora cyklicznego. Trzymam
indeks miejsca do czytania i pisania w buforze. Po każdym wpisaniu komend
użytkownika indeks pisania jest przesuwany. Indeks czytania jest przesuwany po
odebraniu przerwania NOTIFY od countera.

Polecenia od użytkownika wczytuję partiami. Na początku każdego write'a
waliduję wszystkie komendy i jeśli któraś jest niepoprawna, to od razu zwracam
EINVAL. Jeśli nie ma miejsca w buforze poleceń, to wieszam kontekst na kolejce.
Procesy z tej kolejki są budzone w obsłudze przerwania.

Jeśli jest miejsce w buforze poleceń, to wpisuję tyle komend użytkownika, na
ile starczy miejsca. Po takim bloku wpisuję counter z value równym indeksowi
w buforze poleceń, pod którym ten counter został wpisany.
W write staram się nie trzymać za długo spinlocka, biorę go tylko wtedy, kiedy
korzystam ze zmiennych używanych też w funkcji obsługi przerwań.

Żeby wiedzieć któremu procesowi skończyły się obliczenia kiedy przychodzi
przerwanie od countera, trzymam listę kontekstów wraz z numerami countera,
które zostały wpisane po ich obliczeniach. W obsłudze przerwania zmniejszam
licznik nieobliczonych komend wszystkim procesom na liście, tak długo aż nie
trafię na kontekst z counterem, który przyszedł w tym przerwaniu.

Zaimplementowałam też proste funkcje do obsługi vm_area_struct, żeby nie usunąć
pamięci procesowi, który zrobił mmap, zamknął urządzenie, a korzysta jeszcze ze
zmapowanej pamięci.
