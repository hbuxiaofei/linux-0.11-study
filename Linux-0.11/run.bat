@SET PATH=..\ming-w32\bin;..\..\ming-w32\bin;..\..\..\ming-w32\bin;%PATH%

make VERBOSE=1

..\bochs-2.6.10-win64\bochsdbg-win64.exe -f ..\bochs-2.6.10-win64\bochs.conf -q

