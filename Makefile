SOURCE := source/Hunt-Sleeping-Beacons.c
OUT := Hunt-Sleeping-Beacons.exe

CFLAGS := -lntdll -lpsapi -ldbghelp -s 

make:
	x86_64-w64-mingw32-gcc $(SOURCE) -o $(OUT) $(CFLAGS)

