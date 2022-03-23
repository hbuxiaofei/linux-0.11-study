BOCHSDIR ?= ..\..\bochs-2.6.10-win64

all: build run


build:
	@del /S /Q root.img
	$(BOCHSDIR)\bximage.exe -mode=create -hd=16M -imgmode=flat -sectsize=512 -q root.img
	nasm.exe boot.asm -o boot.bin
	dd.exe if=boot.bin of=root.img bs=512 count=1

run:
	$(BOCHSDIR)\bochsdbg-win64.exe -f bochsrc.conf -q


clean:
	@del /S /Q *.img *.bin bx_enh_dbg.ini
