BOCHSDIR ?= ..\..\bochs-2.6.10-win64

all:
	$(BOCHSDIR)\bximage.exe -mode=create -hd=16M -imgmode=flat -sectsize=512 -q root.img
	nasm.exe hello.asm -o hello.bin
	dd.exe if=hello.bin of=root.img bs=512 count=1
	$(BOCHSDIR)\bochs-win64.exe -f bochsrc.conf -q

clean:
	@del /S /Q *.img *.bin
