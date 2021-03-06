;
; SYS_SIZE is the number of clicks (16 bytes) to be loaded.
; 0x3000 is 0x30000 bytes = 196kB, more than enough for current
; versions of linux
;
SYSSIZE equ 0x3000
;
;	bootsect.s		(C) 1991 Linus Torvalds
;
; bootsect.s is loaded at 0x7c00 by the bios-startup routines, and moves
; iself out of the way to address 0x90000, and jumps there.
;
; It then loads 'setup' directly after itself (0x90200), and the system
; at 0x10000, using BIOS interrupts. 
;
; NOTE! currently system is at most 8*65536 bytes long. This should be no
; problem, even in the future. I want to keep it simple. This 512 kB
; kernel size should be enough, especially as this doesn't contain the
; buffer cache as in minix
;
; The loader has been made as simple as possible, and continuos
; read errors will result in a unbreakable loop. Reboot by hand. It
; loads pretty fast by getting whole sectors at a time whenever possible.


SETUPLEN equ 4				; nr of setup-sectors
BOOTSEG  equ 0x07c0			; original address of boot-sector
INITSEG  equ 0x9000			; we move boot here - out of the way
SETUPSEG equ 0x9020			; setup starts here
SYSSEG   equ 0x1000			; system loaded at 0x10000 (65536).
ENDSEG   equ SYSSEG + SYSSIZE		; where to stop loading

; ROOT_DEV:	0x000 - same type of floppy as boot.
;           0x301 - first partition on first drive etc
ROOT_DEV equ 0x306          ; 第2个盘的第1个分区
[SECTION .s16code]          ; 16位代码段
[BITS 16]                   ; 处理器模式16位, 默认的操作数是16位
_start:
	mov	ax,BOOTSEG          ; 将 ds 段寄存器置为 0x07c0
	mov	ds,ax
	mov	ax,INITSEG          ; 将 es 段寄存器置为 0x9000
	mov	es,ax
	mov	cx,256              ; 移动计数值=256 字(word)
	sub	si,si               ; 源地地址 ds:si = 0x07C0:0x0000
	sub	di,di               ; 目的地址 es:di = 0x9000:0x0000
	rep movsw               ; 重复执行 movsw, 直到 cx = 0 
                            ; movsw: 移动 1 个字(word), 1 word = 2 byte  
	jmp	INITSEG:go          ; 长跳转, cs 将变为 0x90000
go:	mov	ax,cs               ; 将 cs、ds、es 和 ss 都置成移动后代码所在的段处(0x9000)
	mov	ds,ax
	mov	es,ax
; put stack at 0x9ff00.     ; 将堆栈指针 sp 指向 0x9ff00(即 0x9000:0xff00)处
	mov	ss,ax
	mov	sp,0xFF00		    ; 从 0x90200 地址开始处还要放置 setup 程序
                            ; 而 setup 程序大约为 4 个扇区，因此 sp 要指向大
                            ; 于（0x200 + 0x200 * 4 + 堆栈大小）处。

; load the setup-sectors directly after the bootblock.
; Note that 'es' is already set up.

load_setup:
	mov	dx,0x0000		    ; drive 0, head 0
	mov	cx,0x0002		    ; sector 2, track 0
	mov	bx,0x0200		    ; es:bx 指向数据缓冲区； 
                            ; es 已经设置好了 (在移动代码时 es 已经指向目的段地址处 0x9000)
	mov	ax,0x0200+SETUPLEN	; ah=0x02 - 读磁盘扇区指令；al=SETUPLEN - 需要读出的扇区数量
	int	0x13	   		    ; BIOS 中断 0x13 进行数据读取, 如果出错则 CF 标志置位
	jnc	ok_load_setup		; CF 未置位则读取成功, 跳转到 ok_load_setup
	mov	dx,0x0000
	mov	ax,0x0000		    ; reset the diskette
	int	0x13
	jmp	load_setup

ok_load_setup:

; Get disk drive parameters, specifically nr of sectors/track

	mov	dl,0x00         ; 驱动器号（如果是硬盘则要置位7 为 1）
	mov	ax,0x0800		; AH=8 is get drive parameters
	int	0x13
	mov	ch,0x00
;	seg cs
	mov	[sectors],cx    ; 保存每磁道扇区数
	mov	ax,INITSEG
	mov	es,ax

; Print some inane message, 显示一些信息('Loading system ...'回车换行，共 24 个字符)。

	mov	ah,0x03         ; read cursor pos
	xor	bh,bh           ; bh清零
	int	0x10
	
	mov	ax,0x1301		; write string, move cursor
	mov	bx,0x0007		; page 0, attribute 7 (normal)
	mov	cx,24           ; 共 24 个字符
	mov	bp,msg1         ; 指向要显示的字符串
	int	0x10

; ok, we've written the message, now
; we want to load the system (at 0x10000)

	mov	ax,SYSSEG   ; SYSSEG = 0x1000
	mov	es,ax		; segment of 0x010000
	call	read_it
	call	kill_motor

; After that we check which root-device to use. If the device is
; defined (;= 0), nothing is done and the given device is used.
; Otherwise, either /dev/PS0 (2,28) or /dev/at0 (2,8), depending
; on the number of sectors that the BIOS reports currently.

;	seg cs
	mov	ax,[root_dev]
	cmp	ax,0
	jne	root_defined
;	seg cs
	mov	bx,[sectors]
	mov	ax,0x0208		; /dev/ps0 - 1.2Mb
	cmp	bx,15
	je	root_defined
	mov	ax,0x021c		; /dev/PS0 - 1.44Mb
	cmp	bx,18
	je	root_defined
undef_root:
	jmp undef_root
root_defined:
;	seg cs
	mov	[root_dev],ax

; after that (everyting loaded), we jump to
; the setup-routine loaded directly after
; the bootblock:

	jmp	SETUPSEG:0

; This routine loads the system at address 0x10000, making sure
; no 64kB boundaries are crossed. We try to load it as fast as
; possible, loading whole tracks whenever we can.
;
; in:	es - starting address segment (normally 0x1000)
;
sread:	dw 1+SETUPLEN	; sectors read of current track
head:	dw 0			; current head
track:	dw 0			; current track

read_it:
	mov ax,es
	test ax,0x0fff      ; 进行与操作, 测试 es<<4 为 64KB 的整数倍
die:
	jne die		  	    ; 上一步不等于0，则ZF=0，则进行跳转
	xor bx,bx		    ; 异或, 清除bx寄存器
rp_read:
	mov ax,es
	cmp ax,ENDSEG		; have we loaded all yet?
	jb ok1_read
	ret
ok1_read:
;	seg cs
	mov ax,[sectors]    ; 取每磁道扇区数
	sub ax,[sread]      ; 减去当前磁道已读扇区数
	mov cx,ax
	shl cx,9
	add cx,bx
	jnc ok2_read
	je ok2_read
	xor ax,ax
	sub ax,bx
	shr ax,9
ok2_read:
	call read_track
	mov cx,ax
	add ax,[sread]
;	seg cs
	cmp ax,[sectors]
	jne ok3_read
	mov ax,1
	sub ax,[head]
	jne ok4_read
	inc word [track]
ok4_read:
	mov [head],ax
	xor ax,ax
ok3_read:
	mov [sread],ax
	shl cx,9
	add bx,cx
	jnc rp_read
	mov ax,es
	add ax,0x1000
	mov es,ax
	xor bx,bx
	jmp rp_read

read_track:
	push ax
	push bx
	push cx
	push dx
	mov dx,[track]
	mov cx,[sread]
	inc cx
	mov ch,dl
	mov dx,[head]
	mov dh,dl
	mov dl,0
	and dx,0x0100
	mov ah,2
	int 0x13
	jc bad_rt
	pop dx
	pop cx
	pop bx
	pop ax
	ret
bad_rt:	mov ax,0
	mov dx,0
	int 0x13
	pop dx
	pop cx
	pop bx
	pop ax
	jmp read_track

;/*
; * This procedure turns off the floppy drive motor, so
; * that we enter the kernel in a known state, and
; * don't have to worry about it later.
; */
kill_motor:
	push dx
	mov dx,0x3f2
	mov al,0
	out dx,ax
	pop dx
	ret

sectors:
	dw 0

msg1:
	db 13,10
	db "dibingfa quick run"
	db 13,10,13,10

times 	508-($-$$)	db	0	
root_dev:
	dw ROOT_DEV
boot_flag:
	dw 0xAA55

