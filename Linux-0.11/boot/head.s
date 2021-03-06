/*
 *  linux/boot/head.s
 *
 *  (C) 1991  Linus Torvalds
 */

# head.s 含有 32 位启动代码。
# 注意!!! 32 位启动代码是从绝对地址 0x00000000 开始的
# 这里也同样是页目录将存在的地方，
# 因此这里的启动代码将被页目录覆盖掉

.text
.globl _idt,_gdt,_pg_dir,_tmp_floppy_area

# 页目录将会存放在这里
_pg_dir:

.globl startup_32
startup_32:
	# (mov)l用于32位, eax为32位寄存器, ax是eax的低16位
	# 0x10(0001,0000) 的含义是请求 特权级0(位0-1=0)、选择全局描述符表(位2=0)、选择表中第2项(位3-15=2)
	# gdt表的第2项即 数据段
	movl $0x10,%eax
	mov %ax,%ds
	mov %ax,%es
	mov %ax,%fs
	mov %ax,%gs
	# 表示 _stack_start -> ss:esp，设置系统堆栈, _stack_start 定义在 kernel/sched.c
	lss _stack_start,%esp

	call _setup_idt
	call _setup_gdt

	movl $0x10,%eax		   # reload all the segment registers
	mov %ax,%ds		       # after changing gdt. CS was already
	mov %ax,%es		       # reloaded in 'setup_gdt'
	mov %ax,%fs
	mov %ax,%gs
	lss _stack_start,%esp

	xorl %eax,%eax
1:	incl %eax		       # check that A20 really IS enabled
	movl %eax,0x000000	   # 向内存地址 0x000000 处写入任意数值
	cmpl %eax,0x100000     # 判断内存地址 0x100000(1M)处是否也是这个数值

	je 1b                  # 如果一直相同的话，就一直较下去，也即死循环、死机
	                       # 表示地址 A20 线没有选通，内核就不能使用 1M 以上内存

/*
 * NOTE! 486 should set bit 16, to check for write-protect in supervisor
 * mode. Then it would be unnecessary with the "verify_area()"-calls.
 * 486 users probably want to set the NE (#5) bit also, so as to use
 * int 16 for math errors.
 */
	movl %cr0,%eax		    # check math chip
	andl $0x80000011,%eax	# Save PG,PE,ET
/* "orl $0x10020,%eax" here for 486 might be good */
	orl $2,%eax		        # set MP
	movl %eax,%cr0
	call check_x87
	jmp after_page_tables

/*
 * We depend on ET to be correct. This checks for 287/387.
 */
check_x87:
	fninit
	fstsw %ax
	cmpb $0,%al
	je 1f			/* no coprocessor: have to set bits */
	movl %cr0,%eax
	xorl $6,%eax		/* reset MP, set EM */
	movl %eax,%cr0
	ret
.align 2
1:	.byte 0xDB,0xE4		/* fsetpm for 287, ignored by 387 */
	ret

/*
 *  setup_idt
 *
 *  sets up a idt with 256 entries pointing to
 *  ignore_int, interrupt gates. It then loads
 *  idt. Everything that wants to install itself
 *  in the idt-table may do so themselves. Interrupts
 *  are enabled elsewhere, when we can be relatively
 *  sure everything is ok. This routine will be over-
 *  written by the page tables.
 */
_setup_idt:
	# ignore_int 的有效地址写入 edx 寄存器, 指向一个只报错误的哑中断程序
	lea ignore_int, %edx

	# selector = 0x0008 = cs 段选择符为第8项 代码段
	movl $0x00080000, %eax
	movw %dx,%ax		/* selector = 0x0008 = cs */

	# 47位 段存在标志P, 用于标识此段是否存在于内存中, 为虚拟机存储提供支持 0x80
	# 40 ~ 43位 段描述符类型标志TYPE, 中断描述符对应的类型标志为0111(0x0E)
	movw $0x8E00,%dx	/* interrupt gate - dpl=0, present */

	lea _idt,%edi
	mov $256,%ecx
rp_sidt:
	movl %eax, (%edi)
	# 将 edx 寄存器中的值存放在 edi 寄存器指向的位置之后4个字节的位置中
	movl %edx, 4(%edi)
	addl $8,%edi
	dec %ecx
	jne rp_sidt
	lidt idt_descr
	ret

/*
 *  setup_gdt
 *
 *  This routines sets up a new gdt and loads it.
 *  Only two entries are currently built, the same
 *  ones that were built in init.s. The routine
 *  is VERY complicated at two whole lines, so this
 *  rather long comment is certainly needed :-).
 *  This routine will beoverwritten by the page tables.
 */
_setup_gdt:
	lgdt gdt_descr
	ret

/*
 * I put the kernel page tables right after the page directory,
 * using 4 of them to span 16 Mb of physical memory. People with
 * more than 16MB will have to expand this.
 */
.org 0x1000
pg0:

.org 0x2000
pg1:

.org 0x3000
pg2:

.org 0x4000
pg3:

.org 0x5000
/*
 * tmp_floppy_area is used by the floppy-driver when DMA cannot
 * reach to a buffer-block. It needs to be aligned, so that it isn't
 * on a 64kB border.
 */
_tmp_floppy_area:
	.fill 1024,1,0

after_page_tables:
	# 这些是调用 main 程序的参数
	pushl $0
	pushl $0
	pushl $0

	# main 函数的返回地址，如果真的会返回的话
	pushl $L6

	# 后面执行ret指令时就会将 main 程序的地址弹出堆栈，并去执行 main 程序去了
	pushl $_start
	jmp setup_paging
L6:
	jmp L6			# main should never return here, but
				# just in case, we know what happens.

/* This is the default interrupt "handler" :-) */
int_msg:
	.asciz "Unknown interrupt\n\r"
.align 2
ignore_int:
	pushl %eax
	pushl %ecx
	pushl %edx
	push %ds
	push %es
	push %fs

	movl $0x10,%eax
	mov %ax,%ds
	mov %ax,%es
	mov %ax,%fs

	pushl $int_msg
	call _printk
	popl %eax

	pop %fs
	pop %es
	pop %ds
	popl %edx
	popl %ecx
	popl %eax

	# 中断返回
	iret


/*
 * Setup_paging
 *
 * This routine sets up paging by setting the page bit
 * in cr0. The page tables are set up, identity-mapping
 * the first 16MB. The pager assumes that no illegal
 * addresses are produced (ie >4Mb on a 4Mb machine).
 *
 * NOTE! Although all physical memory should be identity
 * mapped by this routine, only the kernel page functions
 * use the >1Mb addresses directly. All "normal" functions
 * use just the lower 1Mb, or the local data space, which
 * will be mapped to some other place - mm keeps track of
 * that.
 *
 * For those with more memory than 16 Mb - tough luck. I've
 * not got it, why should you :-) The source is here. Change
 * it. (Seriously - it shouldn't be too difficult. Mostly
 * change some constants etc. I left it at 16Mb, as my machine
 * even cannot be extended past that (ok, but it was cheap :-)
 * I've tried to show which constants to change by having
 * some kind of marker at them (search for "16Mb"), but I
 * won't guarantee that's all :-( )
 */
.align 2
setup_paging:
	movl $1024*5,%ecx		/* 5 pages - pg_dir+4 page tables */
	xorl %eax,%eax
	xorl %edi,%edi			/* pg_dir is at 0x000 */

	# cld指令的解释：与cld相对应的指令是std，二者均是用来操作方向标志位DF（Direction Flag）
	# cld使DF复位，即是让DF=0，std使DF置位，即DF=1. 这两个指令用于串操作指令中
	# 通过执行cld或std指令可以控制方向标志DF，决定内存地址是增大（DF=0，向高地址增加）还是减小（DF=1，向地地址减小）
	# cld指令即告诉程序si di向内存地址增大的方向走
	# rep指令表示紧跟着下面的一条指令重复执行，直到ecx的值是零
	# stosl 将 eax 的值传送到 edi 所指向的内存
	cld;rep;stosl

	# 第1个页表所在的地址 = 0x00001007 & 0xfffff000 = 0x1000
	# 第1个页表的属性标志 = 0x00001007 & 0x00000fff = 0x07，表示该页存在、用户可读写
	movl $pg0+7,_pg_dir         /* set present bit/user r/w */
	movl $pg1+7,_pg_dir+4       /*  --------- " " --------- */
	movl $pg2+7,_pg_dir+8       /*  --------- " " --------- */
	movl $pg3+7,_pg_dir+12      /*  --------- " " --------- */
	movl $pg3+4092,%edi
	movl $0xfff007,%eax         /*  16Mb - 4096 + 7 (r/w user,p) */
	std                    /* 置方向标志1，DF=1，地址从高到低 */
1:	stosl                  /* eax -> es:edi, fill pages backwards - more efficient :-) */
	subl $0x1000,%eax
	jge 1b
	xorl %eax,%eax         /* pg_dir is at 0x0000 */
	movl %eax,%cr3         /* cr3 - page directory start */
	movl %cr0,%eax
	orl $0x80000000,%eax   /* cr0的位31是分页标志 */
	movl %eax,%cr0         /* set paging (PG) bit */

	# 在改变分页处理标志后要求使用转移指令刷新预取指令队列，这里用的是返回指令 ret
	# 该返回指令的另一个作用是将堆栈中的 main 程序的地址弹出，并开始运行 /init/main.c 程序
	# 本程序到此真正结束了
	ret			/* this also flushes prefetch-queue */

.align 2
.word 0
idt_descr:
	.word 256*8-1		# idt contains 256 entries
	.long _idt

.align 2
.word 0
gdt_descr:
	.word 256*8-1		# so does gdt (not that that's any
	.long _gdt		# magic number, but it works for me :^)

.align 8
_idt:
	# 默认中断描述符表未初始化
	# 256 * 8 个字节共64bit，全部都是 0
	.fill 256,8,0		# idt is uninitialized

_gdt:
	# (0-nul, 1-cs, 2-ds, 3-sys, 4-TSS0, 5-LDT0, 6-TSS1, 7-LDT1, 8-TSS2 etc...)
	.quad 0x0000000000000000	/* NULL descriptor */

	# G=1,D/B=1
	# P=1,S=1,TYPE=1010
	# 基地址为0
	.quad 0x00c09a0000000fff	/* 16Mb  代码段最大长度 16M */

	# G=1,D/B=1
	# P=1,S=1,TYPE=0010
	# 基地址为0
	.quad 0x00c0920000000fff	/* 16Mb  数据段最大长度 16M */

	.quad 0x0000000000000000	/* TEMPORARY - don't use */
	.fill 252,8,0			/* space for LDT's and TSS's etc */
