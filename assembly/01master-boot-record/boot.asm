mov ax, 3
int 0x10

mov ax, 0xb800
mov ds, ax

mov byte [0], 'H'
mov byte [2], 'e'
mov byte [4], 'l'
mov byte [6], 'l'
mov byte [8], 'o'

halt:
    jmp halt

times 510 - ($ - $$) db 0
db 0x55, 0xaa
