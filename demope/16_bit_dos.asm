ORG 100h

        lea dx, [msg]
        mov ah,9
        int 21h
        mov ax, 4c00h
        int 21h

msg: DB 'CausticKirbyZ','$' 
; msg: DB 'CausticKirbyZ !!! cannot be run in DOS mode.',0x0D,0x0D,0x0A,'$',0,0,0,0,0,0,0