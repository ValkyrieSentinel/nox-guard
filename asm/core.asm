global _start

section .data
    
    color_green     db 0x1b, "[32m", 0      ; DT_REG = 8
    color_yellow    db 0x1b, "[33m", 0      ; DT_DIR = 4
    color_cyan      db 0x1b, "[36m", 0      ; DT_LNK = 10
    color_reset     db 0x1b, "[0m", 0       

    msg_init        db 0x1b, "[36m[-] Nox-Guard DFIR ASM Core Initialized [Deep Forensic Mode][0m", 0xa
    msg_init_len    equ $ - msg_init
    
    msg_dir_header  db 0x1b, "[33m[+] Directory contents (parsed via direct sys_getdents64):[0m", 0xa
    msg_dir_len     equ $ - msg_dir_header

    msg_elf_ok      db 0x1b, "[32m[+] Target is a valid, uncompromised 64-bit x86_64 ELF binary![0m", 0xa
    msg_elf_ok_len  equ $ - msg_elf_ok

    msg_packed      db 0x1b, "[31m[!] WARNING: Packed/Obfuscated binary signature detected (UPX packer found)![0m", 0xa
    msg_packed_len  equ $ - msg_packed
    
    msg_error       db 0x1b, "[31m[!] Error: Path not found, permission denied, or invalid ELF structure.[0m", 0xa
    msg_error_len   equ $ - msg_error

    msg_usage       db "Usage: ./nox-core <path_to_file_or_directory>", 0xa
    msg_usage_len   equ $ - msg_usage

    newline         db 0xa          

section .bss
    buffer      resb 4096   

section .text
_start:
    
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, msg_init
    mov rdx, msg_init_len
    syscall

    
    mov rax, [rsp]          ; rax = argc 
    cmp rax, 2              
    jl .print_usage

    mov rsi, [rsp + 16]     ; rsi = argv[1]


    mov rax, 257            ; sys openat
    mov rdi, -100           ; AT FDCWD 
    mov rdx, 00000000h      ; O RDONLY 
    xor r10, r10            ; mode = 0
    syscall

    cmp rax, 0
    jl .exit_error
    mov rbx, rax            

    
    mov rax, 0              ; sys read
    mov rdi, rbx            ; fd
    mov rsi, buffer         
    mov rdx, 4096           
    syscall

    cmp rax, 4
    jl .try_directory       

    
    mov al, [buffer]
    cmp al, 0x7f
    jne .try_directory
    
    mov al, [buffer + 1]
    cmp al, 0x45            ; E
    jne .try_directory

    mov al, [buffer + 2]
    cmp al, 0x4c            ; L
    jne .try_directory

    mov al, [buffer + 3]
    cmp al, 0x46            ; F
    jne .try_directory

    
    mov al, [buffer + 4]
    cmp al, 2               ; ELFCLASS64
    jne .exit_error

    mov ax, [buffer + 18]
    cmp ax, 62              ; EM X86_64
    jne .exit_error

    
    xor rcx, rcx
.scan_upx_loop:
    cmp rcx, 4092           
    jge .elf_analysis_passed

    mov al, [buffer + rcx]
    cmp al, 'U'
    jne .next_scan
    mov al, [buffer + rcx + 1]
    cmp al, 'P'
    jne .next_scan
    mov al, [buffer + rcx + 2]
    cmp al, 'X'
    jne .next_scan
    mov al, [buffer + rcx + 3]
    cmp al, '0'
    je .found_packer        

.next_scan:
    inc rcx
    jmp .scan_upx_loop

.found_packer:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_packed
    mov rdx, msg_packed_len
    syscall
    jmp .close_and_exit     

.elf_analysis_passed:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_elf_ok
    mov rdx, msg_elf_ok_len
    syscall

    jmp .close_and_exit

.try_directory:
    
    mov rax, 8              ; sys lseek
    mov rdi, rbx            ; fd
    xor rsi, rsi            ; offset = 0
    xor rdx, rdx            ; SEEK SET = 0
    syscall

    
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_dir_header
    mov rdx, msg_dir_len
    syscall

.read_dir_loop:
    mov rax, 217            ; sys getdents64
    mov rdi, rbx            ; fd
    mov rsi, buffer         ; linux dirent64
    mov rdx, 4096           
    syscall

    cmp rax, 0
    jl .exit_error          
    je .close_and_exit      

    mov r8, rax             
    xor r9, r9              

.parse_dent:
    cmp r9, r8
    jge .read_dir_loop      

    lea r10, [buffer + r9]

    movzx r11, word [r10 + 16]  ; d reclen 
    test r11, r11
    jz .read_dir_loop       

    lea rsi, [r10 + 19]     ; d name 

    ; Фільтрація '.' та '..'
    cmp byte [rsi], '.'
    jne .print_filename
    cmp byte [rsi + 1], 0
    je .skip_entry          
    cmp byte [rsi + 1], '.'
    jne .print_filename
    cmp byte [rsi + 2], 0
    je .skip_entry          

.print_filename:
    push r8
    push r9
    push r10
    push r11                

    ;  d_type +18
    movzx rax, byte [r10 + 18]
    cmp rax, 4              ; DT DIR 
    je .color_dir
    cmp rax, 10             ; DT_LNK 
    je .color_lnk
    

    lea rsi, [color_green]
    jmp .do_color_write

.color_dir:
    lea rsi, [color_yellow]
    jmp .do_color_write

.color_lnk:
    lea rsi, [color_cyan]

.do_color_write:
    
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    
    mov rdx, 5              
    syscall


    lea rsi, [r10 + 19]    
    mov rdi, rsi            
    xor rcx, rcx            
.strlen_loop:
    cmp byte [rdi + rcx], 0
    je .strlen_done
    inc rcx
    jmp .strlen_loop
.strlen_done:


    mov rax, 1              
    mov rsi, rdi            
    mov rdi, 1              
    mov rdx, rcx            
    syscall

    
    mov rax, 1              
    mov rdi, 1             
    lea rsi, [color_reset]  ;  \x1b[0m
    mov rdx, 4              
    syscall

    
    mov rax, 1
    mov rdi, 1
    lea rsi, [newline]
    mov rdx, 1
    syscall

    pop r11                 
    pop r10
    pop r9
    pop r8

.skip_entry:
    add r9, r11             
    jmp .parse_dent

.close_and_exit:
    mov rax, 3
    mov rdi, rbx
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

.print_usage:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_usage
    mov rdx, msg_usage_len
    syscall
    jmp .exit_fail

.exit_error:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_error
    mov rdx, msg_error_len
    syscall

.exit_fail:
    mov rax, 60
    mov rdi, 1
    syscall