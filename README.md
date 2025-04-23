# pwn

Task types listed roughly from easier => harder.

## rand

1) rand_srand_0
2) rand_srand_time_0

## shellcode

1) shellcode_mmap
2) shellcode_execstack
3) shellcode_execstack_gets_leak
4) shellcode_execstack_jmp_rsp
5) shellcode_execstack_gets_no_leak
6) shellcode_execstack_gets_no_leak_pie
7) shellcode_execstack_jmp_rsp_pie
8) shellcode_mmap_bad_bytes

## ret2win

1) ret2win_gets
2) ret2win_gets_canary
3) ret2win_gets_pie
4) ret2win_gets_canary_pie
5) ret2win_read_1_byte
6) ret2win_read_1_byte_canary
7) ret2win_read_1_byte_pie
8) ret2win_read_1_byte_canary_pie

## ret2libc

1) ret2libc_gets
2) ret2libc_fgets
3) ret2libc_gets_canary
4) ret2libc_fgets_canary

## seccomp

1) seccomp_shellcode_execstack
2) seccomp_shellcode_execstack_no_open
3) seccomp_shellcode_execstack_no_read_no_write
4) seccomp_shellcode_execstack_gets_pie
5) seccomp_rop_gets_pie
6) seccomp_rop_gets_pie_only_read_write
7) seccomp_rop_gets_no_read_no_write

## rop

1) rop_stack_pivot

## srop

1) srop

## ret2csu

1) ret2csu

## fmt_str

1) fmt_str_read_flag_from_stack
2) fmt_str_got_overwrite_read
3) fmt_str_got_overwrite_read_pie
4) fmt_str_got_overwrite_read_no_leak
5) fmt_str_got_overwrite_read_no_leak_pie
6) fmt_str_got_overwrite_fgets
7) fmt_str_got_overwrite_fgets_pie
8) fmt_str_got_overwrite_fgets_no_leak
9) fmt_str_got_overwrite_fgets_no_leak_pie
10) fmt_str_rop

## ret2plt

1) ret2plt_gets
2) ret2plt_gets_pie

## ret2dlresolve

1) ret2dlresolve
2) ret2dlresolve_canary
3) ret2dlresolve_pie
4) ret2dlresolve_canary_pie

## ret2gets

1) ret2gets_system
2) ret2gets_puts
3) ret2gets_printf

## ret2rand

1) ret2rand

## shstk

1) shstk_execve
2) shstk_cop
