#!/usr/bin/python3

import subprocess
import os

import pwn
from ptracer import Debugger, parse_mappings


def main():
    pwn.context.arch = 'amd64'

    binary_path = os.path.abspath('../webp_test/tests/fuzzer/simple_api_fuzzer')
    elf = pwn.ELF(binary_path)
    process = subprocess.Popen(
        ['./tracer', binary_path, 'fake-file'], env={'LD_BIND_NOW': '1'}
    )

    debugger = Debugger(process.pid)

    # Set a breakpoint on LLVMFuzzerTestOneInput.
    mappings = parse_mappings(process.pid)
    start = mappings.find_start_address(binary_path)
    assert start is not None

    elf.address = start
    print(f'Program loaded at 0x{start:x}')

    debugger.set_breakpoint(elf.functions['LLVMFuzzerTestOneInput'].address)
    debugger.cont()
    debugger.wait_for_breakpoint()

    plt_replacements = {
        'calloc': 'custom_calloc',
        'free': 'custom_free',
        'malloc': 'custom_malloc',
        'memset': 'custom_memset',
        'memcpy': 'custom_memcpy',
        'pthread_mutex_lock': 'custom_pthread_mutex_lock',
        'pthread_mutex_unlock': 'custom_pthread_mutex_unlock',
    }

    for func, new_func in plt_replacements.items():
        if func not in elf.plt:
            print(f'[!] {func} is missing!!')
            continue

        new_func_addr = elf.functions[new_func].address
        debugger.write_memory(elf.got[func], pwn.p64(new_func_addr))
        print(f'[#] Replaced {func}@GOT for {new_func}, addr: {new_func_addr:x}')

    excluded_mappings = set(
        [
            '[vvar]',
            '[vsyscall]',
            '[vdso]',
            '/usr/lib/x86_64-linux-gnu/libgcc_s.so.1',
            '/usr/lib/x86_64-linux-gnu/libc.so.6',
            '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
            '/usr/lib/x86_64-linux-gnu/libresolv.so.2',
            '/usr/lib/x86_64-linux-gnu/libm.so.6',
        ]
    )

    # Memory Mappings that we want to snapshot.
    mappings = parse_mappings(process.pid)
    mappings = [
        mapping
        for mapping in mappings.mappings
        if mapping.pathname not in excluded_mappings
    ]

    # Snapshot Format:
    # Registers in order: rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15, rbp, rsp, rip
    # Main binary start address
    # Number of Mappings
    # All the mappings in form start, size, [bytes]
    regs = debugger.registers()
    with open('snapshot', 'wb') as snapshot:
        snapshot.write(pwn.p64(regs.rax))
        snapshot.write(pwn.p64(regs.rbx))
        snapshot.write(pwn.p64(regs.rcx))
        snapshot.write(pwn.p64(regs.rdx))
        snapshot.write(pwn.p64(regs.rdi))
        snapshot.write(pwn.p64(regs.rsi))
        snapshot.write(pwn.p64(regs.r8))
        snapshot.write(pwn.p64(regs.r9))
        snapshot.write(pwn.p64(regs.r10))
        snapshot.write(pwn.p64(regs.r11))
        snapshot.write(pwn.p64(regs.r12))
        snapshot.write(pwn.p64(regs.r13))
        snapshot.write(pwn.p64(regs.r14))
        snapshot.write(pwn.p64(regs.r15))
        snapshot.write(pwn.p64(regs.rbp))
        snapshot.write(pwn.p64(regs.rsp))
        snapshot.write(pwn.p64(regs.rip))

        snapshot.write(pwn.p64(elf.address))

        snapshot.write(pwn.p64(len(mappings)))
        for mapping in mappings:
            print(
                f'[#] Storing mapping 0x{mapping.start:x} - 0x{mapping.end:x} (size {mapping.size})'
            )
            snapshot.write(pwn.p64(mapping.start))
            snapshot.write(pwn.p64(mapping.size))
            snapshot.write(debugger.read_memory(mapping.start, mapping.size))

    print('[#] snapshot taken')
    process.terminate()
    process.wait()


if __name__ == '__main__':
    main()
