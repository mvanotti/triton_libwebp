#!/usr/bin/python3

from dataclasses import dataclass
from typing import List, Optional
import os
import pwn

from triton import (
    TritonContext,
    ARCH,
    Instruction,
    MemoryAccess,
    MODE,
    EXCEPTION,
    AST_REPRESENTATION,
    OPCODE,
    SOLVER_STATE,
)

Triton = TritonContext()

def main():
    Triton.setArchitecture(ARCH.X86_64)
    Triton.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    Triton.setMode(MODE.ALIGNED_MEMORY, True)
    Triton.setMode(MODE.CONSTANT_FOLDING, True)
    Triton.setMode(MODE.AST_OPTIMIZATIONS, True)

    pwn.context.arch = 'amd64'

    binary_path = os.path.abspath('../webp_test/tests/fuzzer/simple_api_fuzzer')
    elf = pwn.ELF(binary_path)

    with open('./bad.webp', 'rb') as f:
        fuzzer_input = bytearray(f.read())

    branches = run_from_snapshot('./snapshot', elf, fuzzer_input, None)

    with open('./result', 'rb') as f:
        fuzzer_input = bytearray(f.read())

    run_from_snapshot('./snapshot', elf, fuzzer_input, branches)

def reset_run():
    Triton.clearPathConstraints()
    Triton.concretizeAllMemory()
    Triton.concretizeAllRegister()

def run_from_snapshot(snapshot_path, elf, fuzzer_input, expected_branches):
    reset_run()

    print('[#] Loading from snapshot...', end='')
    with open(snapshot_path, 'rb') as snapshot:
        rax = pwn.u64(snapshot.read(8))
        rbx = pwn.u64(snapshot.read(8))
        rcx = pwn.u64(snapshot.read(8))
        rdx = pwn.u64(snapshot.read(8))
        rdi = pwn.u64(snapshot.read(8))
        rsi = pwn.u64(snapshot.read(8))
        r8 = pwn.u64(snapshot.read(8))
        r9 = pwn.u64(snapshot.read(8))
        r10 = pwn.u64(snapshot.read(8))
        r11 = pwn.u64(snapshot.read(8))
        r12 = pwn.u64(snapshot.read(8))
        r13 = pwn.u64(snapshot.read(8))
        r14 = pwn.u64(snapshot.read(8))
        r15 = pwn.u64(snapshot.read(8))
        rbp = pwn.u64(snapshot.read(8))
        rsp = pwn.u64(snapshot.read(8))
        rip = pwn.u64(snapshot.read(8))

        elf.address = pwn.u64(snapshot.read(8))

        total_mappings = pwn.u64(snapshot.read(8))

        for i in range(total_mappings):
            mapping_start = pwn.u64(snapshot.read(8))
            mapping_size = pwn.u64(snapshot.read(8))
            mapping_data = snapshot.read(mapping_size)

            Triton.setConcreteMemoryAreaValue(mapping_start, mapping_data)

    print('Done')

    CHECK_ADDR = elf.functions['ReplicateValue'].address
    RET_ADDR = Triton.getConcreteMemoryValue(MemoryAccess(rsp, 8))

    INPUT_BUF_ADDR = 0xFFFFFFFF_FF000000  # Use a kernel address to make sure we don't overwrite mapped addresses.

    Triton.setConcreteRegisterValue(Triton.registers.rax, rax)
    Triton.setConcreteRegisterValue(Triton.registers.rbx, rbx)
    Triton.setConcreteRegisterValue(Triton.registers.rcx, rcx)
    Triton.setConcreteRegisterValue(Triton.registers.rdx, rdx)
    Triton.setConcreteRegisterValue(Triton.registers.rdi, rdi)
    Triton.setConcreteRegisterValue(Triton.registers.rsi, rsi)
    Triton.setConcreteRegisterValue(Triton.registers.r8, r8)
    Triton.setConcreteRegisterValue(Triton.registers.r9, r9)
    Triton.setConcreteRegisterValue(Triton.registers.r10, r10)
    Triton.setConcreteRegisterValue(Triton.registers.r11, r11)
    Triton.setConcreteRegisterValue(Triton.registers.r12, r12)
    Triton.setConcreteRegisterValue(Triton.registers.r13, r13)
    Triton.setConcreteRegisterValue(Triton.registers.r14, r14)
    Triton.setConcreteRegisterValue(Triton.registers.r15, r15)
    Triton.setConcreteRegisterValue(Triton.registers.rbp, rbp)
    Triton.setConcreteRegisterValue(Triton.registers.rsp, rsp)
    Triton.setConcreteRegisterValue(Triton.registers.rip, rip)

    print(
        f'[#] Input Buffer: {INPUT_BUF_ADDR:x}, Input Buffer Len: {len(fuzzer_input)}'
    )
    Triton.setConcreteRegisterValue(Triton.registers.rdi, INPUT_BUF_ADDR)
    Triton.setConcreteRegisterValue(Triton.registers.rsi, len(fuzzer_input))

    for i in range(len(fuzzer_input)):
        Triton.setConcreteMemoryValue(
            MemoryAccess(INPUT_BUF_ADDR + i, 1), fuzzer_input[i]
        )
        Triton.symbolizeMemory(
            MemoryAccess(INPUT_BUF_ADDR + i, 1), f'fuzzer_input[{i}]'
        )

    print(f'[#] Executing... CHECK_ADDR is {CHECK_ADDR:x}')

    branches = []
    addr2func = {}

    for func in elf.functions:
        addr2func[elf.functions[func].address] = func

    while True:
        rip = Triton.getConcreteRegisterValue(Triton.registers.rip)

        if rip == RET_ADDR:
            break

        if rip == CHECK_ADDR and len(branches) > 10000:
            model, status, _ = Triton.getModel(
                Triton.getPathPredicate(), status=True, timeout=1000
            )
            assert status == SOLVER_STATE.SAT
            print('Found Solution')

            seed_data = [
                (Triton.getSymbolicVariable(k).getOrigin(), v.getValue())
                for (k, v) in model.items()
            ]
            seed_data = sorted(
                (addr - INPUT_BUF_ADDR, value) for (addr, value) in seed_data
            )

            for offset, value in seed_data:
                if fuzzer_input[offset] == value:
                    continue
                fuzzer_input[offset] = value

            with open(f'result', 'wb') as f:
                f.write(fuzzer_input)

            break

        inst = Instruction(rip, Triton.getConcreteMemoryAreaValue(rip, 15))

        res = Triton.processing(inst)
        assert res == EXCEPTION.NO_FAULT
        assert inst.getType() != OPCODE.X86.SYSCALL

        if inst.isBranch():
            branch_index = len(branches)
            branch_info = (
                f'{rip:x}|{"taken" if inst.isConditionTaken() else "not taken"}'
            )
            branches.append(branch_info)

            if (
                expected_branches is not None
                and expected_branches[branch_index] != branch_info
            ):
                print(
                    'BRANCH ISSUE!',
                    branch_info,
                    expected_branches[branch_index],
                    inst,
                    branch_index,
                    f'{rip - elf.address:x}',
                    len(Triton.getPathConstraints()),
                )
                break

    return branches


if __name__ == '__main__':
    main()
