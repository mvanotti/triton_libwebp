#!/usr/bin/python3

from ptrace.binding import (
    ptrace_setoptions,
    ptrace_cont,
    ptrace_getregs,
    ptrace_setregs,
    ptrace_singlestep,
)
from ptrace.binding.func import PTRACE_O_TRACEEXEC

from dataclasses import dataclass
from typing import List, Optional
import os


@dataclass
class MemoryMapping:
    start: int
    end: int
    size: int
    perms: str
    offset: int
    dev: str
    inode: str
    pathname: Optional[str]


@dataclass
class MemoryMappings:
    mappings: List[MemoryMapping]

    def find_start_address(self, pathname):
        # Mappings are ordered.
        for mapping in self.mappings:
            if mapping.pathname == pathname:
                return mapping.start

        return None

    def find_mapping_containing(self, address):
        for mapping in self.mappings:
            if mapping.start <= address < mapping.end:
                return mapping

        return None


def parse_mappings(pid):
    with open(f'/proc/{pid}/maps', 'r') as maps:
        mappings = [line.strip() for line in maps]

    result = []

    for line in mappings:
        address_range, perms, offset, dev, line = line.split(maxsplit=4)
        start, end = [int(x, 16) for x in address_range.split('-')]
        size = end - start

        offset = int(offset, 16)
        if ' ' in line:
            inode, pathname = line.split(maxsplit=1)
        else:
            inode, pathname = line, None

        result.append(
            MemoryMapping(start, end, size, perms, offset, dev, inode, pathname)
        )

    return MemoryMappings(result)


# TODO(mvanotti): Add memory mapping parsing tests.


class Debugger:
    def __init__(self, pid: int, is_aarch64=False):
        self.pid = pid
        self.breakpoints = {}

        if is_aarch64:
            self.wait_for_breakpoint = self._wait_for_breakpoint_aarch64
            self._resume_from_breakpoint = self._resume_for_breakpoint_aarch64
            self._breakpoint_instruction = b'\x00\x00\x20\xd4'  # brk #0
            self.program_counter = lambda: self.registers().pc
        else:
            self.wait_for_breakpoint = self._wait_for_breakpoint_x64
            self._resume_from_breakpoint = self._resume_from_breakpoint_x64
            self._breakpoint_instruction = b'\xcc'  # int3
            self.program_counter = lambda: self.registers().rip

        # Tracee is stopped after PTRACE_TRACEME
        self._wait_stop()

        # Wait on exec
        ptrace_setoptions(pid, PTRACE_O_TRACEEXEC)
        self.cont()
        self._wait_stop()
        # We are afecter execve.

        self.procmemfd = os.open(f'/proc/{pid}/mem', os.O_RDWR)
        assert self.procmemfd != -1

    def read_memory(self, address: int, n: int):
        res = os.lseek(self.procmemfd, address, os.SEEK_SET)
        assert res == address

        res = os.read(self.procmemfd, n)
        assert len(res) == n

        return res

    def write_memory(self, address: int, data: bytes):
        assert os.lseek(self.procmemfd, address, os.SEEK_SET) == address
        return os.write(self.procmemfd, data)

    def set_breakpoint(self, address: int):
        assert address not in self.breakpoints

        data = self.read_memory(address, len(self._breakpoint_instruction))
        assert len(data) == len(self._breakpoint_instruction)

        print(f'setting breakpoint on address {address:x} old data: {data}')
        self.breakpoints[address] = data
        n = self.write_memory(address, self._breakpoint_instruction)
        assert n == len(self._breakpoint_instruction)

    def _wait_for_breakpoint_x64(self):
        self._wait_stop()
        regs = self.registers()
        old_ip = regs.rip - 1
        assert old_ip in self.breakpoints

        regs.rip = old_ip

        self.set_registers(regs)

        assert self.write_memory(old_ip, self.breakpoints[old_ip]) == len(
            self._breakpoint_instruction
        )

    def _wait_for_breakpoint_aarch64(self):
        self._wait_stop()
        regs = self.registers()
        old_ip = regs.pc
        assert old_ip in self.breakpoints

        regs.pc = old_ip

        self.set_registers(regs)

        assert self.write_memory(old_ip, self.breakpoints[old_ip]) == len(
            self._breakpoint_instruction
        )

    def cont(self):
        pc = self.program_counter()
        if pc in self.breakpoints:
            self._resume_from_breakpoint()
        else:
            ptrace_cont(self.pid)

    def _resume_from_breakpoint_x64(self):
        regs = self.registers()
        assert regs.rip in self.breakpoints
        del self.breakpoints[regs.rip]

        self.step()
        regs = self.registers()

        print(f'Stopped after singlestep, rip is {regs.rip:x}')

        self.set_breakpoint(regs.rip)
        ptrace_cont(self.pid)

    def _resume_from_breakpoint_aarch64(self):
        regs = self.registers()
        assert regs.pc in self.breakpoints
        del self.breakpoints[regs.pc]

        self.step()
        regs = self.registers()

        print(f'Stopped after singlestep, pc is {regs.pc:x}')

        self.set_breakpoint(regs.pc)
        ptrace_cont(self.pid)

    def registers(self):
        return ptrace_getregs(self.pid)

    def set_registers(self, regs):
        ptrace_setregs(self.pid, regs)

    def _wait_stop(self):
        waitpid, status = os.waitpid(self.pid, 0)

        assert waitpid == self.pid
        assert os.WIFSTOPPED(
            status
        ), f'Invalid status: {status}, exited: {os.WIFEXITED(status)}'

    def step(self):
        ptrace_singlestep(self.pid)
        self._wait_stop()
