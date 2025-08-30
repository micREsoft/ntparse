# core functionality for parsing syscalls from ntdll.dll

import os
import pefile
import capstone
from typing import Dict, Optional, Union
from pathlib import Path

class NtParseError(Exception):
    # custom exception for ntparse errors
    pass

def get_syscalls(dll_path: Union[str, Path]) -> Dict[str, int]:
    # extract syscall numbers from an ntdll.dll file
    # args: dll_path: path to the ntdll.dll file
    # returns: dictionary mapping function names to syscall numbers
    # raises: NtParseError: if the DLL cannot be parsed or is not a valid PE file
    dll_path = Path(dll_path)
    if not dll_path.exists():
        raise NtParseError(f"File not found: {dll_path}")
    try:
        pe = pefile.PE(str(dll_path))
    except Exception as e:
        raise NtParseError(f"Failed to parse PE file {dll_path}: {e}")
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or not pe.DIRECTORY_ENTRY_EXPORT:
        raise NtParseError(f"No export directory found in {dll_path}")
    syscall_numbers = {}
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    except Exception as e:
        raise NtParseError(f"Failed to initialize capstone disassembler: {e}")
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not export.name:
            continue
        func_name = export.name.decode('utf-8', errors='ignore')
        func_rva = export.address
        try:
            func_bytes = pe.get_data(func_rva, 16)
            for instruction in md.disasm(func_bytes, func_rva):
                if instruction.mnemonic == 'mov':
                    op_str = instruction.op_str.lower()
                    if 'eax' in op_str or 'rax' in op_str:
                        parts = op_str.split(',')
                        if len(parts) == 2:
                            try:
                                syscall_id_str = parts[1].strip()
                                if syscall_id_str.startswith('0x'):
                                    syscall_id = int(syscall_id_str, 16)
                                else:
                                    syscall_id = int(syscall_id_str, 10)
                                
                                syscall_numbers[func_name] = syscall_id
                                break
                            except ValueError:
                                continue
        except Exception as e:
            continue
    pe.close()
    return syscall_numbers

def parse_ntdll(
    path: Optional[Union[str, Path]] = None, 
    arch: str = "x64"
) -> Dict[str, int]:
    # parse syscalls from ntdll.dll with automatic path detection
    # args: path: path to ntdll.dll. if None, uses default Windows location
    # arch: architecture ("x64" or "x86"). currently only x64 is supported
    # returns: dictionary mapping function names to syscall numbers
    # raises: NtParseError: if parsing fails
    if arch.lower() != "x64":
        raise NtParseError("Currently only x64 architecture is supported")
    if path is None:
        system32 = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        path = os.path.join(system32, 'ntdll.dll')
    return get_syscalls(path)

def validate_ntdll_path(path: Union[str, Path]) -> bool:
    # validate if a file is a valid ntdll.dll for parsing
    # args: path: path to the file to validate
    # returns: true if the file is a valid ntdll.dll, false otherwise
    try:
        path = Path(path)
        if not path.exists():
            return False
        pe = pefile.PE(str(path))
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or not pe.DIRECTORY_ENTRY_EXPORT:
            return False
        if pe.OPTIONAL_HEADER.Magic != 0x20b:
            return False
        pe.close()
        return True
    except Exception:
        return False 