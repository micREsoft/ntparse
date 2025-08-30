# utility functions for ntparse

import os
import platform
import pefile
from typing import Dict, List, Optional, Tuple
from pathlib import Path

def detect_system_architecture() -> str:
    # detect the current system architecture
    # returns: architecture string ("x64" or "x86")
    if platform.architecture()[0] == "64bit":
        return "x64"
    else:
        return "x86"

def get_default_ntdll_path() -> str:
    system_root = os.environ.get('SystemRoot', 'C:\\Windows')
    return os.path.join(system_root, 'System32', 'ntdll.dll')

def find_ntdll_files() -> List[str]:
    ntdll_paths = []
    common_paths = [
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'ntdll.dll'),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64', 'ntdll.dll'),
    ]
    for path in common_paths:
        if os.path.exists(path):
            ntdll_paths.append(path)
    return ntdll_paths

def get_pe_info(file_path: str) -> Dict:
    # get basic information about a PE file
    # returns: dictionary with PE file information
    try:
        pe = pefile.PE(file_path)
        info = {
            "file_path": file_path,
            "machine": pe.FILE_HEADER.Machine,
            "is_64bit": pe.OPTIONAL_HEADER.Magic == 0x20b,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "has_exports": hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT is not None,
        }
        if info["has_exports"]:
            info["export_count"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        pe.close()
        return info
    except Exception as e:
        return {
            "file_path": file_path,
            "error": str(e)
        }

def is_valid_ntdll(file_path: str) -> bool:
    # check if a file is a valid ntdll.dll
    # returns: True if the file is a valid ntdll.dll
    try:
        pe = pefile.PE(file_path)
        # check if it's 64-bit
        if pe.OPTIONAL_HEADER.Magic != 0x20b:
            return False
        # check if it has exports
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or not pe.DIRECTORY_ENTRY_EXPORT:
            return False
        # check if it's a DLL
        if not (pe.FILE_HEADER.Characteristics & 0x2000):
            return False
        pe.close()
        return True
    except Exception:
        return False

def get_exported_functions(file_path: str) -> List[str]:
    # get list of exported functions from a PE file
    # returns: list of exported function names
    try:
        pe = pefile.PE(file_path)
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or not pe.DIRECTORY_ENTRY_EXPORT:
            return []
        functions = []
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name:
                functions.append(export.name.decode('utf-8', errors='ignore'))
        pe.close()
        return functions
    except Exception:
        return []

def filter_nt_functions(functions: List[str]) -> List[str]:
    # filter list to only include Nt* functions
    # returns: list of Nt* function names
    return [f for f in functions if f.startswith('Nt')]

def filter_zw_functions(functions: List[str]) -> List[str]:
    # filter list to only include Zw* functions
    # returns: list of Zw* function names
    return [f for f in functions if f.startswith('Zw')]

def get_offsets(syscalls: Dict[str, int]) -> Dict[str, str]:
    # convert decimal syscall numbers to hexadecimal offsets
    # returns: dictionary mapping function names to hexadecimal offset strings
    offsets = {}
    for func_name, syscall_num in syscalls.items():
        hex_offset = f"0x{syscall_num:02X}"
        offsets[func_name] = hex_offset
    return offsets

def get_asm_offsets(syscalls: Dict[str, int]) -> Dict[str, str]:
    # convert decimal syscall numbers to hexadecimal offsets for assembly
    # returns: dictionary mapping function names to hexadecimal offset strings
    offsets = {}
    for func_name, syscall_num in syscalls.items():
        hex_offset = f"{syscall_num:02X}h"
        offsets[func_name] = hex_offset
    return offsets

def format_syscall_number(number: int, format_type: str = "hex") -> str:
    # format a syscall number in different formats
    # returns: formatted string
    if format_type == "hex":
        return f"0x{number:02X}"
    elif format_type == "decimal":
        return str(number)
    elif format_type == "both":
        return f"{number} (0x{number:02X})"
    else:
        return str(number)

def create_syscall_table(syscalls: Dict[str, int], include_zw: bool = True) -> Dict[str, Dict[str, int]]:
    # create a structured syscall table with Nt and Zw functions
    # returns: structured syscall table
    table = {
        "nt": {},
        "zw": {}
    }
    for func_name, syscall_num in syscalls.items():
        if func_name.startswith('Nt'):
            table["nt"][func_name] = syscall_num
            if include_zw:
                zw_name = func_name.replace('Nt', 'Zw', 1)
                table["zw"][zw_name] = syscall_num
        elif func_name.startswith('Zw'):
            table["zw"][func_name] = syscall_num
            if include_zw:
                nt_name = func_name.replace('Zw', 'Nt', 1)
                table["nt"][nt_name] = syscall_num
    return table 