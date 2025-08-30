# ntparse - A lightweight Python package for parsing syscalls from ntdll.dll

__version__ = "0.2.0"
__author__ = "micREsoft"
__email__ = "contact@reverseengineeri.ng"

from .core import parse_ntdll, get_syscalls
from .formatter import to_json, to_csv, to_asm, to_python_dict

__all__ = [
    "parse_ntdll",
    "get_syscalls", 
    "to_json",
    "to_csv", 
    "to_asm",
    "to_python_dict",
] 