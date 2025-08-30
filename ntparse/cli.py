# command line interface for ntparse

import argparse
import sys
from pathlib import Path
from typing import Optional
from .core import parse_ntdll, NtParseError, validate_ntdll_path
from .formatter import to_json, to_csv, to_asm, to_python_dict

def main():
    parser = argparse.ArgumentParser(
        description="Parse syscalls from ntdll.dll",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  ntparse --input C:\\Windows\\System32\\ntdll.dll --format json
  ntparse --format csv --output syscalls.csv
  ntparse --format asm --output syscalls.asm
  ntparse --format python --output syscalls.py"""
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        help="Path to ntdll.dll (default: C:\\Windows\\System32\\ntdll.dll)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "asm", "python"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--arch",
        choices=["x64", "x86"],
        default="x64",
        help="Target architecture (default: x64)"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate ntdll.dll before parsing"
    )
    if len(sys.argv) == 1:
        parser.print_help()
        print("\nNo arguments provided. Use --help for more information.")
        sys.exit(0)
    args = parser.parse_args()
    try:
        syscalls = parse_ntdll(args.input, args.arch)
        if not syscalls:
            print("No syscalls found in the specified ntdll.dll", file=sys.stderr)
            sys.exit(1)
        if args.validate and args.input:
            if not validate_ntdll_path(args.input):
                print(f"Warning: {args.input} may not be a valid ntdll.dll", file=sys.stderr)
        if args.format == "json":
            output = to_json(syscalls)
        elif args.format == "csv":
            output = to_csv(syscalls)
        elif args.format == "asm":
            output = to_asm(syscalls)
        elif args.format == "python":
            output = to_python_dict(syscalls)
        else:
            print(f"Unknown format: {args.format}", file=sys.stderr)
            sys.exit(1)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(output)
            print(f"Output written to: {output_path}")
        else:
            print(output)
        print(f"Parsed {len(syscalls)} syscalls from ntdll.dll", file=sys.stderr)
    except NtParseError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 