#!/usr/bin/env python3
"""
Helper script to run dangerous function tracking tests
"""

import subprocess
import sys
import os
from pathlib import Path

def compile_example():
    """Compile the example vulnerable program"""
    print("[*] Compiling example-vuln.c...")

    cmd = [
        "gcc",
        "-o", "example-vuln",
        "example-vuln.c",
        "-no-pie",
        "-fno-stack-protector",
        "-Wno-deprecated-declarations"  # Suppress warnings for gets()
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] Compilation failed:")
        print(result.stderr)
        return False

    print("[+] Compilation successful")
    return True

def run_frida_test(mode, test_input="AAAABBBBCCCCDDDD"):
    """Run Frida with the example script"""
    print(f"\n[*] Running test mode {mode} with input: {test_input}")
    print("=" * 80)

    cmd = [
        "frida",
        "-l", "example-dangerous.js",
        "./example-vuln",
        str(mode),
        test_input
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
    except subprocess.TimeoutExpired:
        print("[!] Test timed out")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

def main():
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Convert YAML config to JSON
    print("[*] Converting YAML config to JSON...")
    result = subprocess.run(["python3", "config-converter.py"], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print("[!] Config conversion failed:")
        print(result.stderr)
        return

    # Compile example
    if not compile_example():
        return

    # Run tests
    print("\n" + "=" * 80)
    print("DANGEROUS FUNCTION TRACKING TESTS")
    print("=" * 80)

    if len(sys.argv) > 1:
        # Run specific test
        mode = sys.argv[1]
        test_input = sys.argv[2] if len(sys.argv) > 2 else "AAAABBBBCCCCDDDD"
        run_frida_test(mode, test_input)
    else:
        # Run all tests
        tests = [
            (1, "AAAA_strcpy_overflow"),
            (2, "BBBB_sprintf_overflow"),
            (3, "%x_%x_%x_%x"),  # format string
            (7, "CCCC_all_tests"),  # all tests
        ]

        for mode, test_input in tests:
            run_frida_test(mode, test_input)
            print("\n")

    print("\n[+] All tests completed")

if __name__ == "__main__":
    main()
