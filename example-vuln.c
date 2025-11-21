/**
 * Example vulnerable program for testing dangerous function tracker
 *
 * Compile: gcc -o example-vuln example-vuln.c -no-pie -fno-stack-protector
 *
 * This program contains multiple vulnerabilities:
 * - Buffer overflow (strcpy, gets)
 * - Format string vulnerability (printf)
 * - Command injection (system)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vulnerable_strcpy(char *input) {
    char buffer[64];
    printf("[*] Testing strcpy...\n");
    // VULN: Unbounded copy
    strcpy(buffer, input);
    printf("[+] Buffer contains: %s\n", buffer);
}

void vulnerable_sprintf(char *input) {
    char buffer[64];
    printf("[*] Testing sprintf...\n");
    // VULN: Unbounded formatted output
    sprintf(buffer, "User input: %s", input);
    printf("[+] Buffer contains: %s\n", buffer);
}

void vulnerable_format_string(char *input) {
    printf("[*] Testing format string...\n");
    // VULN: User-controlled format string
    printf(input);
    printf("\n");
}

void vulnerable_system(char *input) {
    char command[128];
    printf("[*] Testing system()...\n");
    // VULN: Command injection
    sprintf(command, "echo %s", input);
    system(command);
}

void vulnerable_gets() {
    char buffer[64];
    printf("[*] Testing gets()...\n");
    printf("Enter something: ");
    fflush(stdout);
    // VULN: gets() has no bounds checking
    gets(buffer);
    printf("[+] You entered: %s\n", buffer);
}

void vulnerable_scanf() {
    char buffer[32];
    printf("[*] Testing scanf()...\n");
    printf("Enter a string: ");
    fflush(stdout);
    // VULN: No width limit on %s
    scanf("%s", buffer);
    printf("[+] You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    printf("=== Dangerous Function Tracker Test Program ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <mode> [input]\n", argv[0]);
        printf("Modes:\n");
        printf("  1 - strcpy test\n");
        printf("  2 - sprintf test\n");
        printf("  3 - format string test\n");
        printf("  4 - system() test\n");
        printf("  5 - gets() test\n");
        printf("  6 - scanf() test\n");
        printf("  7 - all tests (with argv[2] as input)\n");
        return 1;
    }

    int mode = atoi(argv[1]);
    char *input = argc > 2 ? argv[2] : "default_input";

    switch (mode) {
        case 1:
            vulnerable_strcpy(input);
            break;
        case 2:
            vulnerable_sprintf(input);
            break;
        case 3:
            vulnerable_format_string(input);
            break;
        case 4:
            vulnerable_system(input);
            break;
        case 5:
            vulnerable_gets();
            break;
        case 6:
            vulnerable_scanf();
            break;
        case 7:
            vulnerable_strcpy(input);
            vulnerable_sprintf(input);
            vulnerable_format_string(input);
            vulnerable_system(input);
            break;
        default:
            printf("Invalid mode\n");
            return 1;
    }

    printf("\n[+] Program completed\n");
    return 0;
}
