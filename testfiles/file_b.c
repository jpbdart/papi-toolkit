// file_b.c - Second file in two-file test
// Contains functions called from file_a.c

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parser: converts string to int with validation
// Following naming convention, this elevates to SYNTACTIC
int
parse_int (const char *str)
{
    if (str == NULL || *str == '\0')
        {
            return -1;
        }

    // Check all characters are digits (with optional leading minus)
    const char *p = str;
    if (*p == '-')
        p++;

    while (*p)
        {
            if (!isdigit (*p))
                {
                    return -1; // Invalid
                }
            p++;
        }

    return atoi (str);
}

// Validator: checks value is in valid range
// Elevates from SYNTACTIC to SEMANTIC
int
validate_range (int value, int min, int max)
{
    if (value < min || value > max)
        {
            return -1;
        }
    return value;
}

// Combined parse and validate - returns SEMANTIC level data
int
parse_and_validate (const char *input)
{
    // Parse first
    int value = parse_int (input);
    if (value < 0)
        {
            return -1;
        }

    // Then validate
    return validate_range (value, 0, 1000);
}

// This function receives data from file_a.c
// The 'cmd' parameter will be RAW when called from read_and_dispatch
void
process_command (char *cmd)
{
    // Direct use of potentially tainted data
    // This should trigger a violation
    printf ("Executing: %s\n", cmd);

    // VIOLATION: cmd is RAW but system() needs CONTEXTUAL
    system (cmd);
}

// A safer version that parses first
void
process_command_safely (char *cmd)
{
    // Parse the command
    int parsed = parse_int (cmd);

    if (parsed >= 0)
        {
            // Now we have SYNTACTIC data
            // Still not safe for system(), but better
            char safe_cmd[64];
            snprintf (safe_cmd, sizeof (safe_cmd), "echo %d", parsed);

            // This is safer - we're using a controlled format
            // But analyzer may still flag it depending on configuration
            system (safe_cmd);
        }
}
