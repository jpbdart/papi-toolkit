// test1.c - Simple single-file test with taint violations
// This file demonstrates taint tracking through a simple program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulated parser function - the analyzer recognizes parse_* as parsers
int
parse_int (const char *str)
{
    // In real code, this would validate the string is a valid integer
    // For now, just call atoi (which doesn't actually validate)
    return atoi (str);
}

// Simulated validator - elevates from SYNTACTIC to SEMANTIC
int
validate_positive (int value)
{
    if (value < 0)
        {
            return -1; // Error
        }
    return value;
}

void
process_data (char *input)
{
    // This should trigger a violation:
    // input is RAW, but system() requires CONTEXTUAL
    system (input); // VIOLATION: RAW -> CONTEXTUAL
}

void
process_data_with_parse (char *input)
{
    // Parse first - elevates to SYNTACTIC
    int value = parse_int (input);

    // Still a violation: SYNTACTIC is not enough for system()
    char cmd[256];
    snprintf (cmd, sizeof (cmd), "echo %d", value);
    system (cmd); // VIOLATION: SYNTACTIC -> CONTEXTUAL
}

void
safe_processing (char *input)
{
    // Parse to SYNTACTIC
    int value = parse_int (input);

    // Validate to SEMANTIC
    int valid_value = validate_positive (value);

    if (valid_value >= 0)
        {
            // Still technically a violation for system() which wants CONTEXTUAL
            // but this demonstrates the multi-layer approach
            printf ("Value: %d\n", valid_value);
        }
}

int
main (int argc, char *argv[])
{
    char buffer[256];

    // Read from stdin - this is a taint source
    if (fgets (buffer, sizeof (buffer), stdin) != NULL)
        {
            // buffer is now RAW

            // Direct use - violation
            process_data (buffer);

            // With parsing - less severe violation
            process_data_with_parse (buffer);

            // Better approach
            safe_processing (buffer);
        }

    // Environment variable - also a taint source
    char *env_val = getenv ("USER_INPUT");
    if (env_val)
        {
            // env_val is RAW
            system (env_val); // VIOLATION: RAW -> CONTEXTUAL
        }

    return 0;
}
