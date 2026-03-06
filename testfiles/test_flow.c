// test_flow.c - Test file for flow-sensitive analysis
// This file demonstrates cases where flow-sensitive analysis is beneficial

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parser function
int
parse_command (const char *input)
{
    // Validate input is a single digit
    if (input[0] >= '0' && input[0] <= '9' && input[1] == '\0')
        {
            return input[0] - '0';
        }
    return -1;
}

// Case 1: Flow-sensitive should see that after the if-check, data is parsed
void
conditional_parsing (char *input)
{
    int cmd;

    cmd = parse_command (input); // cmd is now SYNTACTIC

    if (cmd >= 0)
        {
            // In this branch, cmd is valid (SYNTACTIC)
            char safe_cmd[64];
            snprintf (safe_cmd, sizeof (safe_cmd), "echo %d", cmd);
            // Flow-sensitive analysis knows cmd is parsed here
            printf ("Executing: %s\n", safe_cmd);
        }
    else
        {
            // In this branch, parsing failed
            // Should NOT use input directly
            // system(input);  // This would be a violation
            printf ("Invalid command\n");
        }
}

// Case 2: Reassignment changes taint
void
reassignment_example (char *input)
{
    char *data = input; // data is RAW

    // Process data...

    // Later, we get safe data from a constant
    data = "safe_value"; // data is now CLEAN

    // This should be safe since data is now a constant
    // (but flow-insensitive might still flag it)
    printf ("Data: %s\n", data);
}

// Case 3: Loop with taint that gets cleared
void
loop_example (char *input)
{
    char buffer[256];

    for (int i = 0; i < 10; i++)
        {
            if (i == 0)
                {
                    // First iteration uses tainted input
                    strcpy (buffer, input); // buffer is RAW
                }
            else
                {
                    // Later iterations use safe data
                    strcpy (buffer, "iteration"); // buffer is CLEAN
                }

            // Here, flow-sensitive needs to be conservative:
            // buffer could be RAW or CLEAN depending on path
            printf ("Buffer: %s\n", buffer);
        }
}

// Case 4: Early return pattern
void
early_return_example (char *input)
{
    int parsed = parse_command (input);

    // If parsing fails, return early
    if (parsed < 0)
        {
            printf ("Parse error\n");
            return;
        }

    // If we reach here, parsed is valid (SYNTACTIC)
    char cmd[64];
    snprintf (cmd, sizeof (cmd), "echo %d", parsed);
    printf ("Would execute: %s\n", cmd);
}

int
main (int argc, char *argv[])
{
    char buffer[256];

    if (fgets (buffer, sizeof (buffer), stdin) != NULL)
        {
            // Remove newline
            size_t len = strlen (buffer);
            if (len > 0 && buffer[len - 1] == '\n')
                {
                    buffer[len - 1] = '\0';
                }

            conditional_parsing (buffer);
            reassignment_example (buffer);
            loop_example (buffer);
            early_return_example (buffer);
        }

    return 0;
}
