// file_a.c - First file in two-file test
// Demonstrates cross-file taint tracking

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declaration of function in file_b.c
extern void process_command (char *cmd);
extern int parse_and_validate (const char *input);

// This function reads input and passes it to another file
void
read_and_dispatch (void)
{
    char buffer[256];

    // Taint source: fgets introduces RAW data
    if (fgets (buffer, sizeof (buffer), stdin) != NULL)
        {
            // Remove newline
            size_t len = strlen (buffer);
            if (len > 0 && buffer[len - 1] == '\n')
                {
                    buffer[len - 1] = '\0';
                }

            // Pass RAW data to function in file_b.c
            // This should be tracked across file boundaries
            process_command (buffer);
        }
}

// This function does proper parsing before cross-file call
void
read_and_dispatch_safely (void)
{
    char buffer[256];

    if (fgets (buffer, sizeof (buffer), stdin) != NULL)
        {
            // Parse and validate first (function in file_b.c)
            int result = parse_and_validate (buffer);

            // Now result should be at a higher taint level
            // (depending on what parse_and_validate does)
            printf ("Parsed result: %d\n", result);
        }
}

int
main (int argc, char *argv[])
{
    printf ("Reading input...\n");

    // Unsafe path
    read_and_dispatch ();

    // Safer path
    read_and_dispatch_safely ();

    return 0;
}
