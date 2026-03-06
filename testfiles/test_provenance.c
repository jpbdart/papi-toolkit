// test_provenance.c - Test file for provenance-aware parse insertion
// Demonstrates pass-through vs. modified parameter analysis

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// Example 1: Pass-through parameter
// ============================================================

// Helper that uses data but doesn't modify it
void
log_data (const char *data)
{
    printf ("Logging: %s\n", data);
}

// process_request receives 'data' and passes it unchanged to helper
// If caller validates 'data', the validation should propagate through
void
process_request (char *data, int len)
{
    // 'data' is NOT modified here - just passed through
    log_data (data); // Pass-through: inherits caller's validation

    // 'len' is also pass-through
    printf ("Length: %d\n", len);
}

// ============================================================
// Example 2: Modified parameter
// ============================================================

// handle_message modifies the buffer before use
void
handle_message (char *buffer, int size)
{
    // 'buffer' IS modified here
    buffer[0] = toupper (buffer[0]); // Modification!

    // Now 'buffer' cannot inherit validation from caller
    // Need fresh validation here
    printf ("Modified message: %s\n", buffer);
}

// ============================================================
// Example 3: Mixed - one pass-through, one modified
// ============================================================

void process_mixed (char *data, char *buffer, int len)
{
    // 'data' is pass-through (only read)
    printf ("Data: %s\n", data);

    // 'buffer' is modified (written to)
    strncpy (buffer, data, len);
    buffer[len - 1] = '\0';

    // 'len' is pass-through (only read)
}

// ============================================================
// Example 4: Indirect modification through function call
// ============================================================

void read_into_buffer (char *buf, int max_len)
{
    fgets (buf, max_len, stdin); // 'buf' modified via fgets
}

void process_with_read (char *buffer, int len)
{
    // 'buffer' gets modified by read_into_buffer
    read_into_buffer (buffer, len);

    // Now buffer is RAW (from fgets), regardless of what caller passed
    printf ("Read: %s\n", buffer);
}

// ============================================================
// Example 5: Struct member pass-through
// ============================================================

typedef struct
{
    char *name;
    int value;
} Record;

void
print_record (Record *rec)
{
    // 'rec' is dereferenced but not modified
    // Members are only read
    printf ("Name: %s, Value: %d\n", rec->name, rec->value);
}

void
modify_record (Record *rec)
{
    // 'rec' members ARE modified
    rec->value = rec->value * 2; // Modification!
}

// ============================================================
// Example 6: Chain of pass-throughs
// ============================================================

void
inner_helper (const char *s)
{
    printf ("%s\n", s);
}

void
middle_helper (const char *s)
{
    inner_helper (s); // Pass-through
}

void
outer_function (char *s)
{
    middle_helper (s); // Pass-through chain: outer -> middle -> inner
}

// ============================================================
// Example 7: Validation followed by pass-through
// ============================================================

int
parse_int (const char *str)
{
    // Parser function - elevates to SYNTACTIC
    return atoi (str);
}

void
use_parsed_value (int val)
{
    // val comes from parse_int output (SYNTACTIC)
    printf ("Value: %d\n", val);
}

void
validated_flow (char *input)
{
    int value = parse_int (input); // RAW -> SYNTACTIC
    use_parsed_value (value);      // SYNTACTIC passed through
}

// ============================================================
// Example 8: Sink requiring validation
// ============================================================

void
execute_command (char *cmd)
{
    // SINK: requires CONTEXTUAL validation
    system (cmd);
}

// Bad: Modified parameter passed to sink
void
bad_execute (char *cmd)
{
    cmd[0] = '/';          // Modification
    execute_command (cmd); // cmd is RAW here, needs validation
}

// Good: Unmodified parameter - validation can come from caller
void
good_execute (const char *cmd)
{
    execute_command ((char *)cmd); // Pass-through: caller validated
}

// ============================================================
// Main - entry point where RAW data enters
// ============================================================

int
main (int argc, char *argv[])
{
    char buffer[256];

    // RAW data source
    if (fgets (buffer, sizeof (buffer), stdin) != NULL)
        {
            // Remove newline
            size_t len = strlen (buffer);
            if (len > 0 && buffer[len - 1] == '\n')
                {
                    buffer[len - 1] = '\0';
                }

            // Test various patterns
            process_request (buffer, len); // Pass-through
            handle_message (buffer, len);  // Modified

            char output[256];
            process_mixed (buffer, output, sizeof (output));

            // Chain test
            outer_function (buffer);

            // Validation flow
            validated_flow (buffer);
        }

    return 0;
}
