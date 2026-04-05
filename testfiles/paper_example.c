/*----------------------------------------------------------------------
 *
 * Filename: paper_example.c
 * Description: Sample portion of code used in the PAPI research paper
 *              in Section VI.C.
 *
 * This is the "illustrative example" mentioned in the PAPI paper, reproduced
 * for testing changes to the analyzer.
 *
 * Date       Pgm  Comments
 * 05 Apr 26  jpb  Creation from paper. Added includes to stop clang messages.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Network input - returns RAW data */
char* receive_packet(int socket) {
    char* buf = (char *)malloc(1024);
    read(socket, buf, 1024);
    return buf;
}

/* VIOLATION: RAW to dangerous sink */
void process_direct(int socket) {
    char* data = receive_packet(socket);
    printf(data);  /* Format string vuln! */
}

/* SAFE: Validated before use */
void process_validated(int socket) {
    char* data = receive_packet(socket);
    int value;
    if (sscanf(data, "%d", &value) != 1)
        return;  /* Reject invalid */
    printf("Value: %d\n", value);
}

/* PASSTHROUGH: Inherits caller status */
void log_message(const char* msg, int level) {
    fprintf(stderr, "[%d] %s\n", level, msg);
}
