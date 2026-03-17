/*----------------------------------------------------------------------
 *
 * Filename: test_stratum_annotations.c
 * Description: Tests for __attribute__((annotate("stratum:...")))
 *                        support in PAPI.
 *
 * Case 1: stratum:validates(0,SEMANTIC)
 *   sanitize_port() declares that after it returns, parameter 0 (raw_port)
 *   has been elevated to SEMANTIC.  PAPI should NOT flag the call to
 *   connect_to_port() as needing a parse point because the port is already
 *   validated.
 *
 * Case 2: stratum:suppress(OUT_PARAM)
 *   fill_buffer() writes to its first parameter (an OUT param); PAPI would
 *   normally flag this, but the suppress annotation should cause the parse
 *   point to appear with suppressed:true instead of being a bare finding.
 *
 * Case 3: No annotation (control)
 *   process_raw() receives raw input and passes it to a sink without
 *   validation.  This SHOULD produce an actionable parse point.
 *
 * Date       Pgm  Comment
 * 12 Mar 26  jpb  Creation.
 *
 */

// Sink functions
extern void connect_to_port(int port);     // needs SEMANTIC
extern void write_to_socket(char *data);   // needs CONTEXTUAL

// Case 1: validates annotation
void sanitize_port(
    __attribute__((annotate("stratum:validates(0,SEMANTIC)")))
    const char *raw_port,
    int *out_port);

void validated_connect(const char *port_str)
{
    int port;
    sanitize_port(port_str, &port);
    // port is SEMANTIC after sanitize_port — no parse point needed here
    connect_to_port(port);
}

// Case 2: suppress annotation
void fill_buffer(
    __attribute__((annotate("stratum:suppress(OUT_PARAM)")))
    char *buf,
    int len);

void use_fill_buffer(char *output, int sz)
{
    fill_buffer(output, sz);
    // output is written by fill_buffer — the suppress annotation should
    // cause a suppressed:true entry rather than a plain parse point
    write_to_socket(output);
}

// Case 3: unannotated control case
extern char *read_network(int fd);

void process_raw(int fd)
{
    char *data = read_network(fd);
    // data is RAW and flows directly to a sink — expect a real parse point
    write_to_socket(data);
}
