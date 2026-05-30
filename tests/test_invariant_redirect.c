#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/*
 * Self-contained simulation of the vulnerable redirect.c buffer construction
 * logic. We replicate the sprintf chain from redirect.c and instrument it
 * with a canary-guarded allocation so that any out-of-bounds write is
 * detected at assertion time.
 *
 * Invariant: Buffer reads/writes never exceed the declared allocation size.
 * The combined output of CONNECT line + hostname (capped at 256) + port +
 * Proxy-Authorization header + Base64 credentials + CRLFs must fit within
 * the allocated buffer, OR the implementation must reject/truncate the input.
 */

#define ALLOC_SIZE   512   /* size used in the real code (approx) */
#define CANARY_SIZE  64
#define CANARY_BYTE  0xAB

/* Base64 encode helper (minimal, self-contained) */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char *in, size_t in_len,
                         char *out, size_t out_size)
{
    size_t i, o = 0;
    for (i = 0; i < in_len && o + 4 < out_size; i += 3) {
        unsigned char b0 = in[i];
        unsigned char b1 = (i + 1 < in_len) ? in[i+1] : 0;
        unsigned char b2 = (i + 2 < in_len) ? in[i+2] : 0;
        out[o++] = b64_table[b0 >> 2];
        out[o++] = b64_table[((b0 & 0x3) << 4) | (b1 >> 4)];
        out[o++] = (i + 1 < in_len) ? b64_table[((b1 & 0xf) << 2) | (b2 >> 6)] : '=';
        out[o++] = (i + 2 < in_len) ? b64_table[b2 & 0x3f] : '=';
    }
    if (o < out_size) out[o] = '\0';
    else out[out_size - 1] = '\0';
    return (int)o;
}

/*
 * Simulate the vulnerable buffer-building logic from redirect.c.
 * Returns the number of bytes written into buf, or -1 if a canary
 * violation is detected (i.e., an out-of-bounds write occurred).
 *
 * The buffer layout:
 *   [ CANARY_SIZE bytes | ALLOC_SIZE bytes (buf) | CANARY_SIZE bytes ]
 */
static int simulate_redirect_connect(const char *hostname,
                                     const char *port,
                                     const char *user,
                                     const char *pass)
{
    /* Allocate with canaries on both sides */
    size_t total = CANARY_SIZE + ALLOC_SIZE + CANARY_SIZE;
    unsigned char *raw = (unsigned char *)malloc(total);
    if (!raw) return -2;

    memset(raw,                  CANARY_BYTE, CANARY_SIZE);
    memset(raw + CANARY_SIZE,    0x00,        ALLOC_SIZE);
    memset(raw + CANARY_SIZE + ALLOC_SIZE, CANARY_BYTE, CANARY_SIZE);

    unsigned char *buf = raw + CANARY_SIZE;

    /* ---- Replicate the sprintf chain from redirect.c ---- */
    int len = 0;

    /* "CONNECT " */
    len += sprintf((char *)buf + len, "CONNECT ");

    /* hostname truncated to 256 chars */
    len += sprintf((char *)buf + len, "%.256s", hostname);

    /* ":port HTTP/1.0\r\n" */
    len += sprintf((char *)buf + len, ":%s HTTP/1.0\r\n", port);

    /* Proxy-Authorization header if user is provided */
    if (user && user[0] != '\0') {
        /* Build "user:pass" credential string (128+1+128 max) */
        unsigned char cred[260];
        snprintf((char *)cred, sizeof(cred), "%.128s:%.128s",
                 user, pass ? pass : "");

        /* Base64-encode credentials */
        char b64cred[400];
        base64_encode(cred, strlen((char *)cred), b64cred, sizeof(b64cred));

        len += sprintf((char *)buf + len, "Proxy-Authorization: Basic ");
        len += sprintf((char *)buf + len, "%s", b64cred);
        len += sprintf((char *)buf + len, "\r\n");
    }

    /* Final blank line */
    len += sprintf((char *)buf + len, "\r\n");
    /* ---- End of sprintf chain ---- */

    /* Check canaries */
    int canary_ok = 1;
    for (int i = 0; i < CANARY_SIZE; i++) {
        if (raw[i] != CANARY_BYTE) { canary_ok = 0; break; }
    }
    for (int i = 0; i < CANARY_SIZE; i++) {
        if (raw[CANARY_SIZE + ALLOC_SIZE + i] != CANARY_BYTE) {
            canary_ok = 0; break;
        }
    }

    free(raw);

    if (!canary_ok) return -1;   /* canary violated → OOB write detected */
    return len;
}

/* ------------------------------------------------------------------ */

START_TEST(test_redirect_buffer_no_oob)
{
    /* Invariant: Buffer writes never exceed the declared allocation size.
     * For any combination of hostname, port, username, and password,
     * the sprintf chain must not write beyond ALLOC_SIZE bytes. */

    struct {
        const char *hostname;
        const char *port;
        const char *user;
        const char *pass;
        const char *description;
    } payloads[] = {
        /* Normal inputs */
        { "proxy.example.com", "8080", "user", "pass",
          "normal input" },
        { "localhost", "3128", NULL, NULL,
          "no auth" },

        /* Hostname exactly at the 256-byte truncation boundary */
        { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "8080", "user", "pass",
          "hostname exactly 256 bytes" },

        /* Hostname 2x oversized (512 bytes) */
        { "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
          "8080", "user", "pass",
          "hostname 2x oversized (512 bytes)" },

        /* Hostname 10x oversized (2560 bytes) */
        { "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
          "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
          "8080", "user", "pass",
          "hostname 10x oversized (2560 bytes)" },

        /* Username exactly at 128-byte truncation boundary */
        { "proxy.example.com", "8080",
          "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"
          "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU",
          "pass",
          "username exactly 128 bytes" },

        /* Username 2x oversized (256 bytes) */
        { "proxy.example.com", "8080",
          "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"