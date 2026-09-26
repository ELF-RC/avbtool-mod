/* Standalone FEC tool matching the AOSP `fec` CLI used by avbtool.
 *
 * Subcommands:
 *   fec --print-fec-size SIZE --roots N
 *       Print the number of bytes of FEC data for an input of SIZE bytes.
 *   fec --encode [--roots N] INPUT OUTPUT
 *       Encode INPUT into OUTPUT (RS parity + 4 KiB libfec footer).
 *
 * Interleaving follows system/extras/libfec: the input is grouped into
 * rounds of rs_n = 255 - roots blocks; each codeword takes one byte
 * from every round block at the same column, and parity bytes are
 * written at (round * block_size + column) * roots.
 *
 * SHA-256 (for the footer) is computed with OpenSSL's libcrypto.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <openssl/sha.h>

/* RS-8 codec interface (extern/fec char variant; struct definition lives
 * in fec/rs-common.h which char.h consumers include). */
typedef unsigned char data_t;
#include "rs-common.h"

void *init_rs_char(int symsize, int gfpoly, int fcr, int prim, int nroots, int pad);
void encode_rs_char(void *rs, data_t *data, data_t *parity);
void free_rs_char(void *rs);

#define FEC_BLOCK_SIZE 4096
#define FEC_RSM 255
#define FEC_MAGIC 0xfecfecfe

static void die(const char *msg) {
  fprintf(stderr, "fec: %s\n", msg);
  exit(1);
}

static size_t fec_size_for(size_t input_size, int roots) {
  size_t rs_n = (size_t)FEC_RSM - (size_t)roots;
  size_t blocks = (input_size + FEC_BLOCK_SIZE - 1) / FEC_BLOCK_SIZE;
  size_t rounds = (blocks + rs_n - 1) / rs_n;
  return rounds * (size_t)roots * FEC_BLOCK_SIZE + FEC_BLOCK_SIZE;
}

int main(int argc, char **argv) {
  int roots = 2;
  int have_roots = 0;
  const char *input = NULL;
  const char *output = NULL;
  size_t size_arg = 0;
  int have_size = 0;
  int mode_encode = 0;
  int mode_size = 0;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--roots")) {
      if (++i >= argc) die("--roots needs a value");
      roots = atoi(argv[i]);
      have_roots = 1;
    } else if (!strcmp(argv[i], "--print-fec-size")) {
      if (++i >= argc) die("--print-fec-size needs a value");
      size_arg = strtoumax(argv[i], NULL, 0);
      have_size = 1;
      mode_size = 1;
    } else if (!strcmp(argv[i], "--encode")) {
      mode_encode = 1;
    } else {
      if (!input) input = argv[i];
      else if (!output) output = argv[i];
      else die("too many arguments");
    }
  }

  if (roots < 1 || roots >= FEC_RSM)
    die("--roots must be in [1, 254]");

  if (mode_size) {
    if (!have_size) die("--print-fec-size needs an input size");
    if (size_arg == 0) die("input size must be non-zero");
    if (size_arg % FEC_BLOCK_SIZE != 0)
      die("input size must be a multiple of the FEC block size");
    printf("%" PRIu64 "\n", fec_size_for(size_arg, roots));
    return 0;
  }

  if (!mode_encode)
    die("nothing to do (use --print-fec-size or --encode)");
  if (!input || !output)
    die("--encode needs INPUT and OUTPUT");

  struct rs *rs = init_rs_char(8, 0x11d, 0, 1, roots, 0);
  if (!rs) die("failed to initialize RS codec");
  const size_t rs_n = (size_t)FEC_RSM - (size_t)roots;
  FILE *in = fopen(input, "rb");
  if (!in) die("cannot open input");

  /* Read the whole input into memory. */
  long in_len;
  if (fseek(in, 0, SEEK_END) || (in_len = ftell(in)) < 0 || fseek(in, 0, SEEK_SET))
    die("cannot stat input");
  unsigned char *data = malloc(in_len ? in_len : 1);
  if (!data) die("out of memory");
  if (fread(data, 1, in_len, in) != (size_t)in_len) die("short read on input");
  fclose(in);

  const size_t input_size = (size_t)in_len;
  if (input_size == 0) die("empty input");
  if (input_size % FEC_BLOCK_SIZE != 0)
    die("input size must be a multiple of the FEC block size");

  const size_t rounds = (input_size / FEC_BLOCK_SIZE + rs_n - 1) / rs_n;
  const size_t raw_size = rounds * (size_t)roots * FEC_BLOCK_SIZE;
  unsigned char *fec = calloc(raw_size, 1);
  if (!fec) die("out of memory");
  unsigned char *codeword = malloc(rs_n);
  if (!codeword) die("out of memory");

  for (size_t column = 0; column < rounds * FEC_BLOCK_SIZE; column++) {
    size_t cw_len = 0;
    for (size_t row = 0; row < rs_n; row++) {
      size_t off = column + row * rounds * FEC_BLOCK_SIZE;
      if (off < input_size)
        codeword[cw_len++] = data[off];
    }
    while (cw_len < rs_n)
      codeword[cw_len++] = 0;
    encode_rs_char(rs, codeword, fec + column * (size_t)roots);
  }

  /* 4 KiB libfec footer (struct fec_header, little-endian, packed). */
  unsigned char footer[FEC_BLOCK_SIZE];
  memset(footer, 0, sizeof(footer));
  uint32_t magic = FEC_MAGIC;
  memcpy(footer + 0, &magic, 4);                    /* magic */
  uint32_t version = 0;
  memcpy(footer + 4, &version, 4);                  /* version */
  uint32_t block = FEC_BLOCK_SIZE;
  memcpy(footer + 8, &block, 4);                    /* size */
  uint32_t nroots = (uint32_t)roots;
  memcpy(footer + 12, &nroots, 4);                  /* roots */
  uint32_t raw = (uint32_t)raw_size;
  memcpy(footer + 16, &raw, 4);                     /* fec_size */
  uint64_t inp = input_size;
  memcpy(footer + 20, &inp, 8);                     /* inx_size */
  unsigned char digest[32];
  SHA256(fec, raw_size, digest);
  memcpy(footer + 28, digest, 32);                  /* hash */

  FILE *out = fopen(output, "wb");
  if (!out) die("cannot open output");
  if (fwrite(fec, 1, raw_size, out) != raw_size ||
      fwrite(footer, 1, sizeof(footer), out) != sizeof(footer))
    die("short write on output");
  fclose(out);

  free(codeword);
  free(fec);
  free(data);
  free_rs_char(rs);
  return 0;
}
