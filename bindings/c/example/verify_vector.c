/**
 * Example: verify spec vector 001 with dev mock key.
 *
 *   ../../build-native.sh
 *   cc -I../include -L../../../target/release -lope_ffi -Wl,-rpath,../../../target/release \
 *      verify_vector.c -o verify_vector
 *   ./verify_vector
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ope.h"

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc((size_t)n + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  fread(buf, 1, (size_t)n, f);
  buf[n] = '\0';
  fclose(f);
  return buf;
}

/* Minimal JSON extract: finds "envelope": { ... } at top level (vector file only). */
static char *extract_envelope(const char *doc) {
  const char *key = "\"envelope\"";
  const char *p = strstr(doc, key);
  if (!p) return NULL;
  p = strchr(p + strlen(key), '{');
  if (!p) return NULL;
  int depth = 0;
  const char *start = p;
  for (; *p; p++) {
    if (*p == '{') depth++;
    else if (*p == '}') {
      depth--;
      if (depth == 0) {
        size_t len = (size_t)(p - start + 1);
        char *out = malloc(len + 1);
        memcpy(out, start, len);
        out[len] = '\0';
        return out;
      }
    }
  }
  return NULL;
}

int main(void) {
  const char *path = "spec/vectors/001-valid-plaintext.json";
  char *doc = read_file(path);
  if (!doc) {
    fprintf(stderr, "read %s failed (run from repo root)\n", path);
    return 1;
  }
  char *env = extract_envelope(doc);
  free(doc);
  if (!env) {
    fprintf(stderr, "parse envelope failed\n");
    return 1;
  }
  int rc = ope_envelope_verify_dev_json(env);
  free(env);
  if (rc != OPE_OK) {
    char err[512];
    ope_last_error_message(err, sizeof(err));
    fprintf(stderr, "verify failed (%d): %s\n", rc, err);
    return 1;
  }
  printf("ok: %s verified with dev key\n", path);
  return 0;
}
