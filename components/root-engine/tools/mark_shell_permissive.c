#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>

static unsigned char *read_file(const char *path, size_t *length) {
  FILE *file = fopen(path, "rb");
  if (!file) {
    fprintf(stderr, "open %s: %s\n", path, strerror(errno));
    return NULL;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return NULL;
  }
  long file_size = ftell(file);
  if (file_size <= 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return NULL;
  }

  unsigned char *data = malloc((size_t)file_size);
  if (!data) {
    fclose(file);
    return NULL;
  }
  if (fread(data, 1, (size_t)file_size, file) != (size_t)file_size) {
    free(data);
    fclose(file);
    return NULL;
  }
  fclose(file);
  *length = (size_t)file_size;
  return data;
}

static int write_file(const char *path, const void *data, size_t length) {
  FILE *file = fopen(path, "wb");
  if (!file) {
    fprintf(stderr, "create %s: %s\n", path, strerror(errno));
    return 0;
  }
  int ok = fwrite(data, 1, length, file) == length;
  if (fclose(file) != 0) {
    ok = 0;
  }
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s INPUT_POLICY OUTPUT_POLICY TYPE_NAME\n",
            argv[0]);
    return 2;
  }

  size_t input_length = 0;
  unsigned char *input = read_file(argv[1], &input_length);
  if (!input) {
    return 1;
  }

  sepol_policy_file_t *policy_file = NULL;
  sepol_policydb_t *policy = NULL;
  if (sepol_policy_file_create(&policy_file) != 0 ||
      sepol_policydb_create(&policy) != 0) {
    fprintf(stderr, "libsepol allocation failed\n");
    free(input);
    return 1;
  }

  sepol_policy_file_set_mem(policy_file, (char *)input, input_length);
  if (sepol_policydb_read(policy, policy_file) != 0) {
    fprintf(stderr, "failed to parse input policy\n");
    sepol_policy_file_free(policy_file);
    sepol_policydb_free(policy);
    free(input);
    return 1;
  }

  type_datum_t *type =
      (type_datum_t *)hashtab_search(policy->p.p_types.table, argv[3]);
  if (!type) {
    fprintf(stderr, "type %s not found\n", argv[3]);
    sepol_policy_file_free(policy_file);
    sepol_policydb_free(policy);
    free(input);
    return 1;
  }

  type->flags |= TYPE_FLAGS_PERMISSIVE;
  if (ebitmap_set_bit(&policy->p.permissive_map, type->s.value, 1) != 0) {
    fprintf(stderr, "failed to set permissive bit\n");
    sepol_policy_file_free(policy_file);
    sepol_policydb_free(policy);
    free(input);
    return 1;
  }

  size_t output_length = 0;
  sepol_policy_file_set_mem(policy_file, NULL, 0);
  if (sepol_policydb_write(policy, policy_file) != 0 ||
      sepol_policy_file_get_len(policy_file, &output_length) != 0 ||
      output_length == 0) {
    fprintf(stderr, "failed to size output policy\n");
    sepol_policy_file_free(policy_file);
    sepol_policydb_free(policy);
    free(input);
    return 1;
  }

  unsigned char *output = malloc(output_length);
  if (!output) {
    sepol_policy_file_free(policy_file);
    sepol_policydb_free(policy);
    free(input);
    return 1;
  }
  sepol_policy_file_set_mem(policy_file, (char *)output, output_length);
  if (sepol_policydb_write(policy, policy_file) != 0 ||
      !write_file(argv[2], output, output_length)) {
    fprintf(stderr, "failed to write output policy\n");
    free(output);
    sepol_policy_file_free(policy_file);
    sepol_policydb_free(policy);
    free(input);
    return 1;
  }

  printf("type=%s value=%u permissive_bit=%u input=%zu output=%zu\n",
         argv[3], type->s.value, type->s.value, input_length, output_length);

  free(output);
  sepol_policy_file_free(policy_file);
  sepol_policydb_free(policy);
  free(input);
  return 0;
}
