/*
Based on example from: 
   https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_rsadecrypt.c

Decrypt a blob with an existing persistent key

*/

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))

#define BAIL_ON_NULL(param, x) \
    do { \
        if (!x) { \
            printf(param" must be specified\n"); \
            return false; \
        } \
    } while(0)

static size_t readx(FILE *f, UINT8 *data, size_t size) {

    size_t bread = 0;
    do {
        bread += fread(&data[bread], 1, size-bread, f);
    } while (bread < size && !feof(f) && errno == EINTR);

    return bread;
}

bool files_get_file_size(FILE *fp, unsigned long *file_size, const char *path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            printf("Error getting current file offset for file \"%s\" error: "
                    "%s", path, strerror(errno));
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            printf("Error seeking to end of file \"%s\" error: %s", path,
                    strerror(errno));
        }
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        if (path) {
            printf("ftell on file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        if (path) {
            printf(
                    "Could not restore initial stream position for file \"%s\" "
                    "failed: %s", path, strerror(errno));
        }
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long) size;
    return true;
}

bool file_read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
        const char *path) {

    unsigned long file_size;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        /* get_file_size() logs errors */
        return false;
    }

    /* max is bounded on *size */
    if (file_size > *size) {
        if (path) {
            printf(
                    "File \"%s\" size is larger than buffer, got %lu expected "
                    "less than or equal to %u", path, file_size, *size);
        }
        return false;
    }

    /* The reported file size is not always correct, e.g. for sysfs files
       generated on the fly by the kernel when they are read, which appear as
       having size 0. Read as many bytes as we can until EOF is reached or the
       provided buffer is full. As a small sanity check, fail if the number of
       bytes read is smaller than the reported file size. */
    *size = readx(f, buf, *size);
    if (*size < file_size) {
        if (path) {
            printf("Could not read data from file \"%s\"", path);
        }
        return false;
    }

    return true;
}
   
bool files_load_bytes_from_path(const char *path, UINT8 *buf, UINT16 *size) {

    if (!buf || !size || !path) {
        return false;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("Could not open file \"%s\" error %s\n", path, strerror(errno));
        return false;
    }

    bool result = file_read_bytes_from_file(f, buf, size, path);

    fclose(f);
    return result;
}

static bool writex(FILE *f, UINT8 *data, size_t size) {

    size_t wrote = 0;
    size_t index = 0;
    do {
        wrote = fwrite(&data[index], 1, size, f);
        if (wrote != size) {
            if (errno != EINTR) {
                return false;
            }
            /* continue on EINTR */
        }
        size -= wrote;
        index += wrote;
    } while (size > 0);

    return true;
}

bool files_write_bytes(FILE *out, uint8_t bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return writex(out, bytes, len);
}

bool tpm2_util_string_to_uint32(const char *str, uint32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    unsigned long int tmp = strtoul(str, &endptr, 0);
    if (errno || tmp > UINT32_MAX) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = (uint32_t) tmp;
    return true;
}

int main(int argc, char *argv[]) {

    TSS2_RC rv;

    if (argc < 6) {
        printf("Usage: esapi_rsadecrypt_persistent_key keyHandle keyauth encrypted_input decrypted_output tcti \n     (e.g.: esapi_rsadecrypt_persistent_key 0x81000005 password encrypted.txt decrypted.txt mssim)\n");
        return 1;
    }

    /* Prepare TCTI context */
    const char *tcti_name = argv[5];
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize (tcti_name, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("\nError: Tss2_TctiLdr_Initialize, response code: 0x%" PRIx32 "\n", rc);                
        exit (1);
    }

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ectx;
    rv = Esys_Initialize(&ectx, tcti_ctx, NULL);

    if (rv != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Initializen\n");
        exit(1);
    }

    // prepare persistent handle
	TPMI_DH_PERSISTENT persist_handle;	
    bool result = tpm2_util_string_to_uint32(argv[1], &persist_handle);
    if (!result) {
        fprintf(stderr, "Could not convert persistent handle to a number\n");
        exit(1);
    } else {
		printf("persist_handle: %#x\n", persist_handle);
	}

    // prepare key handle
    ESYS_TR keyHandle = ESYS_TR_NONE;    

    rv = Esys_TR_FromTPMPublic(ectx, persist_handle,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &keyHandle);    
    if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_TR_FromTPMPublic error: 0x%x\n", rv);
		return 1;
	}

    // set key auth
    TPM2B_AUTH k_authValue = {
        .size = 0,
        .buffer = {0}
    };    

    if (strcmp(argv[2], "NULL") != 0) {
        char *k_auth = argv[2];

        k_authValue.size = strlen(k_auth);
        for (int i = 0; i < k_authValue.size; i++) {
            k_authValue.buffer[i] = k_auth[i];
        }
    }

    rv = Esys_TR_SetAuth(ectx, keyHandle, &k_authValue);
    if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "TR_SetAuth error: 0x%x\n", rv);
		return 1;
	}

    // verify key algorithm
    TPM2B_PUBLIC *key_public_info = 0;
    rv = Esys_ReadPublic(ectx, keyHandle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &key_public_info, NULL, NULL);
    if (rv != TPM2_RC_SUCCESS) {
		fprintf(stderr, "Esys_ReadPublic error: 0x%x\n", rv);
		return 1;
    }    

    if (key_public_info->publicArea.type != TPM2_ALG_RSA) {
		fprintf(stderr, "Unsupported key type for RSA decryption\n");
		return 1;        
    }    

    /*
     * Read enc data blob
     */
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    cipher_text.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    
    result = files_load_bytes_from_path(argv[3], cipher_text.buffer, &cipher_text.size);
    if (!result) {
		fprintf(stderr, "Input reading error\n");
		return 1;            
    }

    TPM2B_PUBLIC_KEY_RSA *message = NULL;
    TPMT_RSA_DECRYPT scheme;

    /*
    Default padding scheme: 0x15 or rsaes for TPM_ALG_RSAES
    https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_rsadecrypt.1.md
    https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/signschemes.md
    */    
    scheme.scheme = 0x15;

    rv = Esys_RSA_Decrypt(ectx, keyHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &cipher_text,
            &scheme, NULL, &message);
    if (rv != TPM2_RC_SUCCESS) {
		fprintf(stderr, "Esys_RSA_Decrypt error: 0x%x\n", rv);
		return 1;
    }

    bool ret = false;
    char *decrypted_output_path = argv[4];
    FILE *f =
            decrypted_output_path ? fopen(decrypted_output_path, "wb+") : stdout;
    if (!f) {
		fprintf(stderr, "Cannot open output file\n");
		return 1;
    }

    printf ("Decrypted message size:%d\n", message->size);

    ret = files_write_bytes(f, message->buffer, message->size);
    if (f != stdout) {
        fclose(f);
    }

    free(message);
    exit(0);
}

