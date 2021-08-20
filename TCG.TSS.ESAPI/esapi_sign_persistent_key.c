/*
Based on example from: 
   https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_sign.c

Sign a blob with an existing persistent key

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

    // size cannot be negative at this point 
    *file_size = (unsigned long) size;
    return true;
}

bool file_read_bytes_from_file(FILE *f, UINT8 *buf, UINT16 *size,
        const char *path) {

    unsigned long file_size;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        //  get_file_size() logs errors 
        return false;
    }

    //  max is bounded on *size 
    if (file_size > *size) {
        if (path) {
            printf(
                    "File \"%s\" size is larger than buffer, got %lu expected "
                    "less than or equal to %u", path, file_size, *size);
        }
        return false;
    }

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
            // 
        }
        size -= wrote;
        index += wrote;
    } while (size > 0);

    return true;
}

bool files_read_bytes(FILE *out, UINT8 bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return (readx(out, bytes, len) == len);
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

    // clear errno before the call, should be 0 afterwards 
    errno = 0;
    unsigned long int tmp = strtoul(str, &endptr, 0);
    if (errno || tmp > UINT32_MAX) {
        return false;
    }

    if (*endptr != '\0') {
        return false;
    }

    *value = (uint32_t) tmp;
    return true;
}

int main(int argc, char *argv[]) {

    TSS2_RC rv;

    if (argc < 8) {
        printf("Usage: esapi_sign_persistent_key hierarchy keyHandle keyauth alg input_data signature_output tcti \n     (e.g.: esapi_sign_persistent_key o 0x81000005 password sha256 data.txt signature.file mssim)\n");
        return 1;
    }

    /* Prepare TCTI context */
    const char *tcti_name = argv[7];
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

    // Configure hierarchy input
    ESYS_TR hierarchy_choice;

    if (strcmp(argv[1], "o") == 0) {
        hierarchy_choice = ESYS_TR_RH_OWNER;
    } else if (strcmp(argv[1], "p") == 0) {
        hierarchy_choice = ESYS_TR_RH_PLATFORM;
    } else {
		fprintf(stderr, "Wrong hierarchy parameter: %s\n", argv[1]);
		exit(1);
    }

    // prepare persistent handle
	TPMI_DH_PERSISTENT persist_handle;	
    bool result = tpm2_util_string_to_uint32(argv[2], &persist_handle);
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

    if (strcmp(argv[3], "NULL") != 0) {
        char *k_auth = argv[3];

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

    TPMI_ALG_HASH halg;
    if (strcmp(argv[4], "sha256") == 0) {
        halg = TPM2_ALG_SHA256;
    } else {
        printf("Unsupported algorithm \"%s\"\n", argv[3]);
        return 1;
    }

    /*
     * Read input data
     */
    TPM2B_MAX_BUFFER input_data;
    input_data.size = BUFFER_SIZE(TPM2B_MAX_BUFFER, buffer);
    
    result = files_load_bytes_from_path(argv[5], input_data.buffer, &input_data.size);
    if (!result) {
		fprintf(stderr, "Input reading error\n");
		return 1;            
    }

    // Calculate digest of input data
    TPM2B_DIGEST *digest;
    TPMT_TK_HASHCHECK *validation;    
    rv = Esys_Hash(ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &input_data,
            halg, hierarchy_choice, &digest, &validation);
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_Hash error: \"%x\"\n", rv);
        return 1;
    }


/*
    // read input message and create digest for signing
    char *input_file = argv[4];
    FILE *input = input_file ? fopen(input_file, "rb") : stdin;
    if (!input) {
        printf("Could not open file \"%s\"\n", input_file);
        return 1;
    }

    TPMT_TK_HASHCHECK *temp_validation_ticket;

    rc = tpm2_hash_file(ectx, halg, TPM2_RH_OWNER, input, &digest,
            &temp_validation_ticket);
    if (input != stdin) {
        fclose(input);
    }

    if (rc != tool_rc_success) {
        printf("Could not hash input\n");
        return 1;
    } else {
        validation = *temp_validation_ticket;
    }

    free(temp_validation_ticket);     */


/*
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

    // 
    //  * Read enc data blob
    //  
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    cipher_text.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    
    result = files_load_bytes_from_path(argv[3], cipher_text.buffer, &cipher_text.size);
    if (!result) {
		fprintf(stderr, "Input reading error\n");
		return 1;            
    }

    TPM2B_PUBLIC_KEY_RSA *message = NULL;
    TPMT_RSA_DECRYPT scheme;

    // 
    // Default padding scheme: 0x15 or rsaes for TPM_ALG_RSAES
    // https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_rsadecrypt.1.md
    // https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/signschemes.md
    // 
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
*/    
    exit(0);
}

