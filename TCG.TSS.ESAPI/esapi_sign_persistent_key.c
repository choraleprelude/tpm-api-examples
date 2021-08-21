/*
Based on example from: 
   https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_sign.c

Sign a blob with an existing persistent key

1. Create hash digest from input message
2. Sign digest with existing persistent key
3. Output signature

*/

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_mu.h>

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))

#define BAIL_ON_NULL(param, x) \
    do { \
        if (!x) { \
            printf(param" must be specified\n"); \
            return false; \
        } \
    } while(0)

typedef enum tpm2_convert_sig_fmt tpm2_convert_sig_fmt;
enum tpm2_convert_sig_fmt {
    signature_format_tss,
    signature_format_plain,
    signature_format_err
};

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

UINT8 *tpm2_convert_sig(UINT16 *size, TPMT_SIGNATURE *signature) {

    UINT8 *buffer = NULL;
    *size = 0;

    switch (signature->sigAlg) {
    case TPM2_ALG_RSASSA:
        *size = signature->signature.rsassa.sig.size;
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, signature->signature.rsassa.sig.buffer, *size);
        break;
    case TPM2_ALG_RSAPSS:
        *size = signature->signature.rsapss.sig.size;
        buffer = malloc(*size);
        if (!buffer) {
            goto nomem;
        }
        memcpy(buffer, signature->signature.rsapss.sig.buffer, *size);
        break;
    // case TPM2_ALG_HMAC: {
    //     TPMU_HA *hmac_sig = &(signature->signature.hmac.digest);
    //     *size = tpm2_alg_util_get_hash_size(signature->signature.hmac.hashAlg);
    //     if (*size == 0) {
    //         LOG_ERR("Hash algorithm %d has 0 size",
    //                 signature->signature.hmac.hashAlg);
    //         goto nomem;
    //     }
    //     buffer = malloc(*size);
    //     if (!buffer) {
    //         goto nomem;
    //     }
    //     memcpy(buffer, hmac_sig, *size);
    //     break;
    //}
    // case TPM2_ALG_ECDSA: {
    //     return extract_ecdsa(&signature->signature.ecdsa, size);
    // }
    default:
        printf("%s: unknown signature scheme: 0x%x", __func__,
                signature->sigAlg);
        return NULL;
    }

    return buffer;
nomem:
    printf("%s: couldn't allocate memory", __func__);
    return NULL;
}

bool output_enabled = true;

bool files_save_bytes_to_file(const char *path, UINT8 *buf, UINT16 size) {

    if (!buf) {
        return false;
    }

    if (!path && !output_enabled) {
        return true;
    }

    FILE *fp = path ? fopen(path, "wb+") : stdout;
    if (!fp) {
        printf("Could not open file \"%s\", error: %s", path, strerror(errno));
        return false;
    }

    bool result = files_write_bytes(fp, buf, size);
    if (!result) {
        printf("Could not write data to file \"%s\"", path ? path : "<stdout>");
    }

    if (fp != stdout) {
        fclose(fp);
    }

    return result;
}

bool files_save_signature(TPMT_SIGNATURE *signature, const char *path)
{
    size_t offset = 0;
    UINT8 buffer[sizeof(*signature)];
    TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, buffer, sizeof(buffer), &offset);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("Error serializing signature structure: 0x%x", rc);
        return false;
    }
    return files_save_bytes_to_file(path, buffer, offset);
}

bool tpm2_convert_sig_save(TPMT_SIGNATURE *signature,
        tpm2_convert_sig_fmt format, const char *path) {

    switch (format) {
    case signature_format_tss:
        return files_save_signature(signature, path);        
    case signature_format_plain: {
        UINT8 *buffer;
        UINT16 size;

        buffer = tpm2_convert_sig(&size, signature);
        if (buffer == NULL) {
            return false;
        }

        bool ret = files_save_bytes_to_file(path, buffer, size);
        free(buffer);
        return ret;
    }
    default:
        printf("Unsupported signature output format.");
        return false;
    }
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

    if (argc < 9) {
        printf("Usage: esapi_sign_persistent_key hierarchy keyHandle keyauth alg input_data signature_output sig_format tcti \n     (e.g.: esapi_sign_persistent_key o 0x81000005 password sha256 data.txt signature.file plain mssim)\n");
        return 1;
    }

    /* Prepare TCTI context */
    const char *tcti_name = argv[8];
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

    // Read input data
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

    // Need to set signature scheme since the signing key does not have a scheme in these sample code (hard-coded!)
    // Default for RSA shall be: TPM2_ALG_RSASSA
    //   references: https://github.com/tpm2-software/tpm2-tools/blob/master/lib/tpm2_alg_util.c
    TPMT_SIG_SCHEME in_scheme = {
                      .scheme = TPM2_ALG_RSASSA,
                      .details = {
                          .rsapss = { .hashAlg = TPM2_ALG_SHA256 }
                      }
    };

    // Sign the digest
    TPMT_SIGNATURE *signature;
    rv = Esys_Sign(ectx, keyHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, digest,
            &in_scheme, validation, &signature);
    if (rv != TPM2_RC_SUCCESS) {
        printf("Esys_Sign error: \"%x\"\n", rv);
        return 1;
    }

    // Set signature format, see: https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/signature.md
    //    - plain for openssl compatibility
    //    - tss for TPM use
    tpm2_convert_sig_fmt sig_format;

    if (strcmp(argv[7], "plain") == 0) {
        sig_format = signature_format_plain;
    } else if (strcmp(argv[7], "tss") == 0) {
        sig_format = signature_format_tss;
    } else {
        printf("Unsupported signature format: \"%s\"\n", argv[7]);
        return 1;        
    }

    // output signature
    char *signature_output_path = argv[6];
    result = tpm2_convert_sig_save(signature, sig_format, signature_output_path);
    if (!result) {
        printf("Signature save error\n");
        return 1;
    }

    exit(0);
}

