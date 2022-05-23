/*
Based on example from: 
    hhttps://github.com/tpm2-software/tpm2-tss/blob/master/test/integration/esys-nv-certify.int.c
     and referencing esapi_nvread_persistent_key.c, esapi_import_persist_openssl_key.c

*/

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// #include <openssl/bio.h>
// #include <openssl/pem.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

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

/* do not port to TSS below here */
typedef enum tool_rc tool_rc;
enum tool_rc {
    /* do not reorder or change, part of returned codes to exit */
    /* maps to common/returns.md */
    tool_rc_success = 0,
    tool_rc_general_error,
    tool_rc_option_error,
    tool_rc_auth_error,
    tool_rc_tcti_error,
    tool_rc_unsupported
};

// tool_rc tpm2_getcap(ESYS_CONTEXT *esys_context, TPM2_CAP capability,
//         UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data,
//         TPMS_CAPABILITY_DATA **capability_data) {

//     TSS2_RC rval = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
//             capability, property, property_count, more_data, capability_data);
//     if (rval != TSS2_RC_SUCCESS) {
//         printf("Esys_GetCapability error: (0x%X) - %s\n", rval, Tss2_RC_Decode(rval));

//         return 1;
//     }

//     return tool_rc_success;
// }

// #define NV_DEFAULT_BUFFER_SIZE 512

// static inline tool_rc tpm2_util_nv_max_buffer_size(ESYS_CONTEXT *ectx,
//         UINT32 *size) {

//     /* Get the maximum read block size */
//     TPMS_CAPABILITY_DATA *cap_data;
//     TPMI_YES_NO more_data;
//     tool_rc rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES,
//             TPM2_PT_NV_BUFFER_MAX, 1, &more_data, &cap_data);
//     if (rc != tool_rc_success) {
//         return rc;
//     }

//     if ( cap_data->data.tpmProperties.tpmProperty[0].property == TPM2_PT_NV_BUFFER_MAX ) {
//         *size = cap_data->data.tpmProperties.tpmProperty[0].value;
//     } else {
//         /* TPM2_PT_NV_BUFFER_MAX is not part of the module spec <= 0.98*/
//         *size = NV_DEFAULT_BUFFER_SIZE;
//     }

//     free(cap_data);

//     return rc;
// }

// #define BAIL_ON_NULL(param, x) \
//     do { \
//         if (!x) { \
//             printf(param" must be specified \n"); \
//             return false; \
//         } \
//     } while(0)

// static bool writex(FILE *f, UINT8 *data, size_t size) {

//     size_t wrote = 0;
//     size_t index = 0;
//     do {
//         wrote = fwrite(&data[index], 1, size, f);
//         if (wrote != size) {
//             if (errno != EINTR) {
//                 return false;
//             }
//             /* continue on EINTR */
//         }
//         size -= wrote;
//         index += wrote;
//     } while (size > 0);

//     return true;
// }

// bool files_write_bytes(FILE *out, uint8_t bytes[], size_t len) {

//     BAIL_ON_NULL("FILE", out);
//     BAIL_ON_NULL("bytes", bytes);
//     return writex(out, bytes, len);
// }

// bool files_save_bytes_to_file(const char *path, UINT8 *buf, UINT16 size) {

//     if (!buf) {
//         return false;
//     }

//     if (!path) {
//         return true;
//     }

//     FILE *fp = path ? fopen(path, "wb+") : stdout;
//     if (!fp) {
//         printf("Could not open file %s\n", path);
//         return false;
//     }

//     bool result = files_write_bytes(fp, buf, size);
//     if (!result) {
//         printf("Could not write data to file %s\n", path);
//     }

//     if (fp != stdout) {
//         fclose(fp);
//     }

//     return result;
// }

int main(int argc, char *argv[]) {

    TSS2_RC rv;

    if (argc < 8) {
        printf("Usage: esapi_nvwrite_persistent hierarchy hierarchyauth NVindex NVauth input_path NVsize tcti (e.g.: esapi_nvwrite_persistent o ownerauth 10 nvauthpassword inputfile.txt 256 mssim)\n");
        return 1;
    }

    // int rand_size;
    // sscanf (argv[1],"%d",&rand_size);

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

    // set hierarchy auth
    TPM2B_AUTH h_authValue = {
        .size = 0,
        .buffer = {0}
    };    

    if (strcmp(argv[2], "NULL") != 0) {
        char *h_auth = argv[2];

        h_authValue.size = strlen(h_auth);
        for (int i = 0; i < h_authValue.size; i++) {
            h_authValue.buffer[i] = h_auth[i];
        }
    }

    // Configure hierarchy input
    ESYS_TR hierarchy_choice;

    if (strcmp(argv[1], "o") == 0) {
        hierarchy_choice = ESYS_TR_RH_OWNER;            
        rv = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &h_authValue);
    } else if (strcmp(argv[1], "p") == 0) {
        hierarchy_choice = ESYS_TR_RH_PLATFORM;
        rv = Esys_TR_SetAuth(ectx, ESYS_TR_RH_PLATFORM, &h_authValue);
    } else {
		fprintf(stderr, "Wrong hierarchy parameter (main): %s\n", argv[1]);
		exit(1);
    }

    if (rv != TSS2_RC_SUCCESS) {
        printf("TR_SetAuth error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		return 1;
	}

/*
    // prepare persistent handle
	TPMI_DH_PERSISTENT persist_handle;	
    bool result = tpm2_util_string_to_uint32(argv[3], &persist_handle);
    if (!result) {
        fprintf(stderr, "Could not convert persistent handle to a number");
        exit(1);
    } else {
		printf("persist_handle: %#x\n", persist_handle);
	}
*/
    // set NV auth
    TPM2B_AUTH h_NVAuthValue = {
        .size = 0,
        .buffer = {0}
    };    

    if (strcmp(argv[4], "NULL") != 0) {
        char *h_nvauth = argv[4];

        h_NVAuthValue.size = strlen(h_nvauth);
        for (int i = 0; i < h_NVAuthValue.size; i++) {
            h_NVAuthValue.buffer[i] = h_nvauth[i];
        }
    }

    // Prepare NV index attribute info
    int nvsize = atoi(argv[6]);
    int nvindex = atoi(argv[3]);

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST + nvindex,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_OWNERREAD |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_AUTHREAD
                ),
            .authPolicy = {
                 .size = 0,
                 .buffer = {}
             },
            .dataSize = nvsize,
        }
    };

    // Define NV index
    ESYS_TR nvHandle = ESYS_TR_NONE;
    rv = Esys_NV_DefineSpace(ectx,
                            hierarchy_choice,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &h_NVAuthValue,
                            &publicInfo,
                            &nvHandle);

    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_NV_DefineSpace error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		return 1;
	}

/*     
    // prepare NV handle
    ESYS_TR NVHandle = ESYS_TR_NONE;    

    rv = Esys_TR_FromTPMPublic(ectx, persist_handle,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &NVHandle);    
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_TR_FromTPMPublic error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		return 1;
	}

    // set NV object auth
    TPM2B_AUTH nv_authValue = {
        .size = 0,
        .buffer = {0}
    };    

    if (strcmp(argv[2], "NULL") != 0) {
        char *nv_auth = argv[2];

        nv_authValue.size = strlen(nv_auth);
        for (int i = 0; i < nv_authValue.size; i++) {
            nv_authValue.buffer[i] = nv_auth[i];
        }
    }

    rv = Esys_TR_SetAuth(ectx, NVHandle, &nv_authValue);
    if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "TR_SetAuth error: 0x%x\n", rv);
		return 1;
	} 
*/

/* 
    // Read NV public data
    TPM2B_NV_PUBLIC *nv_public = NULL;
    // assume NV name = NULL;
    rv = Esys_NV_ReadPublic(ectx, NVHandle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nv_public, NULL);
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_NV_ReadPublic error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		return 1;
	}

    UINT16 data_size = nv_public->nvPublic.dataSize;
    free(nv_public);

    // if size is 0, assume the whole object 
    UINT16 size;
    if (size == 0) {
        size = data_size;
    }

    printf ("datasize = %d \n", size);

    UINT32 max_data_size = NV_DEFAULT_BUFFER_SIZE;

    // read NV data
    UINT8* data_buffer;    
    UINT16 bytes_written;

    data_buffer = malloc(data_size);
    if (!data_buffer) {
        printf("oom malloc \n");
        return 1;
    }

    UINT16 offset = 0;
    UINT16 data_offset = 0;

    while (size > 0) {

        UINT16 bytes_to_read = size > max_data_size ? max_data_size : size;

        TPM2B_MAX_NV_BUFFER *nv_data;

        rc = Esys_NV_Read(ectx, NVHandle, NVHandle, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, bytes_to_read, offset, &nv_data);
        if (rc != tool_rc_success) {
            printf("Esys_NV_Read error: (0x%X) - %s\n", rc, Tss2_RC_Decode(rc));
            return 1;
        }

        size -= nv_data->size;
        offset += nv_data->size;

        memcpy(data_buffer + data_offset, nv_data->buffer, nv_data->size);
        data_offset += nv_data->size;

        free(nv_data);
    }

    bytes_written = data_offset;

    // Write to output file
    if (!files_save_bytes_to_file(argv[3], data_buffer,
            bytes_written)) {
        printf("Failed to save to file \n");
        return 1;
    }

    if (data_buffer != NULL) {
        free(data_buffer);
        data_buffer = NULL;
    }     
*/

    exit(0);
}
