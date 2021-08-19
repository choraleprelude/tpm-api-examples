/*
Based on example from: https://tpm2-software.github.io/tpm2-tss/getting-started/2019/02/05/Getting-Started.html
     and referencing esapi_create_persist_key.c

Remove persistent handle 
1. First get persistent handle with Esys_TR_FromTPMPublic
2. Call evictcontrol to delete persistent handle 

*/

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

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

    if (argc < 5) {
        printf("Usage: esapi_delete_persistent_key hierarchy hierarchyauth keyHandle tcti (e.g.: esapi_delete_persistent_key o ownerauth 0x81000005 mssim)\n");
        return 1;
    }

    // int rand_size;
    // sscanf (argv[1],"%d",&rand_size);

    /* Prepare TCTI context */
    const char *tcti_name = argv[4];
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
        rv = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &h_authValue);
        hierarchy_choice = ESYS_TR_RH_OWNER;        
    } else if (strcmp(argv[1], "p") == 0) {
        rv = Esys_TR_SetAuth(ectx, ESYS_TR_RH_PLATFORM, &h_authValue);
        hierarchy_choice = ESYS_TR_RH_PLATFORM;        
    } else {
		fprintf(stderr, "Wrong hierarchy parameter (main): %s\n", argv[1]);
		exit(1);
    }

    if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "TR_SetAuth error: 0x%x\n", rv);
		return 1;
	}

    // prepare persistent handle
	TPMI_DH_PERSISTENT persist_handle;	
    bool result = tpm2_util_string_to_uint32(argv[3], &persist_handle);
    if (!result) {
        fprintf(stderr, "Could not convert persistent handle to a number");
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

    // remove persistent handle
	ESYS_TR out_tr;
    rv = Esys_EvictControl (ectx,
            hierarchy_choice,
            keyHandle,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,    
			persist_handle,
			&out_tr);
    if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Error: Esys_EvictControl: 0x%x\n", rv);
		exit(1);
	}    

    exit(0);
}

