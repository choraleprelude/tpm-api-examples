/*
Based on example from: https://tpm2-software.github.io/tpm2-tss/getting-started/2019/02/05/Getting-Started.html
Added TCTI controls
*/

#include <stdlib.h>
#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

int main(int argc, char *argv[]) {

    TSS2_RC r;

    if (argc < 3) {
        printf("Usage: esapi_getrandom size tcti (e.g.: esapi_getrandom 8 mssim)\n");
        return 1;
    }

    int rand_size;
    sscanf (argv[1],"%d",&rand_size);

    /* Prepare TCTI context */
    const char *tcti_name = argv[2];
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize (tcti_name, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("\nError: Tss2_TctiLdr_Initialize, response code: 0x%" PRIx32 "\n", rc);                
        exit (1);
    }

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ctx;
    r = Esys_Initialize(&ctx, tcti_ctx, NULL);

        if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Initializen\n");
        exit(1);
    }

    /* Get random data */
    TPM2B_DIGEST *random_bytes;
    r = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, rand_size,
                       &random_bytes);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_GetRandom\n");
        exit(1);
    }

    printf("\n");
    for (int i = 0; i < random_bytes->size; i++) {
        printf("0x%x ", random_bytes->buffer[i]);
    }
    printf("\n");
    exit(0);
}

