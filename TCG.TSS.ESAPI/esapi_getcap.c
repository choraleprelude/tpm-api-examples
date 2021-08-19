/*
Based on example from: https://tpm2-software.github.io/tpm2-tss/getting-started/2019/02/05/Getting-Started.html
    https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_getcap.c

Get capability

*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

/*
 * Iterate over an array of TPML_HANDLEs and dump out the handle
 * values.
 */
static void dump_handles(TPM2_HANDLE handles[], UINT32 count) {
    UINT32 i;

    for (i = 0; i < count; ++i)
        printf("- 0x%X\n", handles[i]);
}

static bool dump_tpm_capability(TPM2_CAP capability, UINT32 property, TPMU_CAPABILITIES *capabilities) {

    bool result = true;
    switch (capability) {
    // case TPM2_CAP_ALGS:
    //     dump_algorithms(capabilities->algorithms.algProperties,
    //             capabilities->algorithms.count);
    //     break;
    // case TPM2_CAP_COMMANDS:
    //     result = dump_command_attr_array(
    //             capabilities->command.commandAttributes,
    //             capabilities->command.count);
    //     break;
    // case TPM2_CAP_TPM_PROPERTIES:
    //     switch (property) {
    //     case TPM2_PT_FIXED:
    //         dump_tpm_properties_fixed(capabilities->tpmProperties.tpmProperty,
    //                 capabilities->tpmProperties.count);
    //         break;
    //     case TPM2_PT_VAR:
    //         dump_tpm_properties_var(capabilities->tpmProperties.tpmProperty,
    //                 capabilities->tpmProperties.count);
    //         break;
    //     default:
    //         return false;
    //     }
    //     break;
    // case TPM2_CAP_ECC_CURVES:
    //     dump_ecc_curves(capabilities->eccCurves.eccCurves,
    //             capabilities->eccCurves.count);
    //     break;
    case TPM2_CAP_HANDLES:
        switch (property & TPM2_HR_RANGE_MASK) {
        case TPM2_HR_TRANSIENT:
        case TPM2_HR_PERSISTENT:
        case TPM2_HR_PERMANENT:
        case TPM2_HR_PCR:
        case TPM2_HR_NV_INDEX:
        case TPM2_HT_LOADED_SESSION << TPM2_HR_SHIFT:
        case TPM2_HT_SAVED_SESSION << TPM2_HR_SHIFT:
            dump_handles(capabilities->handles.handle,
                    capabilities->handles.count);
            break;
        default:
            return false;
        }
        break;
    // case TPM2_CAP_PCRS:
    //     pcr_print_pcr_selections(&capabilities->assignedPCR);
    //     break;
    default:
        return false;
    }
    return result;
}

int main(int argc, char *argv[]) {

    TSS2_RC r;

    if (argc < 3) {
        printf("Usage: esapi_getcap capability tcti (e.g.: esapi_getcap handles-persistent mssim)\n");
        return 1;
    }

    // int rand_size;
    // sscanf (argv[1],"%d",&rand_size);

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

    /* Get cap data */
    TPM2_CAP                       capability;
    UINT32                         property;
    UINT32                         propertyCount;
    TPMS_CAPABILITY_DATA           *capabilityData;
    TPMI_YES_NO                    moreData;

    if (strcmp(argv[1], "handles-persistent") == 0) {
        capability = TPM2_CAP_HANDLES;
        property = TPM2_PERSISTENT_FIRST;
        propertyCount = TPM2_MAX_CAP_HANDLES;
    } else {
		fprintf(stderr, "Error: Unsupported capability\n");
        exit(1);        
    }

    r = Esys_GetCapability(ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           capability, property, propertyCount,
                           &moreData, &capabilityData);

    if (r != TSS2_RC_SUCCESS){
		fprintf(stderr, "Error: Esys_GetCapability: 0x%x\n", r);
        exit(1);
    }

    bool result = dump_tpm_capability(capability, property, &capabilityData->data);

    // printf("\n");
    // for (int i = 0; i < random_bytes->size; i++) {
    //     printf("0x%x ", random_bytes->buffer[i]);
    // }
    // printf("\n");
    exit(0);
}

