#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include "crypto.h"
#include "fw2b.h"

/* Program options 
 */
static const char* const pcShortOptions = "hvk:f:o:";
static const struct option stLongOptions[] =
{
    {"help"                        , 0, 0, 'h'},
    {"version"                     , 0, 0, 'v'},
    {"key"                         , 1, 0, 'k'},
    {"file"                        , 1, 0, 'f'},
    {"output"                      , 1, 0, 'o'},
    {"input"                       , 0, 0, 0},
    {0, 0, 0, 0}
};

/* Show program help
 */
static void help()
{
    printf("help:\n");
    printf("[-h] [-v] -k <key> | -f <key_file> [-o <output_file>] [<input_file>]\n\n");
    printf("--help/-h                    Show this help\n");
    printf("--version/-v                 Show libcrypto version\n");
    printf("--key/-k <key>               Algorithm key for encryption\n");
    printf("--keyFile/-f <keyFile>       File with algorithm key for encryption\n");
    printf("--output/-o <output file>    Encrypted output file (if not configured stdout will be used)\n");
    printf("<input file>                 Input file to encrypt\n");
    printf("\n");
}

/* Show crypto library version
 */
static void version()
{
    printf("%s\n", getCryptoVersion());
}

/* Check key if provided or get and chech key if file
 *
 * key: Key array
 * keyFileD: File descriptor for key
 * keySize: Size of key array
 *
 * returns: OK/ERROR
 */
static FW2B_RES_t keyProcessing(uint8_t *key, FILE *keyFileD, uint32_t *keySize)
{
    uint32_t size;

    if ((*keySize == 0) && (!keyFileD))
    {
        printf("ERROR: key needs to be provided\n");
	return FW2B_RES_WRONG_KEY;
    }
    if ((*keySize) && (keyFileD))
    {
        printf("ERROR: only one key can be defined\n");
	return FW2B_RES_WRONG_KEY;
    }

    /* Read key if file is provided */
    if (keyFileD)
    {
        fseek(keyFileD, 0L, SEEK_END);
        size = ftell(keyFileD);
	if (size > MAX_KEY_LENGTH)
        {
            printf("ERROR: key is too long\n");
	    return FW2B_RES_WRONG_KEY;
        }
        fseek(keyFileD, 0L, SEEK_SET);
        *keySize = fread(key, sizeof(uint8_t), size, keyFileD);
        if (*keySize != size)
        {
            printf("ERROR: key can not be read\n");
	    return FW2B_RES_WRONG_KEY;
        }
    }

    /* Check key */
    if (*keySize == 0)
    {
        printf("ERROR: wrong key\n");
	return FW2B_RES_WRONG_KEY;
    }

    return FW2B_RES_OK;
}

/* Get input, if file is not provided, read from stdin
 *
 * input: Input array
 * inputFileD: File descriptor for input
 * inputSize: Size of input array
 *
 * returns: OK/ERROR
 */
static FW2B_RES_t inputProcessing(uint8_t **input, FILE *inputFileD, uint32_t *inputSize)
{
    struct stat st = {0};
    uint32_t reservedSize;

    /* Check if file is provided */
    if (inputFileD)
    {
        fseek(inputFileD, 0L, SEEK_END);
        reservedSize = ftell(inputFileD);
        fseek(inputFileD, 0L, SEEK_SET);
    }
    else
    {
        /* Check if input is provided through stdin */
        if (fstat(STDIN_FILENO, &st) < 0)
        {
            printf("ERROR: %m\n");
	    return FW2B_RES_WRONG_INPUT_PIPE;
        }
        if ((st.st_mode & S_IFMT) != S_IFIFO)
        {
            printf("ERROR: input is not a pipe\n");
	    return FW2B_RES_WRONG_INPUT_PIPE;
        }
        inputFileD = stdin;
        reservedSize = MAX_PIPE_SIZE;
    }

    /* Allocate memory to read input */
    *input = malloc(reservedSize);
    if (! *input)
    {
        printf("ERROR: not enough memory for input\n");
	return FW2B_RES_OUT_OF_MEMORY;
    }

    /* Read input */
    *inputSize = fread(*input, sizeof(uint8_t), reservedSize, inputFileD);
    
    /* Check input */
    if (*inputSize == 0)
    {
        printf("ERROR: input is empty\n");
	return FW2B_RES_WRONG_INPUT;
    }
    if ((inputFileD != stdin) && (*inputSize != reservedSize))
    {
        printf("ERROR: input can not be read\n");
	return FW2B_RES_WRONG_INPUT;
    }

    return FW2B_RES_OK;
}

/* Apply the cryptography algorithm to the input to get the output
 *
 * key: Key array
 * keySize: Size of key array
 * input: Input array
 * inputSize: Size of input array
 * output: Output array
 * outputSize: Size of output array
 *
 * returns: OK/ERROR
 */
static FW2B_RES_t cryptographyAlgorithm(uint8_t *key, uint32_t keySize, uint8_t *input, uint32_t inputSize, uint8_t **output, uint32_t *outputSize)
{
    *outputSize = inputSize;
    *output = malloc(*outputSize);
    if (!output)
    {
        printf("ERROR: not enough memory for output\n");
	free(input);
	return FW2B_RES_OUT_OF_MEMORY;
    }

    /* Apply cryptography algorithm */
    if (encryptMessage(key, keySize, input, inputSize, *output) != CRYPTO_OK)
    {
        printf("ERROR: cryptography algorithm error\n");
        return FW2B_RES_CRYPTO_ERROR;
    }

    return FW2B_RES_OK;
}

/* If file is provided, save output, otherwise use stdout
 *
 * output: Output array
 * outputFileD: File descriptor for output
 * outputSize: Size of output array
 *
 * returns: OK/ERROR
 */
static FW2B_RES_t outputProcessing(uint8_t *output, FILE *outputFileD, uint32_t outputSize)
{
    uint32_t writtenSize;

    /* Check if file is provided */
    if (!outputFileD)
    {
        /* Use stdout */
        outputFileD = stdout;
    }

    /* Write output */
    writtenSize = fwrite(output, sizeof(uint8_t), outputSize, outputFileD);
    if (writtenSize != outputSize)
    {
        printf("ERROR: output can not be written\n");
	return FW2B_RES_WRONG_OUTPUT;
    }

    return FW2B_RES_OK;
}

/* Release resources
 *
 * input: Input array
 * output: Output array
 * keyFileD: File descriptor for key
 * inputFileD: File descriptor for input
 * outputFileD: File descriptor for output
 */
static void releaseResources(uint8_t *input, uint8_t *output, FILE *keyFileD, FILE *inputFileD, FILE *outputFileD)
{
    if (input)
    {
        free(input);
    }
    if (output)
    {
        free(output);
    }
    if (keyFileD)
    {
        fclose(keyFileD);
    }
    if (inputFileD)
    {
        fclose(inputFileD);
    }
    if (outputFileD)
    {
        fclose(outputFileD);
    }
}

/* Test program for encryption
 *
 * argc: Argument count
 * argv: Argument list
 *
 * returns: program exit status
 */
int main(int argc, char **argv)
{
    int32_t iOption = -1;
    char *keyFile = NULL;
    char *inputFile = NULL;
    char *outputFile = NULL;
    FILE *keyFileD  = NULL;
    FILE *inputFileD  = NULL;
    FILE *outputFileD  = NULL;
    uint8_t key[MAX_KEY_LENGTH] = {0};
    uint8_t *input = NULL;
    uint8_t *output = NULL;
    uint32_t keySize = 0;
    uint32_t inputSize = 0;
    uint32_t outputSize = 0;
    FW2B_RES_t res = FW2B_RES_OK;

    /* Get options */
    do
    {
        iOption = getopt_long(argc, argv, pcShortOptions, stLongOptions, 0);
        switch (iOption)
        {
            case 'h':
                help();
                return FW2B_RES_OK;
            case 'v':
                version();
                return FW2B_RES_OK;
	    case 'k':
		keySize = strlen(optarg); 
	        if (keySize > MAX_KEY_LENGTH)
                {
                    printf("ERROR: key is too long\n");
	            return FW2B_RES_WRONG_KEY;
                }
		strncpy((char*)key, optarg, MAX_KEY_LENGTH);
                break;
	    case 'f':
		keyFile = optarg;
                keyFileD  = fopen(keyFile, "r");
	        if (keyFileD == NULL) 
                {   
                    printf("ERROR: key file can not be opened\n");
	            return FW2B_RES_WRONG_KEY_FILE;
                }
                break;
            case 'o':
		outputFile = optarg;
                outputFileD  = fopen(outputFile, "w");
	        if (outputFileD == NULL) 
                {   
                    printf("ERROR: output file can not be opened\n");
	            return FW2B_RES_WRONG_OUTPUT_FILE;
                }
		break;
	    case -1:
                break;
            default:
                return FW2B_RES_UNKNOWN_COMMAND;
        };
    } 
    while (iOption != -1);
    if (optind < argc) 
    {
        inputFile = argv[optind++];
        inputFileD  = fopen(inputFile, "r");
	if (inputFileD == NULL) 
        {   
            printf("ERROR: input file is not found\n");
	    return FW2B_RES_WRONG_INPUT_FILE;
        }
    }

    /* Get key */
    res = keyProcessing(key, keyFileD, &keySize);

    /* Get input */
    if (res == FW2B_RES_OK)
    {
        res = inputProcessing(&input, inputFileD, &inputSize);
    }

    /* Encrypt */
    if (res == FW2B_RES_OK)
    {
        res = cryptographyAlgorithm(key, keySize, input, inputSize, &output, &outputSize);
    }

    /* Set output */
    if (res == FW2B_RES_OK)
    {
        res = outputProcessing(output, outputFileD, outputSize);
    }

    /* Release resources */
    releaseResources(input, output, keyFileD, inputFileD, outputFileD);

    return res;
}
