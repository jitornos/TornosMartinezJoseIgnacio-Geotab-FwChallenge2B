#ifndef __FW2B_H__
#define __FW2B_H__

#define MAX_PIPE_SIZE 65536

/* Error codes
 */
typedef enum
{
    FW2B_RES_UNKNOWN_COMMAND = -1,
    FW2B_RES_OK,
    FW2B_RES_WRONG_KEY,
    FW2B_RES_WRONG_KEY_FILE,
    FW2B_RES_WRONG_INPUT,
    FW2B_RES_WRONG_INPUT_FILE,
    FW2B_RES_WRONG_INPUT_PIPE,
    FW2B_RES_WRONG_OUTPUT,
    FW2B_RES_WRONG_OUTPUT_FILE,
    FW2B_RES_OUT_OF_MEMORY,
    FW2B_RES_CRYPTO_ERROR,
} FW2B_RES_t;

#endif /*__FW2B_H__*/
