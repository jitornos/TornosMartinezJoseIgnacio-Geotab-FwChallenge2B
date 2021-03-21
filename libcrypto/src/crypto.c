#include <stdint.h>
#include <string.h>
#include "crypto.h"

/* Get libcrypto version.
 *
 * returns: libcrypto version string
 */
char *getCryptoVersion()
{
    return (char*)VERSION;
}

/* Encrypt input message with provided key
 * Algorithm:
 * i = 0
 * k = key
 * FOR each input_byte in input
 *     k[i] = (k[i] + i) modulo 256
 *     output_byte = input_byte xor k[i]
 *     i = (i + 1) modulo length(key)
 * ENDFOR
 *
 * key: Key array
 * keyLength: Length of key array
 * input: Input message array to encrypt
 * inputLength: Lenght of input message array
 * output: Encrypted output message array
 *
 * returns: OK/ERROR
*/
CRYPTO_RES_t encryptMessage(uint8_t *key, uint32_t keyLength, uint8_t *input, uint32_t inputLength, uint8_t * output)
{
    uint32_t p;
    uint32_t i = 0;
    uint8_t k[MAX_KEY_LENGTH] = {0};
    
    if (keyLength > MAX_KEY_LENGTH) 
    {
        return CRYPTO_ERROR;
    }
    memcpy(k, key, keyLength);
    for (p = 0; p < inputLength; p ++)
    {
        k[i] = (k[i] + i) % MAX_KEY_LENGTH;
	output[p] = input[p] ^ k[i];
	i = (i +1) % keyLength;
    }	
    return CRYPTO_OK;
}
