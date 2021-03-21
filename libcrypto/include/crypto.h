#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#define MAX_KEY_LENGTH 256

/* Error codes
 *  */
typedef enum
{
    CRYPTO_ERROR = -1,
    CRYPTO_OK,
} CRYPTO_RES_t;

/* Get libcrypto version.
 *
 * returns: libcrypto version string
 */
char *getCryptoVersion();

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
CRYPTO_RES_t encryptMessage(uint8_t *key, uint32_t keyLenght, uint8_t *input, uint32_t inputLength, uint8_t * output);

#endif /*__CRYPTO_H__*/
