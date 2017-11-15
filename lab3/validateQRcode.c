#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include "lib/sha1.h"

#define BLOCK_LEN 64
#define KEY_LEN 20
#define IPAD 0x36
#define OPAD 0x5c

uint8_t hex_char_to_byte(char c) {
	return (c <= '9') ? (uint8_t)(c - '0') : (uint8_t)(c - 'A' + 10);
}

uint8_t* hex_str_to_bytes(char* input) {
	int i = 0;
	const int len = KEY_LEN >> 1;
	uint8_t* hex = malloc(len);
	uint8_t upper, lower; // a hex need 4 bits
	while (i < len) {
		upper = hex_char_to_byte(input[i << 1]);
		lower = hex_char_to_byte(input[(i << 1) + 1]);
		hex[i] = (upper << 4) | lower;
		++i;
	}
	return hex;
}

// based on https://tools.ietf.org/pdf/rfc2104.pdf page 9
uint8_t* HMAC_SHA_1(uint8_t* text, int text_len, uint8_t* key, int key_len) {
	uint8_t k_ipad[BLOCK_LEN + 1] = {0};
	uint8_t k_opad[BLOCK_LEN + 1] = {0};
	bcopy(key, k_ipad, key_len);
	bcopy(key, k_opad, key_len);

	int i = 0;
	for (i = 0; i < BLOCK_LEN; ++i) {
		k_ipad[i] ^= IPAD;
		k_opad[i] ^= OPAD;
	}

	SHA1_INFO ctx;
	uint8_t* digest = malloc(SHA1_DIGEST_LENGTH);
	bzero(digest, SHA1_DIGEST_LENGTH);

	// perform inner SHA1
	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, BLOCK_LEN);
	sha1_update(&ctx, text, text_len);
	sha1_final(&ctx, digest);

	// perform outer SHA1
	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, BLOCK_LEN);
	sha1_update(&ctx, digest, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, digest);

	return digest;
}

/**
 * based on https://tools.ietf.org/pdf/rfc4226.pdf page 30
 */
int computeOTP(uint8_t* key, int key_len, uint64_t counter) {
	const int len = 8; // BLOCK_LEN / sizeof(byte)
	uint8_t text[len];
	int i = len - 1;
	while (i > -1) {
		text[i] = (uint8_t)(counter & 0xff);
		counter >>= 8;
		--i;
	}
	uint8_t *hash = HMAC_SHA_1(text, len, key, key_len);
	int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int binary = ((hash[offset] & 0x7f) << 24) |
				 ((hash[offset + 1] & 0xff) << 16) |
				 ((hash[offset + 2] & 0xff) << 8) |
				 (hash[offset + 3] & 0xff);
	return (binary % 1000000); // assume 6 digit-code
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t *key = hex_str_to_bytes(secret_hex);
	int hotp = computeOTP(key, KEY_LEN >> 1, 1);
	return (hotp == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t *key = hex_str_to_bytes(secret_hex);
	int totp = computeOTP(key, KEY_LEN >> 1, (uint64_t)time(NULL) / 30);
	return (totp == atoi(TOTP_string));
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
